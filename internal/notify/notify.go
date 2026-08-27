package notify

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"
)

// Alert is a single notification payload, independent of channel.
type Alert struct {
	Kind          string // "reminder" | "expired" | "test" | "deleted"
	ResourceKind  string // "certificate" | "token"; blank is treated as certificate
	CertName      string
	Environment   string
	DaysRemaining int
	ExpiryDate    string // YYYY-MM-DD
	Severity      string // healthy|notice|warning|urgent|critical|expired
	BaseURL       string // optional link back to the tracker
	Owner         string // username responsible for rotating this cert
	Cadence       string // e.g. "repeats every 3 days until rotated"; empty when milestone-only

	// Deletion alerts only — who asked, why, and who signed it off.
	Reason      string
	RequestedBy string
	ApprovedBy  string
	ReviewNote  string
}

// noun is the word for what this alert is about: a certificate or a token.
// Both expire and both get rotated, so the only difference in a message is
// the label — but calling a token a certificate is exactly the sort of detail
// that makes people ignore an alert.
func (a Alert) noun() string {
	if a.ResourceKind == "token" {
		return "Token"
	}
	return "Certificate"
}

func (a Alert) headline() string {
	switch a.Kind {
	case "test":
		return "Test notification"
	case "expired":
		return a.noun() + " EXPIRED"
	case "deleted":
		return a.noun() + " deleted"
	default:
		return a.noun() + " rotation reminder"
	}
}

func (a Alert) remainingText() string {
	switch {
	case a.Kind == "deleted":
		return "removed from the tracker"
	case a.Kind == "test":
		return fmt.Sprintf("%d days remaining (test)", a.DaysRemaining)
	case a.DaysRemaining < 0:
		return fmt.Sprintf("expired %d day(s) ago", -a.DaysRemaining)
	case a.DaysRemaining == 0:
		return "expires today"
	default:
		return fmt.Sprintf("%d day(s) remaining", a.DaysRemaining)
	}
}

func (a Alert) subject() string {
	if a.Kind == "deleted" {
		return fmt.Sprintf("[DELETED] %s: %s (%s) — approved by %s",
			strings.ToUpper(a.noun()), a.CertName, a.Environment, a.ApprovedBy)
	}
	return fmt.Sprintf("[%s] %s (%s) — %s",
		strings.ToUpper(a.Severity), a.CertName, a.Environment, a.remainingText())
}

// Color returns a hex colour (no leading #) for a severity level.
func Color(severity string) string {
	switch severity {
	case "healthy":
		return "16A34A"
	case "notice":
		return "2563EB"
	case "warning":
		return "D97706"
	case "urgent":
		return "EA580C"
	case "critical":
		return "DC2626"
	case "expired":
		return "7F1D1D"
	default:
		return "6B7280"
	}
}

// ---------- Teams (Power Automate Workflows webhook) ----------

// TeamsClient posts to a Teams "When a Teams webhook request is received"
// Workflow URL. The payload is a MessageCard, which Workflows webhooks accept;
// themeColor carries the severity colour. (The legacy Office 365 "Incoming
// Webhook" connector was retired in 2026 — create the URL via Workflows.)
type TeamsClient struct {
	http *http.Client
}

func NewTeamsClient() *TeamsClient {
	return &TeamsClient{http: &http.Client{Timeout: 15 * time.Second}}
}

func (t *TeamsClient) Send(webhookURL string, a Alert) error {
	// Labels carry their own colon so the card reads "Certificate: api.example.com"
	// rather than leaving the name and its value visually unattached.
	facts := []map[string]string{
		{"name": a.noun() + ":", "value": a.CertName},
		{"name": "Environment:", "value": strings.ToUpper(a.Environment)},
		{"name": "Status:", "value": a.remainingText()},
		{"name": "Expiry date:", "value": a.ExpiryDate},
	}
	if a.Kind != "deleted" {
		facts = append(facts, map[string]string{"name": "Severity:", "value": strings.ToUpper(a.Severity)})
	}
	if a.Owner != "" {
		facts = append(facts, map[string]string{"name": "Owner:", "value": a.Owner})
	}
	if a.RequestedBy != "" {
		facts = append(facts, map[string]string{"name": "Deleted by:", "value": a.RequestedBy})
	}
	if a.ApprovedBy != "" {
		facts = append(facts, map[string]string{"name": "Approved by:", "value": a.ApprovedBy})
	}
	if a.Reason != "" {
		facts = append(facts, map[string]string{"name": "Reason:", "value": a.Reason})
	}
	if a.ReviewNote != "" {
		facts = append(facts, map[string]string{"name": "Reviewer note:", "value": a.ReviewNote})
	}
	if a.Cadence != "" {
		facts = append(facts, map[string]string{"name": "Reminder:", "value": a.Cadence})
	}
	section := map[string]any{
		"activityTitle": a.headline(),
		"facts":         facts,
		"markdown":      true,
	}
	card := map[string]any{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor": Color(a.Severity),
		"summary":    a.subject(),
		"title":      fmt.Sprintf("%s: %s", a.headline(), a.CertName),
		"sections":   []any{section},
	}
	if a.BaseURL != "" {
		card["potentialAction"] = []any{
			map[string]any{
				"@type": "OpenUri",
				"name":  "Open tracker",
				"targets": []any{
					map[string]string{"os": "default", "uri": a.BaseURL},
				},
			},
		}
	}

	body, err := json.Marshal(card)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("teams webhook returned %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

// ---------- Email (SMTP) ----------

type EmailConfig struct {
	Host               string
	Port               int
	Username           string
	Password           string
	From               string
	UseTLS             bool // implicit TLS (e.g. port 465)
	InsecureSkipVerify bool // for internal relays with self-signed certs
}

type EmailClient struct {
	cfg EmailConfig
}

func NewEmailClient(cfg EmailConfig) *EmailClient { return &EmailClient{cfg: cfg} }

func (e *EmailClient) Send(to []string, a Alert) error {
	if len(to) == 0 {
		return nil
	}
	return e.deliver(to, e.build(to, a))
}

// SendOneTimePassword mails a temporary password to the address on the
// account. It is deliberately its own message rather than an Alert: nothing
// about it is a certificate, and it must never pick up an Alert's severity
// colouring or "open tracker" call to action.
func (e *EmailClient) SendOneTimePassword(to, otp, baseURL string, validFor time.Duration) error {
	html := fmt.Sprintf(`<!doctype html><html><body style="margin:0;font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f4f5f7;padding:24px;">
<div style="max-width:520px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;border:1px solid #e5e7eb;">
  <div style="height:6px;background:#111827;"></div>
  <div style="padding:24px;">
    <h2 style="margin:0 0 4px;color:#111827;font-size:20px;">Your one-time password</h2>
    <p style="margin:0 0 20px;color:#6b7280;font-size:14px;">Someone asked to reset the password for this account on the Certificate Rotation Tracker.</p>
    <div style="font-family:monospace;font-size:26px;font-weight:700;letter-spacing:.08em;color:#111827;background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;padding:16px;text-align:center;">%s</div>
    <p style="margin:20px 0 0;color:#374151;font-size:14px;">Sign in with it within <strong>%s</strong>. You will be asked to choose a new password straight away — this one stops working as soon as you do.</p>
    <p style="margin:16px 0 0;padding:10px 12px;background:#fef2f2;border-radius:8px;color:#991b1b;font-size:13px;">If you did not ask for this, tell an administrator: someone else knows your address and wanted into your account. Your previous password no longer works, so it has to be reset either way.</p>
    %s
  </div>
</div></body></html>`, htmlEscape(otp), htmlEscape(humanDuration(validFor)), linkBlock(baseURL))

	return e.deliver([]string{to}, e.envelope([]string{to}, "Your one-time password for the Certificate Rotation Tracker", html))
}

// humanDuration renders a reset window the way a person would say it.
func humanDuration(d time.Duration) string {
	if d < time.Hour {
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
	h := int(d.Hours())
	if h == 1 {
		return "1 hour"
	}
	return fmt.Sprintf("%d hours", h)
}

func (e *EmailClient) deliver(to []string, msg []byte) error {
	addr := fmt.Sprintf("%s:%d", e.cfg.Host, e.cfg.Port)

	var client *smtp.Client
	var err error
	if e.cfg.UseTLS {
		conn, derr := tls.Dial("tcp", addr, e.tlsConfig())
		if derr != nil {
			return derr
		}
		client, err = smtp.NewClient(conn, e.cfg.Host)
	} else {
		client, err = smtp.Dial(addr)
	}
	if err != nil {
		return err
	}
	defer client.Close()

	if err = client.Hello(clientHostname()); err != nil {
		return err
	}
	if !e.cfg.UseTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err = client.StartTLS(e.tlsConfig()); err != nil {
				return err
			}
		}
	}
	if e.cfg.Username != "" {
		auth := smtp.PlainAuth("", e.cfg.Username, e.cfg.Password, e.cfg.Host)
		if err = client.Auth(auth); err != nil {
			return err
		}
	}
	if err = client.Mail(e.cfg.From); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err = client.Rcpt(rcpt); err != nil {
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err = w.Write(msg); err != nil {
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func (e *EmailClient) tlsConfig() *tls.Config {
	return &tls.Config{ServerName: e.cfg.Host, InsecureSkipVerify: e.cfg.InsecureSkipVerify}
}

func (e *EmailClient) build(to []string, a Alert) []byte {
	color := "#" + Color(a.Severity)
	badge := strings.ToUpper(a.Severity)
	if a.Kind == "deleted" {
		// A deletion is not an urgency level, so it does not borrow one of the
		// severity colours — it gets its own neutral, final-looking slate.
		color = "#374151"
		badge = "DELETED"
	}

	// Every label carries its own colon, so a row reads "Certificate: api.example.com"
	// even in the clients that collapse the two-column table into one line.
	rows := detailRow(a.noun(), a.CertName, false) +
		detailRow("Environment", strings.ToUpper(a.Environment), false) +
		detailRow("Expiry date", a.ExpiryDate, true)
	if a.Kind != "deleted" {
		rows += detailRow("Severity", strings.ToUpper(a.Severity), false)
	}
	rows += detailRow("Owner", a.Owner, false) +
		detailRow("Deleted by", a.RequestedBy, false) +
		detailRow("Approved by", a.ApprovedBy, false) +
		detailRow("Reason", a.Reason, false) +
		detailRow("Reviewer note", a.ReviewNote, false)

	html := fmt.Sprintf(`<!doctype html><html><body style="margin:0;font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f4f5f7;padding:24px;">
<div style="max-width:520px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;border:1px solid #e5e7eb;">
  <div style="height:6px;background:%s;"></div>
  <div style="padding:24px;">
    <div style="display:inline-block;font-size:12px;font-weight:700;letter-spacing:.04em;color:#fff;background:%s;padding:4px 10px;border-radius:999px;">%s</div>
    <h2 style="margin:16px 0 4px;color:#111827;font-size:20px;">%s: %s</h2>
    <p style="margin:0 0 20px;color:#6b7280;font-size:14px;">%s</p>
    <table style="width:100%%;border-collapse:collapse;font-size:14px;color:#374151;">
      %s
    </table>
    %s
    %s
    %s
  </div>
</div></body></html>`,
		color, color, badge,
		a.headline(), a.CertName, a.remainingText(),
		rows,
		deletionNote(a),
		cadenceNote(a.Cadence),
		linkBlock(a.BaseURL))

	return e.envelope(to, a.subject(), html)
}

// envelope wraps a rendered body in the RFC 5322 headers every message the
// tracker sends needs.
func (e *EmailClient) envelope(to []string, subject, html string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", e.cfg.From)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(html)
	return b.Bytes()
}

// detailRow renders one "Label: value" row, or nothing when the value is
// empty — so optional fields never leave a dangling label behind.
func detailRow(label, value string, mono bool) string {
	if value == "" {
		return ""
	}
	style := "padding:8px 0;text-align:right;font-weight:600;"
	if mono {
		style += "font-family:monospace;"
	}
	return fmt.Sprintf(
		`<tr><td style="padding:8px 0;color:#9ca3af;">%s:</td><td style="%s">%s</td></tr>`,
		htmlEscape(label), style, htmlEscape(value))
}

// deletionNote spells out that the deletion was reviewed and is reversible.
// The people on this list did not necessarily ask for it, so the message has
// to say what happened and what to do if it was wrong.
func deletionNote(a Alert) string {
	if a.Kind != "deleted" {
		return ""
	}
	return `<p style="margin:16px 0 0;padding:10px 12px;background:#f9fafb;border-radius:8px;color:#6b7280;font-size:13px;">` +
		`This was requested with a reason and approved by a second person. Reminders for it have stopped. ` +
		`Nothing is lost — an administrator can restore it if this was a mistake.</p>`
}

// cadenceNote tells the recipient this is a repeating alert and how to make it
// stop — which is the difference between an escalation people act on and one
// they filter out.
func cadenceNote(cadence string) string {
	if cadence == "" {
		return ""
	}
	return fmt.Sprintf(`<p style="margin:16px 0 0;padding:10px 12px;background:#f9fafb;border-radius:8px;color:#6b7280;font-size:13px;">This reminder %s. Rotate it and mark it renewed in the tracker to stop it.</p>`, htmlEscape(cadence))
}

func linkBlock(baseURL string) string {
	if baseURL == "" {
		return ""
	}
	return fmt.Sprintf(`<a href="%s" style="display:inline-block;margin-top:20px;background:#111827;color:#fff;text-decoration:none;font-size:14px;padding:10px 16px;border-radius:8px;">Open tracker</a>`, baseURL)
}

// htmlEscape keeps user-controlled values (names, notes, deletion reasons)
// from breaking out of the markup they are dropped into.
func htmlEscape(s string) string { return html.EscapeString(s) }

func clientHostname() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "localhost"
}

// ---------- Dispatcher ----------

// Dispatcher fans an alert out to whichever channels a certificate has
// configured. A failure in one channel does not stop the others.
type Dispatcher struct {
	Teams *TeamsClient
	Email *EmailClient // nil when SMTP is not configured
}

func NewDispatcher(email *EmailClient) *Dispatcher {
	return &Dispatcher{Teams: NewTeamsClient(), Email: email}
}

// Dispatch sends the alert to the cert's Teams webhook and/or email list.
// Returns any per-channel errors.
func (d *Dispatcher) Dispatch(a Alert, teamsWebhook string, emails []string) []error {
	var errs []error
	if strings.TrimSpace(teamsWebhook) != "" {
		if err := d.Teams.Send(teamsWebhook, a); err != nil {
			errs = append(errs, fmt.Errorf("teams: %w", err))
		}
	}
	if d.Email != nil && len(emails) > 0 {
		if err := d.Email.Send(emails, a); err != nil {
			errs = append(errs, fmt.Errorf("email: %w", err))
		}
	}
	return errs
}
