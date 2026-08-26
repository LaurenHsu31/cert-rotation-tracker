package notify

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"
)

// Alert is a single notification payload, independent of channel.
type Alert struct {
	Kind          string // "reminder" | "expired" | "test"
	CertName      string
	Environment   string
	DaysRemaining int
	ExpiryDate    string // YYYY-MM-DD
	Severity      string // healthy|notice|warning|urgent|critical|expired
	BaseURL       string // optional link back to the tracker
	Owner         string // username responsible for rotating this cert
	Cadence       string // e.g. "repeats every 3 days until rotated"; empty when milestone-only
}

func (a Alert) headline() string {
	switch a.Kind {
	case "test":
		return "Test notification"
	case "expired":
		return "Certificate EXPIRED"
	default:
		return "Certificate rotation reminder"
	}
}

func (a Alert) remainingText() string {
	switch {
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
	facts := []map[string]string{
		{"name": "Certificate", "value": a.CertName},
		{"name": "Environment", "value": strings.ToUpper(a.Environment)},
		{"name": "Status", "value": a.remainingText()},
		{"name": "Expiry date", "value": a.ExpiryDate},
		{"name": "Severity", "value": strings.ToUpper(a.Severity)},
	}
	if a.Owner != "" {
		facts = append(facts, map[string]string{"name": "Owner", "value": a.Owner})
	}
	if a.Cadence != "" {
		facts = append(facts, map[string]string{"name": "Reminder", "value": a.Cadence})
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
		"title":      fmt.Sprintf("%s — %s", a.headline(), a.CertName),
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
	msg := e.build(to, a)
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
	html := fmt.Sprintf(`<!doctype html><html><body style="margin:0;font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f4f5f7;padding:24px;">
<div style="max-width:520px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;border:1px solid #e5e7eb;">
  <div style="height:6px;background:%s;"></div>
  <div style="padding:24px;">
    <div style="display:inline-block;font-size:12px;font-weight:700;letter-spacing:.04em;color:#fff;background:%s;padding:4px 10px;border-radius:999px;">%s</div>
    <h2 style="margin:16px 0 4px;color:#111827;font-size:20px;">%s</h2>
    <p style="margin:0 0 20px;color:#6b7280;font-size:14px;">%s</p>
    <table style="width:100%%;border-collapse:collapse;font-size:14px;color:#374151;">
      <tr><td style="padding:8px 0;color:#9ca3af;">Certificate</td><td style="padding:8px 0;text-align:right;font-weight:600;">%s</td></tr>
      <tr><td style="padding:8px 0;color:#9ca3af;">Environment</td><td style="padding:8px 0;text-align:right;font-weight:600;">%s</td></tr>
      <tr><td style="padding:8px 0;color:#9ca3af;">Expiry date</td><td style="padding:8px 0;text-align:right;font-weight:600;font-family:monospace;">%s</td></tr>
      %s
    </table>
    %s
    %s
  </div>
</div></body></html>`,
		color, color, strings.ToUpper(a.Severity),
		a.headline(), a.remainingText(),
		a.CertName, strings.ToUpper(a.Environment), a.ExpiryDate,
		ownerRow(a.Owner),
		cadenceNote(a.Cadence),
		linkBlock(a.BaseURL))

	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", e.cfg.From)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", a.subject())
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(html)
	return b.Bytes()
}

func ownerRow(owner string) string {
	if owner == "" {
		return ""
	}
	return fmt.Sprintf(`<tr><td style="padding:8px 0;color:#9ca3af;">Owner</td><td style="padding:8px 0;text-align:right;font-weight:600;">%s</td></tr>`, owner)
}

// cadenceNote tells the recipient this is a repeating alert and how to make it
// stop — which is the difference between an escalation people act on and one
// they filter out.
func cadenceNote(cadence string) string {
	if cadence == "" {
		return ""
	}
	return fmt.Sprintf(`<p style="margin:16px 0 0;padding:10px 12px;background:#f9fafb;border-radius:8px;color:#6b7280;font-size:13px;">This reminder %s. Rotate the certificate and mark it renewed in the tracker to stop it.</p>`, cadence)
}

func linkBlock(baseURL string) string {
	if baseURL == "" {
		return ""
	}
	return fmt.Sprintf(`<a href="%s" style="display:inline-block;margin-top:20px;background:#111827;color:#fff;text-decoration:none;font-size:14px;padding:10px 16px;border-radius:8px;">Open tracker</a>`, baseURL)
}

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
