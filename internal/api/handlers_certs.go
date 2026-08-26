package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"certtracker/internal/models"
	"certtracker/internal/notify"
	"certtracker/internal/severity"
	"certtracker/internal/store"
)

// present fills in the per-viewer fields and strips anything the viewer is not
// entitled to see. Every certificate leaving the API goes through it — that is
// what stops a read-only colleague from harvesting Teams webhook URLs, which
// are bearer credentials for a channel.
func (a *API) present(c *models.Certificate, actor store.Actor, isAdmin bool) {
	c.Enrich(time.Now(), a.cfg.Location, a.cuts)
	c.ReminderIntervalD = a.cfg.ReminderEscalation.IntervalFor(c.DaysRemaining)
	privileged := isAdmin || c.OwnedBy(actor.ID)
	c.CanEdit = privileged && c.IsLive()
	if !privileged {
		c.Redact()
	}
}

func (a *API) listCertificates(w http.ResponseWriter, r *http.Request) {
	actor, isAdmin := a.actor(r)

	includeDeleted := r.URL.Query().Get("include_deleted") == "1"
	if includeDeleted && !isAdmin {
		writeError(w, http.StatusForbidden, "Only administrators can list deleted certificates")
		return
	}

	certs, err := a.store.ListCertificates(includeDeleted)
	if err != nil {
		a.serverError(w, "list certificates", err)
		return
	}
	for _, c := range certs {
		a.present(c, actor, isAdmin)
	}

	// Most urgent first: higher severity rank, then fewer days remaining.
	// Rotated certificates drop to the bottom — they are history, not work.
	sort.SliceStable(certs, func(i, j int) bool {
		li, lj := certs[i].IsLive(), certs[j].IsLive()
		if li != lj {
			return li
		}
		ri := severity.Rank(severity.Level(certs[i].Severity))
		rj := severity.Rank(severity.Level(certs[j].Severity))
		if ri != rj {
			return ri > rj
		}
		return certs[i].DaysRemaining < certs[j].DaysRemaining
	})
	writeJSON(w, http.StatusOK, certs)
}

func (a *API) getCertificate(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	actor, isAdmin := a.actor(r)
	c, err := a.store.GetCertificate(id)
	if err != nil {
		a.storeError(w, "get certificate", err)
		return
	}
	if c.DeletedAt != nil && !isAdmin {
		writeError(w, http.StatusNotFound, "Certificate not found")
		return
	}
	a.present(c, actor, isAdmin)
	writeJSON(w, http.StatusOK, c)
}

func (a *API) createCertificate(w http.ResponseWriter, r *http.Request) {
	actor, isAdmin := a.actor(r)
	in, err := decodeInput(r, w)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	cert, verr := in.toCertificate(a.cfg)
	if verr != nil {
		writeError(w, http.StatusBadRequest, verr.Error())
		return
	}
	created, err := a.store.CreateCertificate(cert, actor)
	if err != nil {
		a.storeError(w, "create certificate", err)
		return
	}
	a.present(created, actor, isAdmin)
	writeJSON(w, http.StatusCreated, created)
}

func (a *API) updateCertificate(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	actor, isAdmin := a.actor(r)
	in, err := decodeInput(r, w)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	cert, verr := in.toCertificate(a.cfg)
	if verr != nil {
		writeError(w, http.StatusBadRequest, verr.Error())
		return
	}
	cert.ID = id

	updated, err := a.store.UpdateCertificate(cert, actor, isAdmin)
	if err != nil {
		a.storeError(w, "update certificate", err)
		return
	}
	a.present(updated, actor, isAdmin)
	writeJSON(w, http.StatusOK, updated)
}

func (a *API) deleteCertificate(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	actor, isAdmin := a.actor(r)
	if err := a.store.DeleteCertificate(id, actor, isAdmin); err != nil {
		a.storeError(w, "delete certificate", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) restoreCertificate(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	actor, isAdmin := a.actor(r)
	c, err := a.store.RestoreCertificate(id, actor)
	if err != nil {
		a.storeError(w, "restore certificate", err)
		return
	}
	a.present(c, actor, isAdmin)
	writeJSON(w, http.StatusOK, c)
}

type ownerInput struct {
	OwnerID int64 `json:"owner_id"`
}

// transferOwner reassigns a certificate. Owners can hand theirs over directly;
// admins can move anyone's. Without this, an owner leaving would leave their
// certificates permanently uneditable by their team.
func (a *API) transferOwner(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	actor, isAdmin := a.actor(r)
	var in ownerInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil || in.OwnerID <= 0 {
		writeError(w, http.StatusBadRequest, "A valid owner_id is required")
		return
	}
	c, err := a.store.TransferOwner(id, in.OwnerID, actor, isAdmin)
	if err != nil {
		a.storeError(w, "transfer owner", err)
		return
	}
	a.present(c, actor, isAdmin)
	writeJSON(w, http.StatusOK, c)
}

// testCertificate sends a test notification using the cert's configured
// channels. Restricted to the owner and admins: it triggers real messages to
// a Teams channel and real inboxes, which is not a read-only action.
func (a *API) testCertificate(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	actor, isAdmin := a.actor(r)
	c, err := a.store.GetCertificate(id)
	if err != nil {
		a.storeError(w, "get certificate", err)
		return
	}
	if err := a.store.AssertCanWrite(c, actor, isAdmin); err != nil {
		a.storeError(w, "test certificate", err)
		return
	}
	c.Enrich(time.Now(), a.cfg.Location, a.cuts)

	if c.TeamsWebhook == "" && !(a.cfg.EmailEnabled() && len(c.NotifyEmails) > 0) {
		writeError(w, http.StatusBadRequest, "No deliverable channel configured for this certificate")
		return
	}

	alert := notify.Alert{
		Kind:          "test",
		CertName:      c.Name,
		Environment:   c.Environment,
		DaysRemaining: c.DaysRemaining,
		ExpiryDate:    models.DateOnly(c.ExpiryDate),
		Severity:      c.Severity,
		BaseURL:       a.cfg.BaseURL,
		Owner:         c.OwnerUsername,
	}
	if errs := a.dispatcher.Dispatch(alert, c.TeamsWebhook, c.NotifyEmails); len(errs) > 0 {
		msgs := make([]string, len(errs))
		for i, e := range errs {
			msgs[i] = e.Error()
		}
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "errors": msgs})
		return
	}
	if err := a.store.Audit(actor, store.ActionCertTest, "certificate", &c.ID,
		map[string]any{"name": c.Name}); err != nil {
		a.log.Warn("audit test notification", "error", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// certificateAudit returns the history of one certificate. Visible to the
// owner and admins — "who changed my reminder settings" is exactly the
// question this feature exists to answer.
func (a *API) certificateAudit(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	actor, isAdmin := a.actor(r)
	c, err := a.store.GetCertificate(id)
	if err != nil {
		a.storeError(w, "get certificate", err)
		return
	}
	if !isAdmin && !c.OwnedBy(actor.ID) {
		writeError(w, http.StatusForbidden, "Only the owner or an administrator can view this history")
		return
	}
	entries, err := a.store.ListAudit(store.AuditFilter{EntityType: "certificate", EntityID: &id, Limit: 100})
	if err != nil {
		a.serverError(w, "list audit", err)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

func (a *API) runCheck(w http.ResponseWriter, r *http.Request) {
	actor, _ := a.actor(r)
	n, err := a.scheduler.RunOnce(r.Context())
	if err != nil {
		a.serverError(w, "run check", err)
		return
	}
	if err := a.store.Audit(actor, store.ActionRunCheck, "task", nil,
		map[string]any{"alerts_sent": n}); err != nil {
		a.log.Warn("audit run check", "error", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "alerts_sent": n})
}

// ---------- input ----------

type certInput struct {
	Name            string   `json:"name"`
	Environment     string   `json:"environment"`
	IssuedDate      string   `json:"issued_date"`
	ExpiryDate      string   `json:"expiry_date"`
	ReminderDays    []int    `json:"reminder_days"`
	TeamsWebhookURL string   `json:"teams_webhook_url"`
	NotifyEmails    []string `json:"notify_emails"`
	Notes           string   `json:"notes"`
}

func decodeInput(r *http.Request, w http.ResponseWriter) (*certInput, error) {
	var in certInput
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return nil, errors.New("Invalid request body: " + err.Error())
	}
	return &in, nil
}

func (in *certInput) toCertificate(cfg cfgReader) (*models.Certificate, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, errors.New("Name is required")
	}
	if !models.ValidEnvironment(in.Environment) {
		return nil, errors.New("Environment must be one of dev, stg, prd")
	}
	issued, expiry, err := parseDateRange(in.IssuedDate, in.ExpiryDate)
	if err != nil {
		return nil, err
	}

	return &models.Certificate{
		Name:         name,
		Environment:  in.Environment,
		IssuedDate:   issued,
		ExpiryDate:   expiry,
		ReminderDays: normalizeDays(in.ReminderDays, cfg.DefaultReminderDays()),
		TeamsWebhook: strings.TrimSpace(in.TeamsWebhookURL),
		NotifyEmails: normalizeEmails(in.NotifyEmails),
		Notes:        strings.TrimSpace(in.Notes),
	}, nil
}

// cfgReader keeps toCertificate testable without a full Config.
type cfgReader interface{ DefaultReminderDays() []int }

func parseDateRange(issuedStr, expiryStr string) (time.Time, time.Time, error) {
	issued, err := time.Parse("2006-01-02", issuedStr)
	if err != nil {
		return time.Time{}, time.Time{}, errors.New("Issued date must be YYYY-MM-DD")
	}
	expiry, err := time.Parse("2006-01-02", expiryStr)
	if err != nil {
		return time.Time{}, time.Time{}, errors.New("Expiry date must be YYYY-MM-DD")
	}
	if expiry.Before(issued) {
		return time.Time{}, time.Time{}, errors.New("Expiry date must be on or after the issued date")
	}
	return issued, expiry, nil
}

func normalizeDays(in, def []int) []int {
	seen := map[int]bool{}
	var out []int
	for _, d := range in {
		if d > 0 && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		out = append(out, def...)
	}
	sort.Ints(out)
	return out
}

func normalizeEmails(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, e := range in {
		e = strings.TrimSpace(e)
		if e == "" || !strings.Contains(e, "@") || seen[e] {
			continue
		}
		seen[e] = true
		out = append(out, e)
	}
	return out
}
