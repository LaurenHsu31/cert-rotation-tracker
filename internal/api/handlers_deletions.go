package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"certtracker/internal/models"
	"certtracker/internal/notify"
	"certtracker/internal/store"
)

// presentDeletion fills the per-viewer action flags. CanReview encodes the
// four-eyes rule: whoever asked for the deletion can never be the one who
// approves it — a reason nobody else reads is not a control.
func presentDeletion(d *models.DeletionRequest, actor store.Actor, isAdmin bool) {
	open := d.Status == models.DeletionPending
	d.CanReview = open && d.RequestedBy != actor.ID
	d.CanWithdraw = open && (d.RequestedBy == actor.ID || isAdmin)
}

func (a *API) listDeletions(w http.ResponseWriter, r *http.Request) {
	actor, isAdmin := a.actor(r)
	f := store.DeletionFilter{Status: r.URL.Query().Get("status")}
	if v := r.URL.Query().Get("certificate_id"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil || id <= 0 {
			writeError(w, http.StatusBadRequest, "Invalid certificate_id")
			return
		}
		f.CertificateID = &id
	}
	if f.Status != "" && f.Status != models.DeletionPending && f.Status != models.DeletionApproved &&
		f.Status != models.DeletionRejected && f.Status != models.DeletionWithdrawn {
		writeError(w, http.StatusBadRequest, "Invalid status filter")
		return
	}

	list, err := a.store.ListDeletions(f)
	if err != nil {
		a.serverError(w, "list deletions", err)
		return
	}
	for _, item := range list {
		presentDeletion(item, actor, isAdmin)
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) getDeletion(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	actor, isAdmin := a.actor(r)
	item, err := a.store.GetDeletionRequest(id)
	if err != nil {
		a.storeError(w, "get deletion", err)
		return
	}
	presentDeletion(item, actor, isAdmin)
	writeJSON(w, http.StatusOK, item)
}

type deletionInput struct {
	Reason string `json:"reason"`
}

// submitDeletion opens a deletion request. Nothing is removed here: the
// certificate keeps alerting until a second person approves.
func (a *API) submitDeletion(w http.ResponseWriter, r *http.Request) {
	certID, ok := parseID(w, r)
	if !ok {
		return
	}
	actor, isAdmin := a.actor(r)

	var in deletionInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	reason := strings.TrimSpace(in.Reason)
	if reason == "" {
		writeError(w, http.StatusBadRequest,
			"Say why this should be deleted — the reviewer and the notified team see this reason")
		return
	}

	created, err := a.store.CreateDeletion(certID, reason, actor, isAdmin)
	if err != nil {
		a.storeError(w, "create deletion", err)
		return
	}
	presentDeletion(created, actor, isAdmin)
	writeJSON(w, http.StatusCreated, created)
}

// approveDeletion is the four-eyes gate. On success the certificate is
// soft-deleted and everyone on its notification channels is told — a tracked
// secret disappearing quietly is exactly the failure this tracker exists to
// prevent.
func (a *API) approveDeletion(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	actor, isAdmin := a.actor(r)
	note, ok := decodeReview(w, r)
	if !ok {
		return
	}

	request, cert, err := a.store.ApproveDeletion(id, note, actor)
	if err != nil {
		a.storeError(w, "approve deletion", err)
		return
	}

	delivery := a.announceDeletion(request, cert, actor)
	presentDeletion(request, actor, isAdmin)
	a.present(cert, actor, isAdmin)
	writeJSON(w, http.StatusOK, map[string]any{
		"deletion":     request,
		"certificate":  cert,
		"notification": delivery,
	})
}

func (a *API) rejectDeletion(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	actor, isAdmin := a.actor(r)
	note, ok := decodeReview(w, r)
	if !ok {
		return
	}
	if note == "" {
		writeError(w, http.StatusBadRequest, "Give a reason so the requester knows why this was refused")
		return
	}

	request, err := a.store.RejectDeletion(id, note, actor)
	if err != nil {
		a.storeError(w, "reject deletion", err)
		return
	}
	presentDeletion(request, actor, isAdmin)
	writeJSON(w, http.StatusOK, request)
}

func (a *API) withdrawDeletion(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	actor, isAdmin := a.actor(r)
	request, err := a.store.WithdrawDeletion(id, actor, isAdmin)
	if err != nil {
		a.storeError(w, "withdraw deletion", err)
		return
	}
	presentDeletion(request, actor, isAdmin)
	writeJSON(w, http.StatusOK, request)
}

// announceDeletion tells the certificate's configured channels that it is gone,
// and who approved it. Delivery failures are reported back to the reviewer but
// never undo the deletion: the record is already committed, and re-running the
// approval is not possible.
func (a *API) announceDeletion(d *models.DeletionRequest, c *models.Certificate, actor store.Actor) map[string]any {
	emails := a.deletionRecipients(c)
	if c.TeamsWebhook == "" && len(emails) == 0 {
		return map[string]any{"sent": false, "reason": "no notification channel is configured for this certificate"}
	}

	alert := notify.Alert{
		Kind:         "deleted",
		ResourceKind: c.Kind,
		CertName:     c.Name,
		Environment:  c.Environment,
		ExpiryDate:   models.DateOnly(c.ExpiryDate),
		Severity:     c.Severity,
		BaseURL:      a.cfg.BaseURL,
		Owner:        c.OwnerUsername,
		Reason:       d.Reason,
		RequestedBy:  d.RequestedByName,
		ApprovedBy:   actor.Username,
		ReviewNote:   d.ReviewNote,
	}

	errs := a.dispatcher.Dispatch(alert, c.TeamsWebhook, emails)
	if len(errs) == 0 {
		return map[string]any{"sent": true, "recipients": len(emails), "teams": c.TeamsWebhook != ""}
	}
	msgs := make([]string, len(errs))
	for i, e := range errs {
		msgs[i] = e.Error()
		a.log.Error("deletion notification failed", "cert_id", c.ID, "error", e)
	}
	return map[string]any{"sent": false, "errors": msgs}
}

// deletionRecipients is the certificate's notification list plus the owner's
// own address. The owner is the person most affected by the removal, and they
// are not necessarily on a list they configured for expiry reminders.
func (a *API) deletionRecipients(c *models.Certificate) []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(addr string) {
		addr = strings.TrimSpace(addr)
		if addr == "" || !strings.Contains(addr, "@") || seen[strings.ToLower(addr)] {
			return
		}
		seen[strings.ToLower(addr)] = true
		out = append(out, addr)
	}
	for _, e := range c.NotifyEmails {
		add(e)
	}
	if c.OwnerID != nil {
		if u, err := a.store.GetUser(*c.OwnerID); err == nil {
			add(u.Email)
		} else {
			a.log.Warn("look up owner for deletion notice", "cert_id", c.ID, "error", err)
		}
	}
	return out
}
