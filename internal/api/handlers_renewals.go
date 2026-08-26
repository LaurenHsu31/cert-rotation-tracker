package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"certtracker/internal/models"
	"certtracker/internal/store"
)

// allowedEvidenceTypes are the image formats accepted as renewal proof.
// Deliberately narrow: the evidence is served back from the tracker's own
// origin, so anything that a browser might execute (SVG, HTML) is excluded.
var allowedEvidenceTypes = map[string]string{
	"image/png":  ".png",
	"image/jpeg": ".jpg",
	"image/webp": ".webp",
	"image/gif":  ".gif",
}

// presentRenewal fills the per-viewer action flags. CanReview encodes the
// four-eyes rule directly: whoever submitted a request can never be the one
// who approves it.
func presentRenewal(r *models.Renewal, actor store.Actor, isAdmin bool) {
	open := r.Status == models.RenewalPending
	r.CanReview = open && r.SubmittedBy != actor.ID
	r.CanWithdraw = open && (r.SubmittedBy == actor.ID || isAdmin)
}

func (a *API) listRenewals(w http.ResponseWriter, r *http.Request) {
	actor, isAdmin := a.actor(r)
	f := store.RenewalFilter{Status: r.URL.Query().Get("status")}
	if v := r.URL.Query().Get("certificate_id"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil || id <= 0 {
			writeError(w, http.StatusBadRequest, "Invalid certificate_id")
			return
		}
		f.CertificateID = &id
	}
	if f.Status != "" && f.Status != models.RenewalPending && f.Status != models.RenewalApproved &&
		f.Status != models.RenewalRejected && f.Status != models.RenewalWithdrawn {
		writeError(w, http.StatusBadRequest, "Invalid status filter")
		return
	}

	list, err := a.store.ListRenewals(f)
	if err != nil {
		a.serverError(w, "list renewals", err)
		return
	}
	for _, item := range list {
		presentRenewal(item, actor, isAdmin)
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) getRenewal(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	actor, isAdmin := a.actor(r)
	item, err := a.store.GetRenewal(id)
	if err != nil {
		a.storeError(w, "get renewal", err)
		return
	}
	presentRenewal(item, actor, isAdmin)
	writeJSON(w, http.StatusOK, item)
}

// submitRenewal opens a renewal request: the owner states the new validity
// dates and attaches a picture of the new certificate as proof. Nothing is
// marked rotated here — that needs a second person's approval.
func (a *API) submitRenewal(w http.ResponseWriter, r *http.Request) {
	certID, ok := parseID(w, r)
	if !ok {
		return
	}
	actor, isAdmin := a.actor(r)

	// Cap the request body before parsing, so an oversized upload is rejected
	// rather than buffered.
	r.Body = http.MaxBytesReader(w, r.Body, a.cfg.MaxUploadBytes+512*1024)
	if err := r.ParseMultipartForm(a.cfg.MaxUploadBytes); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf(
			"Could not read the upload (limit %d MB): %v", a.cfg.MaxUploadBytes/1024/1024, err))
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	issued, expiry, derr := parseDateRange(
		r.FormValue("new_issued_date"), r.FormValue("new_expiry_date"))
	if derr != nil {
		writeError(w, http.StatusBadRequest, derr.Error())
		return
	}

	file, header, err := r.FormFile("evidence")
	if err != nil {
		writeError(w, http.StatusBadRequest,
			"Attach a picture of the new certificate as proof (field name: evidence)")
		return
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, a.cfg.MaxUploadBytes+1))
	if err != nil {
		a.serverError(w, "read evidence", err)
		return
	}
	if int64(len(data)) > a.cfg.MaxUploadBytes {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf(
			"Evidence image must be %d MB or smaller", a.cfg.MaxUploadBytes/1024/1024))
		return
	}

	mime, verr := detectEvidenceType(data)
	if verr != nil {
		writeError(w, http.StatusBadRequest, verr.Error())
		return
	}

	renewal := &models.Renewal{
		CertificateID:    certID,
		NewIssuedDate:    issued,
		NewExpiryDate:    expiry,
		Note:             strings.TrimSpace(r.FormValue("note")),
		EvidenceMIME:     mime,
		EvidenceFilename: safeFilename(header.Filename, allowedEvidenceTypes[mime]),
	}

	created, err := a.store.CreateRenewal(renewal, data, actor, isAdmin)
	if err != nil {
		a.storeError(w, "create renewal", err)
		return
	}
	presentRenewal(created, actor, isAdmin)
	writeJSON(w, http.StatusCreated, created)
}

// renewalEvidence streams the stored proof image back. Any signed-in user can
// see it: reviewers must be able to, and the image is the audit artifact.
func (a *API) renewalEvidence(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	ev, err := a.store.GetRenewalEvidence(id)
	if err != nil {
		a.storeError(w, "get evidence", err)
		return
	}

	// Belt and braces for user-supplied bytes served from our own origin:
	// a fixed image content type, no sniffing, and a CSP that forbids the
	// page from loading or running anything if it is opened directly.
	w.Header().Set("Content-Type", ev.MIME)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("inline; filename=%q", ev.Filename))
	w.Header().Set("Cache-Control", "private, max-age=300")
	w.Header().Set("Content-Length", strconv.Itoa(len(ev.Data)))
	_, _ = w.Write(ev.Data)
}

type reviewInput struct {
	Note string `json:"note"`
}

func decodeReview(w http.ResponseWriter, r *http.Request) (string, bool) {
	var in reviewInput
	// An empty body is fine for approval; only rejection insists on a reason.
	if r.ContentLength > 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid request body")
			return "", false
		}
	}
	return strings.TrimSpace(in.Note), true
}

// approveRenewal is the four-eyes gate. On success the old certificate is
// marked rotated and its replacement is created in the same transaction, so
// the tracker never has a window where a rotated cert has no successor.
func (a *API) approveRenewal(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	actor, isAdmin := a.actor(r)
	note, ok := decodeReview(w, r)
	if !ok {
		return
	}

	renewal, newCert, err := a.store.ApproveRenewal(id, note, actor)
	if err != nil {
		a.storeError(w, "approve renewal", err)
		return
	}
	presentRenewal(renewal, actor, isAdmin)
	a.present(newCert, actor, isAdmin)
	writeJSON(w, http.StatusOK, map[string]any{
		"renewal":         renewal,
		"new_certificate": newCert,
	})
}

func (a *API) rejectRenewal(w http.ResponseWriter, r *http.Request) {
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
		writeError(w, http.StatusBadRequest, "Give a reason so the submitter knows what to fix")
		return
	}

	renewal, err := a.store.RejectRenewal(id, note, actor)
	if err != nil {
		a.storeError(w, "reject renewal", err)
		return
	}
	presentRenewal(renewal, actor, isAdmin)
	writeJSON(w, http.StatusOK, renewal)
}

func (a *API) withdrawRenewal(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	actor, isAdmin := a.actor(r)
	renewal, err := a.store.WithdrawRenewal(id, actor, isAdmin)
	if err != nil {
		a.storeError(w, "withdraw renewal", err)
		return
	}
	presentRenewal(renewal, actor, isAdmin)
	writeJSON(w, http.StatusOK, renewal)
}

// ---------- upload validation ----------

// detectEvidenceType identifies the upload from its own bytes. The browser's
// declared Content-Type is not trusted: it is attacker-controlled, and the
// whole value of the evidence is that it is what it claims to be.
func detectEvidenceType(data []byte) (string, error) {
	if len(data) == 0 {
		return "", fmt.Errorf("The uploaded file is empty")
	}
	detected := http.DetectContentType(data)
	if i := strings.Index(detected, ";"); i > 0 {
		detected = strings.TrimSpace(detected[:i])
	}
	if _, ok := allowedEvidenceTypes[detected]; !ok {
		return "", fmt.Errorf("Evidence must be a PNG, JPEG, WebP or GIF image (got %s)", detected)
	}
	return detected, nil
}

// safeFilename reduces an uploaded name to a harmless base name with an
// extension that matches what the bytes actually are.
func safeFilename(name, ext string) string {
	base := filepath.Base(strings.ReplaceAll(name, `\`, "/"))
	base = strings.TrimSuffix(base, filepath.Ext(base))
	base = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '-', r == '_', r == '.':
			return r
		default:
			return '-'
		}
	}, base)
	base = strings.Trim(base, "-.")
	if base == "" || base == ".." {
		base = "evidence"
	}
	if len(base) > 60 {
		base = base[:60]
	}
	return base + ext
}
