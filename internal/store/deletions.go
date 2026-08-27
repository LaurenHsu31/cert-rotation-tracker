package store

import (
	"database/sql"
	"errors"
	"strings"

	"certtracker/internal/models"
)

var (
	ErrDeletionNotFound = errors.New("deletion request not found")
	ErrDeletionNotOpen  = errors.New("deletion request is no longer open")
	ErrDeletionOpen     = errors.New("this certificate already has an open deletion request")
	ErrNoReason         = errors.New("a reason for the deletion is required")
	// ErrSelfDeleteReview mirrors ErrSelfReview for the deletion workflow: the
	// whole point of asking for a reason is that somebody else reads it.
	ErrSelfDeleteReview = errors.New("a deletion must be reviewed by someone other than the person who requested it")
)

const deletionSelect = `
	SELECT d.id, d.certificate_id, c.name, c.kind, c.environment, d.status, d.reason,
	       d.requested_by, ru.username, d.requested_at,
	       d.reviewed_by, COALESCE(vu.username, ''), d.reviewed_at, d.review_note
	  FROM deletion_requests d
	  JOIN certificates c ON c.id = d.certificate_id
	  JOIN users ru       ON ru.id = d.requested_by
	  LEFT JOIN users vu  ON vu.id = d.reviewed_by`

func scanDeletion(row rowScanner) (*models.DeletionRequest, error) {
	var d models.DeletionRequest
	var reviewedBy sql.NullInt64
	var reviewedAt sql.NullTime
	if err := row.Scan(
		&d.ID, &d.CertificateID, &d.CertificateName, &d.CertificateKind, &d.Environment,
		&d.Status, &d.Reason,
		&d.RequestedBy, &d.RequestedByName, &d.RequestedAt,
		&reviewedBy, &d.ReviewedByName, &reviewedAt, &d.ReviewNote,
	); err != nil {
		return nil, err
	}
	d.ReviewedBy = nullInt(reviewedBy)
	d.ReviewedAt = nullTime(reviewedAt)
	return &d, nil
}

// ---------- reads ----------

// DeletionFilter narrows a deletion listing. A zero filter returns everything.
type DeletionFilter struct {
	CertificateID *int64
	Status        string
	Limit         int
}

func (s *Store) ListDeletions(f DeletionFilter) ([]*models.DeletionRequest, error) {
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.db.Query(deletionSelect+`
		WHERE ($1::bigint IS NULL OR d.certificate_id = $1)
		  AND ($2 = '' OR d.status = $2)
		ORDER BY d.requested_at DESC, d.id DESC
		LIMIT $3`, f.CertificateID, f.Status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*models.DeletionRequest{}
	for rows.Next() {
		d, err := scanDeletion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) GetDeletionRequest(id int64) (*models.DeletionRequest, error) {
	d, err := scanDeletion(s.db.QueryRow(deletionSelect+` WHERE d.id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrDeletionNotFound
	}
	return d, err
}

// ---------- writes ----------

// CreateDeletion opens a deletion request. Nothing is hidden yet: the row stays
// live and alerting until a second person approves, so a mistaken or malicious
// request cannot silence a certificate on its own.
func (s *Store) CreateDeletion(certID int64, reason string, actor Actor, isAdmin bool) (*models.DeletionRequest, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil, ErrNoReason
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if _, err := lockCertForWrite(tx, certID, actor, isAdmin, true); err != nil {
		return nil, err
	}

	var id int64
	err = tx.QueryRow(
		`INSERT INTO deletion_requests (certificate_id, reason, requested_by)
		 VALUES ($1,$2,$3) RETURNING id`, certID, reason, actor.ID).Scan(&id)
	if isUniqueViolation(err) {
		return nil, ErrDeletionOpen
	}
	if err != nil {
		return nil, err
	}

	if err := auditTx(tx, actor, ActionDeletionRequest, "deletion", &id, map[string]any{
		"certificate_id": certID,
		"kind":           certKind(tx, certID),
		"reason":         reason,
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetDeletionRequest(id)
}

// lockDeletion loads an open deletion request under a row lock.
func lockDeletion(tx *sql.Tx, id int64) (certID, requestedBy int64, reason string, err error) {
	var status string
	err = tx.QueryRow(
		`SELECT certificate_id, requested_by, reason, status
		   FROM deletion_requests WHERE id=$1 FOR UPDATE`, id).
		Scan(&certID, &requestedBy, &reason, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, "", ErrDeletionNotFound
	}
	if err != nil {
		return 0, 0, "", err
	}
	if status != models.DeletionPending {
		return 0, 0, "", ErrDeletionNotOpen
	}
	return certID, requestedBy, reason, nil
}

// ApproveDeletion is the four-eyes step. In one transaction it soft-deletes the
// certificate (hidden but recoverable), stamps the approved reason onto the row
// and closes any open renewal request, which could never be actioned afterwards.
// The certificate is returned so the caller can announce the deletion on its
// configured channels.
func (s *Store) ApproveDeletion(id int64, note string, actor Actor) (*models.DeletionRequest, *models.Certificate, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()

	certID, requestedBy, reason, err := lockDeletion(tx, id)
	if err != nil {
		return nil, nil, err
	}
	if requestedBy == actor.ID {
		return nil, nil, ErrSelfDeleteReview
	}

	// Ownership is NOT required to review: the reviewer is deliberately a
	// different person from the requester.
	var name string
	err = tx.QueryRow(
		`UPDATE certificates
		    SET deleted_at=now(), deleted_by=$1, deletion_reason=$2, updated_at=now()
		  WHERE id=$3 AND deleted_at IS NULL AND rotated_at IS NULL
		  RETURNING name`, actor.ID, reason, certID).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrCertLocked
	}
	if err != nil {
		return nil, nil, err
	}

	// An open renewal request on a deleted cert can never be actioned.
	if _, err := tx.Exec(
		`UPDATE renewals SET status=$1, review_note='certificate deleted'
		  WHERE certificate_id=$2 AND status=$3`,
		models.RenewalWithdrawn, certID, models.RenewalPending); err != nil {
		return nil, nil, err
	}

	if _, err := tx.Exec(
		`UPDATE deletion_requests
		    SET status=$1, reviewed_by=$2, reviewed_at=now(), review_note=$3
		  WHERE id=$4`, models.DeletionApproved, actor.ID, note, id); err != nil {
		return nil, nil, err
	}

	kind := certKind(tx, certID)
	if err := auditTx(tx, actor, ActionDeletionApprove, "deletion", &id, map[string]any{
		"certificate_id":   certID,
		"kind":             kind,
		"certificate_name": name,
		"reason":           reason,
		"requested_by":     requestedBy,
	}); err != nil {
		return nil, nil, err
	}
	// A second row against the certificate itself, so its own history shows the
	// deletion without having to cross-reference the request.
	if err := auditTx(tx, actor, ActionCertDelete, "certificate", &certID, map[string]any{
		"name":         name,
		"kind":         kind,
		"reason":       reason,
		"deletion_id":  id,
		"requested_by": requestedBy,
	}); err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}

	request, err := s.GetDeletionRequest(id)
	if err != nil {
		return nil, nil, err
	}
	cert, err := s.GetCertificate(certID)
	if err != nil {
		return nil, nil, err
	}
	return request, cert, nil
}

// RejectDeletion refuses the request and leaves the certificate alone.
func (s *Store) RejectDeletion(id int64, note string, actor Actor) (*models.DeletionRequest, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	certID, requestedBy, _, err := lockDeletion(tx, id)
	if err != nil {
		return nil, err
	}
	if requestedBy == actor.ID {
		return nil, ErrSelfDeleteReview
	}

	if _, err := tx.Exec(
		`UPDATE deletion_requests
		    SET status=$1, reviewed_by=$2, reviewed_at=now(), review_note=$3
		  WHERE id=$4`, models.DeletionRejected, actor.ID, note, id); err != nil {
		return nil, err
	}
	if err := auditTx(tx, actor, ActionDeletionReject, "deletion", &id, map[string]any{
		"certificate_id": certID,
		"kind":           certKind(tx, certID),
		"review_note":    note,
		"requested_by":   requestedBy,
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetDeletionRequest(id)
}

// WithdrawDeletion lets the requester (or an admin) cancel their own request.
func (s *Store) WithdrawDeletion(id int64, actor Actor, isAdmin bool) (*models.DeletionRequest, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	certID, requestedBy, _, err := lockDeletion(tx, id)
	if err != nil {
		return nil, err
	}
	if !isAdmin && requestedBy != actor.ID {
		return nil, ErrForbidden
	}

	if _, err := tx.Exec(
		`UPDATE deletion_requests SET status=$1 WHERE id=$2`,
		models.DeletionWithdrawn, id); err != nil {
		return nil, err
	}
	if err := auditTx(tx, actor, ActionDeletionWithdraw, "deletion", &id, map[string]any{
		"certificate_id": certID,
		"kind":           certKind(tx, certID),
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetDeletionRequest(id)
}
