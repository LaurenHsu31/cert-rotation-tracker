package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/lib/pq"

	"certtracker/internal/models"
)

var (
	ErrRenewalNotFound = errors.New("renewal request not found")
	ErrRenewalNotOpen  = errors.New("renewal request is no longer open")
	ErrRenewalOpen     = errors.New("this certificate already has an open renewal request")
	ErrSelfReview      = errors.New("a renewal must be reviewed by someone other than the person who submitted it")
	ErrNoEvidence      = errors.New("renewal evidence is required")
)

// renewalSelect deliberately omits the evidence blob — listing a queue of
// requests should not drag megabytes of images through the connection.
const renewalSelect = `
	SELECT r.id, r.certificate_id, c.name, c.environment, r.status,
	       r.new_issued_date, r.new_expiry_date, r.note,
	       r.evidence_mime, r.evidence_filename, r.evidence_size, r.evidence_sha256,
	       r.submitted_by, su.username, r.submitted_at,
	       r.reviewed_by, COALESCE(ru.username, ''), r.reviewed_at, r.review_note,
	       r.new_certificate_id
	  FROM renewals r
	  JOIN certificates c ON c.id = r.certificate_id
	  JOIN users su       ON su.id = r.submitted_by
	  LEFT JOIN users ru  ON ru.id = r.reviewed_by`

func scanRenewal(row rowScanner) (*models.Renewal, error) {
	var r models.Renewal
	var reviewedBy, newCertID sql.NullInt64
	var reviewedAt sql.NullTime
	if err := row.Scan(
		&r.ID, &r.CertificateID, &r.CertificateName, &r.Environment, &r.Status,
		&r.NewIssuedDate, &r.NewExpiryDate, &r.Note,
		&r.EvidenceMIME, &r.EvidenceFilename, &r.EvidenceSize, &r.EvidenceSHA256,
		&r.SubmittedBy, &r.SubmittedByName, &r.SubmittedAt,
		&reviewedBy, &r.ReviewedByName, &reviewedAt, &r.ReviewNote,
		&newCertID,
	); err != nil {
		return nil, err
	}
	r.ReviewedBy = nullInt(reviewedBy)
	r.NewCertificateID = nullInt(newCertID)
	r.ReviewedAt = nullTime(reviewedAt)
	return &r, nil
}

// ---------- reads ----------

// RenewalFilter narrows a renewal listing. A zero filter returns everything.
type RenewalFilter struct {
	CertificateID *int64
	Status        string
	Limit         int
}

func (s *Store) ListRenewals(f RenewalFilter) ([]*models.Renewal, error) {
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.db.Query(renewalSelect+`
		WHERE ($1::bigint IS NULL OR r.certificate_id = $1)
		  AND ($2 = '' OR r.status = $2)
		ORDER BY r.submitted_at DESC, r.id DESC
		LIMIT $3`, f.CertificateID, f.Status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*models.Renewal{}
	for rows.Next() {
		r, err := scanRenewal(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetRenewal(id int64) (*models.Renewal, error) {
	r, err := scanRenewal(s.db.QueryRow(renewalSelect+` WHERE r.id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrRenewalNotFound
	}
	return r, err
}

// Evidence is the stored proof image for a renewal.
type Evidence struct {
	Data     []byte
	MIME     string
	Filename string
}

func (s *Store) GetRenewalEvidence(id int64) (*Evidence, error) {
	var e Evidence
	err := s.db.QueryRow(
		`SELECT evidence, evidence_mime, evidence_filename FROM renewals WHERE id=$1`, id).
		Scan(&e.Data, &e.MIME, &e.Filename)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrRenewalNotFound
	}
	return &e, err
}

// ---------- writes ----------

// CreateRenewal opens a renewal request against a certificate. The caller must
// already own the certificate (or be an admin); the check runs under the same
// row lock as the insert.
func (s *Store) CreateRenewal(r *models.Renewal, evidence []byte, actor Actor, isAdmin bool) (*models.Renewal, error) {
	if len(evidence) == 0 {
		return nil, ErrNoEvidence
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if _, err := lockCertForWrite(tx, r.CertificateID, actor, isAdmin, true); err != nil {
		return nil, err
	}

	sum := sha256.Sum256(evidence)
	digest := hex.EncodeToString(sum[:])

	var id int64
	err = tx.QueryRow(
		`INSERT INTO renewals
		 (certificate_id, new_issued_date, new_expiry_date, note,
		  evidence, evidence_mime, evidence_filename, evidence_size, evidence_sha256,
		  submitted_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
		r.CertificateID, r.NewIssuedDate, r.NewExpiryDate, r.Note,
		evidence, r.EvidenceMIME, r.EvidenceFilename, len(evidence), digest,
		actor.ID).Scan(&id)
	if isUniqueViolation(err) {
		return nil, ErrRenewalOpen
	}
	if err != nil {
		return nil, err
	}

	if err := auditTx(tx, actor, ActionRenewalSubmit, "renewal", &id, map[string]any{
		"certificate_id":  r.CertificateID,
		"new_expiry_date": models.DateOnly(r.NewExpiryDate),
		"evidence_sha256": digest,
		"evidence_bytes":  len(evidence),
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetRenewal(id)
}

// lockRenewal loads an open renewal under a row lock.
func lockRenewal(tx *sql.Tx, id int64) (certID, submittedBy int64, err error) {
	var status string
	err = tx.QueryRow(
		`SELECT certificate_id, submitted_by, status FROM renewals WHERE id=$1 FOR UPDATE`, id).
		Scan(&certID, &submittedBy, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, ErrRenewalNotFound
	}
	if err != nil {
		return 0, 0, err
	}
	if status != models.RenewalPending {
		return 0, 0, ErrRenewalNotOpen
	}
	return certID, submittedBy, nil
}

// ApproveRenewal is the four-eyes step. In one transaction it: marks the old
// certificate rotated, creates its replacement carrying the same reminder
// configuration and owner, and records who approved what. The reviewer can
// never be the submitter — that rule is the entire point of the workflow, so
// it is enforced here (and again by a CHECK constraint) rather than in the
// handler.
func (s *Store) ApproveRenewal(id int64, note string, actor Actor) (*models.Renewal, *models.Certificate, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()

	certID, submittedBy, err := lockRenewal(tx, id)
	if err != nil {
		return nil, nil, err
	}
	if submittedBy == actor.ID {
		return nil, nil, ErrSelfReview
	}

	// Lock the certificate and confirm it is still live. Ownership is NOT
	// required to review: a reviewer is deliberately a different person.
	var (
		name, env, webhook, notes string
		days                      pq.Int64Array
		emails                    pq.StringArray
		ownerID                   sql.NullInt64
		deletedAt, rotatedAt      sql.NullTime
	)
	err = tx.QueryRow(
		`SELECT name, environment, reminder_days, teams_webhook_url, notify_emails,
		        notes, owner_id, deleted_at, rotated_at
		   FROM certificates WHERE id=$1 FOR UPDATE`, certID).
		Scan(&name, &env, &days, &webhook, &emails, &notes, &ownerID, &deletedAt, &rotatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	if deletedAt.Valid || rotatedAt.Valid {
		return nil, nil, ErrCertLocked
	}

	var newIssued, newExpiry time.Time
	if err := tx.QueryRow(
		`SELECT new_issued_date, new_expiry_date FROM renewals WHERE id=$1`, id).
		Scan(&newIssued, &newExpiry); err != nil {
		return nil, nil, err
	}

	// The replacement inherits everything operational; only the dates change.
	var newCertID int64
	if err := tx.QueryRow(
		`INSERT INTO certificates
		 (name, environment, issued_date, expiry_date, reminder_days,
		  teams_webhook_url, notify_emails, notes, owner_id, renewed_from_id)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
		name, env, newIssued, newExpiry, days, webhook, emails, notes, ownerID, certID).
		Scan(&newCertID); err != nil {
		return nil, nil, err
	}

	if _, err := tx.Exec(
		`UPDATE certificates SET rotated_at=now(), rotated_by=$1, updated_at=now() WHERE id=$2`,
		actor.ID, certID); err != nil {
		return nil, nil, err
	}

	if _, err := tx.Exec(
		`UPDATE renewals SET status=$1, reviewed_by=$2, reviewed_at=now(),
		        review_note=$3, new_certificate_id=$4
		  WHERE id=$5`,
		models.RenewalApproved, actor.ID, note, newCertID, id); err != nil {
		return nil, nil, err
	}

	if err := auditTx(tx, actor, ActionRenewalApprove, "renewal", &id, map[string]any{
		"certificate_id":     certID,
		"certificate_name":   name,
		"new_certificate_id": newCertID,
		"new_expiry_date":    models.DateOnly(newExpiry),
		"submitted_by":       submittedBy,
	}); err != nil {
		return nil, nil, err
	}
	if err := auditTx(tx, actor, ActionCertCreate, "certificate", &newCertID, map[string]any{
		"name":            name,
		"environment":     env,
		"expiry_date":     models.DateOnly(newExpiry),
		"via":             "renewal",
		"renewed_from_id": certID,
	}); err != nil {
		return nil, nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}

	renewal, err := s.GetRenewal(id)
	if err != nil {
		return nil, nil, err
	}
	newCert, err := s.GetCertificate(newCertID)
	if err != nil {
		return nil, nil, err
	}
	return renewal, newCert, nil
}

// RejectRenewal sends the request back. Like approval, the reviewer must be
// someone other than the submitter.
func (s *Store) RejectRenewal(id int64, note string, actor Actor) (*models.Renewal, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	certID, submittedBy, err := lockRenewal(tx, id)
	if err != nil {
		return nil, err
	}
	if submittedBy == actor.ID {
		return nil, ErrSelfReview
	}

	if _, err := tx.Exec(
		`UPDATE renewals SET status=$1, reviewed_by=$2, reviewed_at=now(), review_note=$3
		  WHERE id=$4`, models.RenewalRejected, actor.ID, note, id); err != nil {
		return nil, err
	}
	if err := auditTx(tx, actor, ActionRenewalReject, "renewal", &id, map[string]any{
		"certificate_id": certID,
		"reason":         note,
		"submitted_by":   submittedBy,
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetRenewal(id)
}

// WithdrawRenewal lets the submitter (or an admin) cancel their own request,
// e.g. to re-upload better evidence.
func (s *Store) WithdrawRenewal(id int64, actor Actor, isAdmin bool) (*models.Renewal, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	certID, submittedBy, err := lockRenewal(tx, id)
	if err != nil {
		return nil, err
	}
	if !isAdmin && submittedBy != actor.ID {
		return nil, ErrForbidden
	}

	if _, err := tx.Exec(
		`UPDATE renewals SET status=$1 WHERE id=$2`, models.RenewalWithdrawn, id); err != nil {
		return nil, err
	}
	if err := auditTx(tx, actor, ActionRenewalWithdraw, "renewal", &id, map[string]any{
		"certificate_id": certID,
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetRenewal(id)
}
