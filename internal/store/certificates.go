package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/lib/pq"

	"certtracker/internal/models"
)

var (
	ErrNotFound = errors.New("certificate not found")
	// ErrForbidden means the row exists but the caller may not change it.
	// Certificates are readable tracker-wide, so hiding existence would buy
	// nothing — a precise error is the more useful answer.
	ErrForbidden = errors.New("not permitted")
	// ErrCertLocked covers edits to a certificate that is no longer live.
	ErrCertLocked = errors.New("certificate is rotated or deleted")
)

// certSelect reads a certificate plus the owner's username and the ids of any
// open renewal / deletion request. Kept as one string so every read path
// returns rows that scanCert can consume.
const certSelect = `
	SELECT c.id, c.name, c.kind, c.environment, c.issued_date, c.expiry_date,
	       c.reminder_days, c.teams_webhook_url, c.notify_emails, c.notes,
	       c.created_at, c.updated_at,
	       c.owner_id, COALESCE(u.username, ''), c.deleted_at, c.deletion_reason,
	       c.rotated_at, c.renewed_from_id, c.last_notified_on,
	       (SELECT r.id FROM renewals r
	         WHERE r.certificate_id = c.id AND r.status = 'pending_review' LIMIT 1),
	       (SELECT d.id FROM deletion_requests d
	         WHERE d.certificate_id = c.id AND d.status = 'pending_review' LIMIT 1)
	  FROM certificates c
	  LEFT JOIN users u ON u.id = c.owner_id`

// certReturning is the RETURNING clause for writes. It cannot join, so the
// owner username and the pending-request ids come back empty; write paths that
// need them re-read through certSelect.
const certReturning = `
	RETURNING id, name, kind, environment, issued_date, expiry_date,
	          reminder_days, teams_webhook_url, notify_emails, notes,
	          created_at, updated_at,
	          owner_id, '', deleted_at, deletion_reason, rotated_at,
	          renewed_from_id, last_notified_on, NULL::bigint, NULL::bigint`

func scanCert(row rowScanner) (*models.Certificate, error) {
	var c models.Certificate
	var days pq.Int64Array
	var emails pq.StringArray
	var ownerID, renewedFrom, pendingRenewal, pendingDeletion sql.NullInt64
	var deletedAt, rotatedAt, lastNotified sql.NullTime

	if err := row.Scan(
		&c.ID, &c.Name, &c.Kind, &c.Environment, &c.IssuedDate, &c.ExpiryDate,
		&days, &c.TeamsWebhook, &emails, &c.Notes, &c.CreatedAt, &c.UpdatedAt,
		&ownerID, &c.OwnerUsername, &deletedAt, &c.DeletionReason, &rotatedAt,
		&renewedFrom, &lastNotified, &pendingRenewal, &pendingDeletion,
	); err != nil {
		return nil, err
	}
	c.ReminderDays = fromInt64Slice(days)
	c.NotifyEmails = []string(emails)
	if c.NotifyEmails == nil {
		c.NotifyEmails = []string{}
	}
	c.OwnerID = nullInt(ownerID)
	c.RenewedFromID = nullInt(renewedFrom)
	c.PendingRenewalID = nullInt(pendingRenewal)
	c.PendingDeletionID = nullInt(pendingDeletion)
	c.DeletedAt = nullTime(deletedAt)
	c.RotatedAt = nullTime(rotatedAt)
	c.LastNotifiedOn = nullTime(lastNotified)
	return &c, nil
}

func nullInt(v sql.NullInt64) *int64 {
	if !v.Valid {
		return nil
	}
	n := v.Int64
	return &n
}

func nullTime(v sql.NullTime) *time.Time {
	if !v.Valid {
		return nil
	}
	t := v.Time
	return &t
}

// lib/pq scans/values []int64 and []string via concrete Array types; []int is
// not supported, so convert at the boundary.
func toInt64Slice(in []int) pq.Int64Array {
	out := make(pq.Int64Array, len(in))
	for i, v := range in {
		out[i] = int64(v)
	}
	return out
}

func fromInt64Slice(in pq.Int64Array) []int {
	out := make([]int, len(in))
	for i, v := range in {
		out[i] = int(v)
	}
	return out
}

// certKind reads the kind of one certificate inside a transaction. Audit rows
// carry it so the log can be filtered by type without joining back to a row
// that may since have been renamed or deleted.
func certKind(tx *sql.Tx, id int64) string {
	var kind string
	if err := tx.QueryRow(`SELECT kind FROM certificates WHERE id=$1`, id).Scan(&kind); err != nil {
		return models.KindCertificate
	}
	return kind
}

// ---------- reads ----------

// ListCertificates returns every certificate the tracker knows about.
// Soft-deleted rows are excluded unless includeDeleted is set (admin only).
func (s *Store) ListCertificates(includeDeleted bool) ([]*models.Certificate, error) {
	q := certSelect + ` WHERE ($1 OR c.deleted_at IS NULL) ORDER BY c.expiry_date ASC`
	return s.queryCerts(q, includeDeleted)
}

// ListLiveCertificates returns the certificates the scheduler should watch:
// neither soft-deleted nor already rotated. A rotated certificate has been
// replaced, so nagging about its expiry would be pure noise.
func (s *Store) ListLiveCertificates() ([]*models.Certificate, error) {
	return s.queryCerts(certSelect + `
		WHERE c.deleted_at IS NULL AND c.rotated_at IS NULL
		ORDER BY c.expiry_date ASC`)
}

func (s *Store) queryCerts(q string, args ...any) ([]*models.Certificate, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*models.Certificate{}
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) GetCertificate(id int64) (*models.Certificate, error) {
	c, err := scanCert(s.db.QueryRow(certSelect+` WHERE c.id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

// ---------- writes ----------

// CreateCertificate inserts a certificate owned by the actor.
func (s *Store) CreateCertificate(c *models.Certificate, actor Actor) (*models.Certificate, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	created, err := scanCert(tx.QueryRow(
		`INSERT INTO certificates
		 (name, kind, environment, issued_date, expiry_date, reminder_days,
		  teams_webhook_url, notify_emails, notes, owner_id, renewed_from_id)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`+certReturning,
		c.Name, c.Kind, c.Environment, c.IssuedDate, c.ExpiryDate,
		toInt64Slice(c.ReminderDays), c.TeamsWebhook, pq.StringArray(c.NotifyEmails),
		c.Notes, actor.ID, c.RenewedFromID))
	if err != nil {
		return nil, err
	}

	if err := auditTx(tx, actor, ActionCertCreate, "certificate", &created.ID, map[string]any{
		"name":        created.Name,
		"kind":        created.Kind,
		"environment": created.Environment,
		"expiry_date": models.DateOnly(created.ExpiryDate),
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetCertificate(created.ID)
}

// lockCertForWrite loads the mutable state of a certificate under a row lock
// and applies the ownership rule. Every mutating path goes through it, so
// "owner or admin" is enforced in exactly one place and cannot be forgotten.
func lockCertForWrite(tx *sql.Tx, id int64, actor Actor, isAdmin bool, requireLive bool) (ownerID *int64, err error) {
	var owner sql.NullInt64
	var deletedAt, rotatedAt sql.NullTime
	err = tx.QueryRow(
		`SELECT owner_id, deleted_at, rotated_at FROM certificates WHERE id=$1 FOR UPDATE`, id).
		Scan(&owner, &deletedAt, &rotatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !isAdmin && !(owner.Valid && owner.Int64 == actor.ID) {
		return nil, ErrForbidden
	}
	if requireLive && (deletedAt.Valid || rotatedAt.Valid) {
		return nil, ErrCertLocked
	}
	return nullInt(owner), nil
}

// UpdateCertificate writes new values, enforcing owner-or-admin. If the expiry
// date changed the reminder state is cleared so the cycle re-arms.
func (s *Store) UpdateCertificate(c *models.Certificate, actor Actor, isAdmin bool) (*models.Certificate, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if _, err := lockCertForWrite(tx, c.ID, actor, isAdmin, true); err != nil {
		return nil, err
	}

	var prevExpiry time.Time
	var prevName string
	if err := tx.QueryRow(`SELECT expiry_date, name FROM certificates WHERE id=$1`, c.ID).
		Scan(&prevExpiry, &prevName); err != nil {
		return nil, err
	}

	updated, err := scanCert(tx.QueryRow(
		`UPDATE certificates SET
		   name=$1, environment=$2, issued_date=$3, expiry_date=$4,
		   reminder_days=$5, teams_webhook_url=$6, notify_emails=$7, notes=$8,
		   updated_at=now()
		 WHERE id=$9`+certReturning,
		c.Name, c.Environment, c.IssuedDate, c.ExpiryDate,
		toInt64Slice(c.ReminderDays), c.TeamsWebhook, pq.StringArray(c.NotifyEmails),
		c.Notes, c.ID))
	if err != nil {
		return nil, err
	}

	if !prevExpiry.Equal(updated.ExpiryDate) {
		if _, err := tx.Exec(`DELETE FROM notifications_sent WHERE certificate_id=$1`, c.ID); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(`UPDATE certificates SET last_notified_on=NULL WHERE id=$1`, c.ID); err != nil {
			return nil, err
		}
	}

	if err := auditTx(tx, actor, ActionCertUpdate, "certificate", &updated.ID, map[string]any{
		"name":           updated.Name,
		"kind":           updated.Kind,
		"expiry_date":    models.DateOnly(updated.ExpiryDate),
		"expiry_changed": !prevExpiry.Equal(updated.ExpiryDate),
		"prev_expiry":    models.DateOnly(prevExpiry),
		"renamed_from":   prevName,
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetCertificate(updated.ID)
}

// RestoreCertificate undoes a soft delete. Admin-only at the API layer.
func (s *Store) RestoreCertificate(id int64, actor Actor) (*models.Certificate, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var name string
	err = tx.QueryRow(
		`UPDATE certificates SET deleted_at=NULL, deleted_by=NULL, deletion_reason='',
		        updated_at=now()
		  WHERE id=$1 AND deleted_at IS NOT NULL RETURNING name`, id).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := auditTx(tx, actor, ActionCertRestore, "certificate", &id,
		map[string]any{"name": name, "kind": certKind(tx, id)}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetCertificate(id)
}

// TransferOwner hands a certificate to another active user. Without this an
// owner leaving the company would strand their certificates: nobody but an
// admin could ever adjust the reminders again.
func (s *Store) TransferOwner(id, newOwnerID int64, actor Actor, isAdmin bool) (*models.Certificate, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	prevOwner, err := lockCertForWrite(tx, id, actor, isAdmin, false)
	if err != nil {
		return nil, err
	}

	var newOwnerName string
	var disabled sql.NullTime
	err = tx.QueryRow(`SELECT username, disabled_at FROM users WHERE id=$1`, newOwnerID).
		Scan(&newOwnerName, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	if disabled.Valid {
		return nil, ErrUserDisabled
	}

	if _, err := tx.Exec(
		`UPDATE certificates SET owner_id=$1, updated_at=now() WHERE id=$2`, newOwnerID, id); err != nil {
		return nil, err
	}

	detail := map[string]any{
		"new_owner": newOwnerName, "new_owner_id": newOwnerID, "kind": certKind(tx, id),
	}
	if prevOwner != nil {
		detail["prev_owner_id"] = *prevOwner
	}
	if err := auditTx(tx, actor, ActionCertTransfer, "certificate", &id, detail); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetCertificate(id)
}

// AssertCanWrite reports whether the actor may mutate the certificate, for
// handlers (test notification, renewal submission) that don't write the row.
func (s *Store) AssertCanWrite(c *models.Certificate, actor Actor, isAdmin bool) error {
	if !isAdmin && !c.OwnedBy(actor.ID) {
		return ErrForbidden
	}
	if !c.IsLive() {
		return ErrCertLocked
	}
	return nil
}

// AdoptOrphans assigns every ownerless certificate to a user. Used once at
// startup so rows created before ownership existed remain editable.
func (s *Store) AdoptOrphans(ownerID int64) (int64, error) {
	res, err := s.db.Exec(
		`UPDATE certificates SET owner_id=$1 WHERE owner_id IS NULL`, ownerID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}
