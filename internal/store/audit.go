package store

import (
	"database/sql"
	"encoding/json"

	"github.com/lib/pq"

	"certtracker/internal/models"
)

// Audit action names. Kept as constants so the UI filter and the writers can
// never drift apart.
const (
	ActionCertCreate      = "certificate.create"
	ActionCertUpdate      = "certificate.update"
	ActionCertDelete      = "certificate.delete"
	ActionCertRestore     = "certificate.restore"
	ActionCertTransfer    = "certificate.transfer_owner"
	ActionCertTest        = "certificate.test_notification"
	ActionRenewalSubmit   = "renewal.submit"
	ActionRenewalApprove  = "renewal.approve"
	ActionRenewalReject   = "renewal.reject"
	ActionRenewalWithdraw = "renewal.withdraw"
	ActionUserCreate      = "user.create"
	ActionUserUpdate      = "user.update"
	ActionUserPassword    = "user.password_change"
	ActionLogin           = "auth.login"
	ActionLoginFailed     = "auth.login_failed"
	ActionLogout          = "auth.logout"
	ActionRunCheck        = "task.run_check"
)

// AuditCategories groups actions into the buckets the UI filters by. Defined
// here, next to the action constants, so a new action cannot quietly fall out
// of every category.
var AuditCategories = map[string][]string{
	"certificate": {ActionCertCreate, ActionCertUpdate, ActionCertDelete,
		ActionCertRestore, ActionCertTransfer, ActionCertTest},
	"rotation": {ActionRenewalSubmit, ActionRenewalApprove,
		ActionRenewalReject, ActionRenewalWithdraw},
	"user":   {ActionUserCreate, ActionUserUpdate, ActionUserPassword},
	"auth":   {ActionLogin, ActionLoginFailed, ActionLogout},
	"system": {ActionRunCheck},
}

// CategoryActions returns the actions in a category, or nil for "all" and for
// any name that is not a category.
func CategoryActions(name string) []string {
	if name == "" || name == "all" {
		return nil
	}
	return AuditCategories[name]
}

// IsAuditCategory reports whether name is a known category (or "all").
func IsAuditCategory(name string) bool {
	if name == "" || name == "all" {
		return true
	}
	_, ok := AuditCategories[name]
	return ok
}

// dbtx is the subset of *sql.DB / *sql.Tx the audit writer needs, so audit
// rows can be written inside the same transaction as the change they describe.
type dbtx interface {
	Exec(query string, args ...any) (sql.Result, error)
	QueryRow(query string, args ...any) *sql.Row
}

// Actor identifies who performed an action. Username is denormalized into the
// audit row so history stays readable even if the account is later renamed.
type Actor struct {
	ID       int64
	Username string
}

// Audit appends an immutable record. It is best-effort by design at the call
// sites that pass s.db: a failure to log must not roll back a change the user
// already saw succeed — but inside a transaction the error is propagated.
func (s *Store) Audit(a Actor, action, entityType string, entityID *int64, detail map[string]any) error {
	return auditTx(s.db, a, action, entityType, entityID, detail)
}

func auditTx(q dbtx, a Actor, action, entityType string, entityID *int64, detail map[string]any) error {
	if detail == nil {
		detail = map[string]any{}
	}
	blob, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	var actorID any
	if a.ID > 0 {
		actorID = a.ID
	}
	_, err = q.Exec(
		`INSERT INTO audit_log (actor_id, actor_username, action, entity_type, entity_id, detail)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		actorID, a.Username, action, entityType, entityID, blob)
	return err
}

// AuditFilter narrows an audit query.
type AuditFilter struct {
	EntityType string
	EntityID   *int64
	Action     string
	// Actions restricts to a set (a category). Empty means no restriction.
	// Filtering in SQL rather than in the handler matters: the LIMIT is applied
	// after the filter, so picking a category returns the most recent 200 rows
	// OF THAT CATEGORY, not whatever survives from the most recent 200 overall.
	Actions []string
	Limit   int
}

// ListAudit returns audit rows newest-first.
func (s *Store) ListAudit(f AuditFilter) ([]*models.AuditEntry, error) {
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	var actions pq.StringArray
	if len(f.Actions) > 0 {
		actions = pq.StringArray(f.Actions)
	}
	rows, err := s.db.Query(
		`SELECT id, actor_id, actor_username, action, entity_type, entity_id, detail, created_at
		   FROM audit_log
		  WHERE ($1 = '' OR entity_type = $1)
		    AND ($2::bigint IS NULL OR entity_id = $2)
		    AND ($3 = '' OR action = $3)
		    AND ($4::text[] IS NULL OR action = ANY($4))
		  ORDER BY created_at DESC, id DESC
		  LIMIT $5`,
		f.EntityType, f.EntityID, f.Action, actions, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*models.AuditEntry{}
	for rows.Next() {
		var (
			e        models.AuditEntry
			actorID  sql.NullInt64
			entityID sql.NullInt64
			detail   []byte
		)
		if err := rows.Scan(&e.ID, &actorID, &e.Actor, &e.Action,
			&e.EntityType, &entityID, &detail, &e.CreatedAt); err != nil {
			return nil, err
		}
		if actorID.Valid {
			v := actorID.Int64
			e.ActorID = &v
		}
		if entityID.Valid {
			v := entityID.Int64
			e.EntityID = &v
		}
		var d any
		if err := json.Unmarshal(detail, &d); err != nil {
			d = map[string]any{}
		}
		e.Detail = d
		out = append(out, &e)
	}
	return out, rows.Err()
}
