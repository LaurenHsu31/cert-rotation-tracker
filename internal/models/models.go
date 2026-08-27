package models

import (
	"time"

	"certtracker/internal/severity"
)

// Environment values a certificate can be tagged with. This is DATA about
// which environment the certificate belongs to — distinct from the tracker's
// own deployment environment.
const (
	EnvDev = "dev"
	EnvStg = "stg"
	EnvPrd = "prd"
)

func ValidEnvironment(e string) bool {
	return e == EnvDev || e == EnvStg || e == EnvPrd
}

// Roles.
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

func ValidRole(r string) bool { return r == RoleAdmin || r == RoleUser }

// Kinds of tracked secret. A certificate and an API/service token expire the
// same way and need the same rotation discipline, so they share one table and
// one workflow — the kind only changes the wording people see.
const (
	KindCertificate = "certificate"
	KindToken       = "token"
)

func ValidKind(k string) bool { return k == KindCertificate || k == KindToken }

// KindLabel is the capitalised noun used in notifications and headings.
func KindLabel(k string) string {
	if k == KindToken {
		return "Token"
	}
	return "Certificate"
}

// Renewal request states.
const (
	RenewalPending   = "pending_review"
	RenewalApproved  = "approved"
	RenewalRejected  = "rejected"
	RenewalWithdrawn = "withdrawn"
)

// Deletion request states. Same vocabulary as renewals — both are four-eyes
// requests — but kept as their own constants so the two workflows can diverge
// without a silent rename rippling through the other.
const (
	DeletionPending   = "pending_review"
	DeletionApproved  = "approved"
	DeletionRejected  = "rejected"
	DeletionWithdrawn = "withdrawn"
)

// User is an account that can sign in. Password hashes never leave the store
// layer, so there is no field for one here.
type User struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	// Email is the login identifier as well as the address notifications and
	// one-time passwords go to. Accounts created before it became the
	// identifier may still have it empty and sign in by username.
	Email      string     `json:"email"`
	Role       string     `json:"role"`
	Disabled   bool       `json:"disabled"`
	DisabledAt *time.Time `json:"disabled_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`

	// MustChangePassword is set while the account is holding a one-time
	// password (or one an administrator chose). Until it is cleared the API
	// refuses everything except signing out and setting a new password.
	MustChangePassword bool `json:"must_change_password"`
}

// Certificate is a tracked certificate and its reminder configuration.
type Certificate struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	// Kind is "certificate" or "token" — see KindCertificate/KindToken.
	Kind         string    `json:"kind"`
	Environment  string    `json:"environment"`
	IssuedDate   time.Time `json:"issued_date"` // date only
	ExpiryDate   time.Time `json:"expiry_date"` // date only
	ReminderDays []int     `json:"reminder_days"`
	TeamsWebhook string    `json:"teams_webhook_url"`
	NotifyEmails []string  `json:"notify_emails"`
	Notes        string    `json:"notes"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`

	// Ownership & lifecycle.
	OwnerID        *int64     `json:"owner_id"`
	OwnerUsername  string     `json:"owner_username"`
	DeletedAt      *time.Time `json:"deleted_at,omitempty"`
	DeletionReason string     `json:"deletion_reason,omitempty"`
	RotatedAt      *time.Time `json:"rotated_at,omitempty"`
	RenewedFromID  *int64     `json:"renewed_from_id,omitempty"`
	// LastNotifiedOn is the calendar date an alert last went out, in the
	// tracker's timezone. It drives the escalating reminder cadence.
	LastNotifiedOn *time.Time `json:"last_notified_on,omitempty"`

	// Computed on read (not stored):
	DaysRemaining int    `json:"days_remaining"`
	Severity      string `json:"severity"`
	LifePercent   int    `json:"life_percent"` // 0-100, how much of issued->expiry has elapsed

	// Set per-viewer by the API layer (not stored):
	CanEdit           bool   `json:"can_edit"`
	TeamsWebhookSet   bool   `json:"teams_webhook_set"`
	NotifyEmailCount  int    `json:"notify_email_count"`
	Redacted          bool   `json:"redacted"`
	PendingRenewalID  *int64 `json:"pending_renewal_id,omitempty"`
	PendingDeletionID *int64 `json:"pending_deletion_id,omitempty"`
	ReminderIntervalD int    `json:"reminder_interval_days"` // 0 = milestone-only, no repeat yet
}

// Renewal is a request to mark a certificate rotated. It always carries proof
// and always needs a second person to approve, so no single account can retire
// a certificate on its own.
type Renewal struct {
	ID               int64      `json:"id"`
	CertificateID    int64      `json:"certificate_id"`
	CertificateName  string     `json:"certificate_name"`
	Environment      string     `json:"environment"`
	Status           string     `json:"status"`
	NewIssuedDate    time.Time  `json:"new_issued_date"`
	NewExpiryDate    time.Time  `json:"new_expiry_date"`
	Note             string     `json:"note"`
	EvidenceMIME     string     `json:"evidence_mime"`
	EvidenceFilename string     `json:"evidence_filename"`
	EvidenceSize     int        `json:"evidence_size"`
	EvidenceSHA256   string     `json:"evidence_sha256"`
	SubmittedBy      int64      `json:"submitted_by"`
	SubmittedByName  string     `json:"submitted_by_username"`
	SubmittedAt      time.Time  `json:"submitted_at"`
	ReviewedBy       *int64     `json:"reviewed_by,omitempty"`
	ReviewedByName   string     `json:"reviewed_by_username,omitempty"`
	ReviewedAt       *time.Time `json:"reviewed_at,omitempty"`
	ReviewNote       string     `json:"review_note"`
	NewCertificateID *int64     `json:"new_certificate_id,omitempty"`

	// Set per-viewer by the API layer (not stored):
	CanReview   bool `json:"can_review"`
	CanWithdraw bool `json:"can_withdraw"`
}

// DeletionRequest is a request to remove a tracked certificate or token. Like
// a Renewal it always carries a reason and always needs a second person, so no
// single account can make a tracked secret disappear on its own.
type DeletionRequest struct {
	ID              int64      `json:"id"`
	CertificateID   int64      `json:"certificate_id"`
	CertificateName string     `json:"certificate_name"`
	CertificateKind string     `json:"certificate_kind"`
	Environment     string     `json:"environment"`
	Status          string     `json:"status"`
	Reason          string     `json:"reason"`
	RequestedBy     int64      `json:"requested_by"`
	RequestedByName string     `json:"requested_by_username"`
	RequestedAt     time.Time  `json:"requested_at"`
	ReviewedBy      *int64     `json:"reviewed_by,omitempty"`
	ReviewedByName  string     `json:"reviewed_by_username,omitempty"`
	ReviewedAt      *time.Time `json:"reviewed_at,omitempty"`
	ReviewNote      string     `json:"review_note"`

	// Set per-viewer by the API layer (not stored):
	CanReview   bool `json:"can_review"`
	CanWithdraw bool `json:"can_withdraw"`
}

// AuditEntry is one immutable record of who did what.
type AuditEntry struct {
	ID         int64     `json:"id"`
	ActorID    *int64    `json:"actor_id,omitempty"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	EntityType string    `json:"entity_type"`
	EntityID   *int64    `json:"entity_id,omitempty"`
	Detail     any       `json:"detail"`
	CreatedAt  time.Time `json:"created_at"`
}

// DateOnly formats a stored date without the (meaningless) time component.
func DateOnly(t time.Time) string { return t.Format("2006-01-02") }

// DaysUntil returns whole calendar days from `now` (in loc) until `date`.
// Both are reduced to their calendar date so timezone/DST never shifts the
// count. Negative means the date is in the past.
func DaysUntil(date, now time.Time, loc *time.Location) int {
	n := now.In(loc)
	d := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, time.UTC)
	today := time.Date(n.Year(), n.Month(), n.Day(), 0, 0, 0, 0, time.UTC)
	return int(d.Sub(today).Hours() / 24)
}

// Enrich populates the computed fields (DaysRemaining, Severity, LifePercent).
func (c *Certificate) Enrich(now time.Time, loc *time.Location, cuts severity.Cutoffs) {
	if c.Kind == "" {
		c.Kind = KindCertificate
	}
	c.DaysRemaining = DaysUntil(c.ExpiryDate, now, loc)
	c.Severity = string(severity.Classify(c.DaysRemaining, cuts))
	c.TeamsWebhookSet = c.TeamsWebhook != ""
	c.NotifyEmailCount = len(c.NotifyEmails)

	total := c.ExpiryDate.Sub(c.IssuedDate).Hours() / 24
	if total <= 0 {
		if c.DaysRemaining <= 0 {
			c.LifePercent = 100
		} else {
			c.LifePercent = 0
		}
		return
	}
	elapsed := total - float64(c.DaysRemaining)
	pct := int((elapsed / total) * 100)
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	c.LifePercent = pct
}

// IsLive reports whether the cert should still be watched by the scheduler.
func (c *Certificate) IsLive() bool { return c.DeletedAt == nil && c.RotatedAt == nil }

// OwnedBy reports whether userID is the recorded owner.
func (c *Certificate) OwnedBy(userID int64) bool {
	return c.OwnerID != nil && *c.OwnerID == userID
}

// Redact strips credential-bearing fields for viewers who neither own the
// certificate nor administer the tracker. A Teams webhook URL is a bearer
// token — anyone holding it can post to that channel — and the recipient list
// is personal data, so read access to a certificate must not leak either.
// The *Set/*Count fields survive so the UI can still show "Teams configured".
func (c *Certificate) Redact() {
	c.TeamsWebhook = ""
	c.NotifyEmails = []string{}
	c.Redacted = true
}
