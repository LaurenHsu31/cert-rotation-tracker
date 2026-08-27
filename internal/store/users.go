package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"certtracker/internal/auth"
	"certtracker/internal/models"
)

var (
	ErrUserNotFound   = errors.New("user not found")
	ErrUserExists     = errors.New("username already taken")
	ErrEmailExists    = errors.New("that email address already has an account")
	ErrUserDisabled   = errors.New("account is disabled")
	ErrBadCredentials = errors.New("invalid username or password")
	// ErrPasswordExpired means the credentials were right but they were a
	// one-time password that has since timed out.
	ErrPasswordExpired = errors.New("one-time password has expired")
	// ErrLastAdmin guards against locking everyone out of the tracker by
	// demoting or disabling the only remaining admin.
	ErrLastAdmin = errors.New("cannot remove the last active admin")
)

const userColumns = `id, username, display_name, email, role, disabled_at, created_at, must_change_password`

func scanUser(row rowScanner) (*models.User, error) {
	var u models.User
	var disabled sql.NullTime
	if err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.Role,
		&disabled, &u.CreatedAt, &u.MustChangePassword); err != nil {
		return nil, err
	}
	if disabled.Valid {
		t := disabled.Time
		u.DisabledAt = &t
		u.Disabled = true
	}
	return &u, nil
}

// NormalizeUsername lower-cases and trims, so "Alice" and "alice" are the
// same account and can't be registered twice.
func NormalizeUsername(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// NormalizeEmail applies the same rule to the login address. Mail servers do
// not distinguish the case of a domain, and people do not distinguish it at
// all, so storing one canonical form is what makes "one address, one account"
// actually hold.
func NormalizeEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

func (s *Store) ListUsers() ([]*models.User, error) {
	rows, err := s.db.Query(`SELECT ` + userColumns + ` FROM users ORDER BY username ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*models.User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) GetUser(id int64) (*models.User, error) {
	u, err := scanUser(s.db.QueryRow(`SELECT `+userColumns+` FROM users WHERE id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	return u, err
}

func (s *Store) GetUserByUsername(username string) (*models.User, error) {
	u, err := scanUser(s.db.QueryRow(`SELECT `+userColumns+` FROM users WHERE username=$1`, NormalizeUsername(username)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	return u, err
}

func (s *Store) GetUserByEmail(email string) (*models.User, error) {
	e := NormalizeEmail(email)
	if e == "" {
		return nil, ErrUserNotFound
	}
	u, err := scanUser(s.db.QueryRow(`SELECT `+userColumns+` FROM users WHERE email=$1`, e))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	return u, err
}

// CreateUser hashes the password and inserts the account. mustChange marks the
// password as a handover credential: whoever signs in with it has to replace it
// before the account can do anything else.
func (s *Store) CreateUser(username, displayName, email, password, role string, mustChange bool) (*models.User, error) {
	hash, err := auth.HashPassword(password)
	if err != nil {
		return nil, err
	}
	u, err := scanUser(s.db.QueryRow(
		`INSERT INTO users (username, display_name, email, password_hash, role, must_change_password)
		 VALUES ($1,$2,$3,$4,$5,$6) RETURNING `+userColumns,
		NormalizeUsername(username), strings.TrimSpace(displayName), NormalizeEmail(email),
		hash, role, mustChange))
	if isUniqueViolation(err) {
		return nil, uniqueUserErr(err)
	}
	return u, err
}

// uniqueUserErr tells the two unique constraints on users apart, so the caller
// can say which field actually clashed instead of guessing.
func uniqueUserErr(err error) error {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && strings.Contains(pqErr.Constraint, "email") {
		return ErrEmailExists
	}
	return ErrUserExists
}

// SuggestUsername turns a login address into a readable handle for the audit
// log and ownership chips, adding a numeric suffix when the obvious one is
// taken. Screens that name a person read far better as "alice" than as
// "alice@example.com", but the account is still the address.
func (s *Store) SuggestUsername(email string) (string, error) {
	base := NormalizeEmail(email)
	if i := strings.Index(base, "@"); i > 0 {
		base = base[:i]
	}
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, base)
	cleaned = strings.Trim(cleaned, ".-_")
	if len(cleaned) < 3 {
		cleaned = "user" + cleaned
	}
	if len(cleaned) > 28 {
		cleaned = cleaned[:28]
	}

	candidate := cleaned
	for n := 2; n < 100; n++ {
		var exists bool
		if err := s.db.QueryRow(
			`SELECT EXISTS (SELECT 1 FROM users WHERE username=$1)`, candidate).Scan(&exists); err != nil {
			return "", err
		}
		if !exists {
			return candidate, nil
		}
		candidate = fmt.Sprintf("%s%d", cleaned, n)
	}
	return "", errors.New("could not derive a free username from that address")
}

// Authenticate verifies credentials. The identifier is the account's email
// address; the username is still accepted so accounts created before email
// became the identifier (the bootstrap admin among them) can still sign in.
// The KDF always runs, even for unknown identifiers, so response time does not
// reveal which accounts exist.
func (s *Store) Authenticate(identifier, password string) (*models.User, error) {
	var (
		u          models.User
		hash       string
		disabled   sql.NullTime
		expiresAt  sql.NullTime
		normalized = NormalizeEmail(identifier)
	)

	// One query for both forms: an address never looks like a username, so
	// there is no ambiguity to resolve and no second round trip to pay for.
	row := s.db.QueryRow(
		`SELECT id, username, display_name, email, role, password_hash,
		        disabled_at, must_change_password, password_expires_at
		   FROM users
		  WHERE (email <> '' AND email = $1) OR username = $1
		  ORDER BY (email = $1) DESC
		  LIMIT 1`, normalized)
	err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.Role, &hash,
		&disabled, &u.MustChangePassword, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		// Burn comparable time against a dummy hash of the same shape.
		_, _ = auth.VerifyPassword(dummyHash, password)
		return nil, ErrBadCredentials
	}
	if err != nil {
		return nil, err
	}

	ok, verr := auth.VerifyPassword(hash, password)
	if verr != nil || !ok {
		return nil, ErrBadCredentials
	}
	if disabled.Valid {
		return nil, ErrUserDisabled
	}
	// Checked only after the password matched, so the expiry of a one-time
	// password is never disclosed to someone who does not already hold it.
	if expiresAt.Valid && expiresAt.Time.Before(time.Now()) {
		return nil, ErrPasswordExpired
	}
	return &u, nil
}

// VerifyCurrentPassword checks a password against one account by id, ignoring
// expiry. The forced-change screen needs this: the credential in hand is very
// often the one-time password that just expired, and refusing it there would
// strand the holder on a screen whose whole purpose is to replace it.
func (s *Store) VerifyCurrentPassword(id int64, password string) error {
	var hash string
	err := s.db.QueryRow(`SELECT password_hash FROM users WHERE id=$1`, id).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUserNotFound
	}
	if err != nil {
		return err
	}
	ok, verr := auth.VerifyPassword(hash, password)
	if verr != nil || !ok {
		return ErrBadCredentials
	}
	return nil
}

// UpdateUser changes the profile/role/disabled state of an account.
func (s *Store) UpdateUser(id int64, displayName, email, role string, disabled bool) (*models.User, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Lock the row, then re-check the admin floor inside the transaction so
	// two concurrent demotions can't both pass the check.
	var curRole string
	var curDisabled sql.NullTime
	err = tx.QueryRow(`SELECT role, disabled_at FROM users WHERE id=$1 FOR UPDATE`, id).
		Scan(&curRole, &curDisabled)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}

	wasActiveAdmin := curRole == models.RoleAdmin && !curDisabled.Valid
	willBeActiveAdmin := role == models.RoleAdmin && !disabled
	if wasActiveAdmin && !willBeActiveAdmin {
		if err := assertOtherActiveAdminExists(tx, id); err != nil {
			return nil, err
		}
	}

	u, err := scanUser(tx.QueryRow(
		`UPDATE users SET display_name=$1, email=$2, role=$3,
		        disabled_at = CASE WHEN $4 THEN COALESCE(disabled_at, now()) ELSE NULL END,
		        updated_at = now()
		  WHERE id=$5 RETURNING `+userColumns,
		strings.TrimSpace(displayName), strings.TrimSpace(email), role, disabled, id))
	if err != nil {
		return nil, err
	}

	// Disabling an account must kill its live sessions immediately, otherwise
	// the person stays signed in until their cookie expires.
	if disabled {
		if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id=$1`, id); err != nil {
			return nil, err
		}
	}
	return u, tx.Commit()
}

// SetPassword replaces an account's password and invalidates every session
// except the caller's current one (passed as keepTokenHash, may be nil).
// mustChange marks the new password as another handover credential — true when
// an administrator sets it for somebody else, false when the holder chooses
// their own, which is what clears a forced change.
func (s *Store) SetPassword(id int64, password string, keepTokenHash []byte, mustChange bool) error {
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.Exec(
		`UPDATE users SET password_hash=$1, must_change_password=$2,
		        password_expires_at=NULL, updated_at=now()
		  WHERE id=$3`, hash, mustChange, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	if keepTokenHash == nil {
		_, err = tx.Exec(`DELETE FROM sessions WHERE user_id=$1`, id)
	} else {
		_, err = tx.Exec(`DELETE FROM sessions WHERE user_id=$1 AND token_hash <> $2`, id, keepTokenHash)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

// IssueOneTimePassword replaces the account's password with a temporary one,
// marks it as needing replacement, and drops every live session for the
// account. Dropping the sessions is the point: whoever asked for the reset is
// claiming they lost control of the credential, so anyone currently signed in
// as that account has to prove themselves again.
//
// cooldown suppresses a repeat within that window and reports it, so the
// endpoint cannot be used to flood an inbox or to keep burning somebody's
// working password.
func (s *Store) IssueOneTimePassword(id int64, otp string, ttl, cooldown time.Duration) (bool, error) {
	hash, err := auth.HashPassword(otp)
	if err != nil {
		return false, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var lastReset sql.NullTime
	err = tx.QueryRow(`SELECT password_reset_at FROM users WHERE id=$1 FOR UPDATE`, id).Scan(&lastReset)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrUserNotFound
	}
	if err != nil {
		return false, err
	}
	if lastReset.Valid && time.Since(lastReset.Time) < cooldown {
		return false, nil
	}

	if _, err := tx.Exec(
		`UPDATE users SET password_hash=$1, must_change_password=true,
		        password_expires_at=$2, password_reset_at=now(), updated_at=now()
		  WHERE id=$3`, hash, time.Now().Add(ttl), id); err != nil {
		return false, err
	}
	if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id=$1`, id); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func assertOtherActiveAdminExists(tx *sql.Tx, excludeID int64) error {
	var n int
	err := tx.QueryRow(
		`SELECT count(*) FROM users
		  WHERE role=$1 AND disabled_at IS NULL AND id <> $2`, models.RoleAdmin, excludeID).Scan(&n)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrLastAdmin
	}
	return nil
}

// dummyHash is a real PBKDF2 hash of an unguessable value, used to keep
// failed logins for unknown users as slow as failed logins for known ones.
var dummyHash = mustHash()

func mustHash() string {
	h, err := auth.HashPassword("cert-tracker-timing-equalizer")
	if err != nil {
		return ""
	}
	return h
}

func isUniqueViolation(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "23505"
}

// rowScanner covers both *sql.Row and *sql.Rows.
type rowScanner interface{ Scan(dest ...any) error }
