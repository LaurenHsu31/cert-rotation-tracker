package store

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/lib/pq"

	"certtracker/internal/auth"
	"certtracker/internal/models"
)

var (
	ErrUserNotFound   = errors.New("user not found")
	ErrUserExists     = errors.New("username already taken")
	ErrUserDisabled   = errors.New("account is disabled")
	ErrBadCredentials = errors.New("invalid username or password")
	// ErrLastAdmin guards against locking everyone out of the tracker by
	// demoting or disabling the only remaining admin.
	ErrLastAdmin = errors.New("cannot remove the last active admin")
)

const userColumns = `id, username, display_name, email, role, disabled_at, created_at`

func scanUser(row rowScanner) (*models.User, error) {
	var u models.User
	var disabled sql.NullTime
	if err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.Role, &disabled, &u.CreatedAt); err != nil {
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

// CreateUser hashes the password and inserts the account.
func (s *Store) CreateUser(username, displayName, email, password, role string) (*models.User, error) {
	hash, err := auth.HashPassword(password)
	if err != nil {
		return nil, err
	}
	u, err := scanUser(s.db.QueryRow(
		`INSERT INTO users (username, display_name, email, password_hash, role)
		 VALUES ($1,$2,$3,$4,$5) RETURNING `+userColumns,
		NormalizeUsername(username), strings.TrimSpace(displayName), strings.TrimSpace(email), hash, role))
	if isUniqueViolation(err) {
		return nil, ErrUserExists
	}
	return u, err
}

// Authenticate verifies credentials. It always runs the KDF, even for unknown
// usernames, so response time does not reveal which accounts exist.
func (s *Store) Authenticate(username, password string) (*models.User, error) {
	var (
		id       int64
		uname    string
		display  string
		email    string
		role     string
		hash     string
		disabled sql.NullTime
	)

	row := s.db.QueryRow(
		`SELECT id, username, display_name, email, role, password_hash, disabled_at
		   FROM users WHERE username=$1`, NormalizeUsername(username))
	err := row.Scan(&id, &uname, &display, &email, &role, &hash, &disabled)
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
	return &models.User{
		ID: id, Username: uname, DisplayName: display,
		Email: email, Role: role,
	}, nil
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
func (s *Store) SetPassword(id int64, password string, keepTokenHash []byte) error {
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.Exec(`UPDATE users SET password_hash=$1, updated_at=now() WHERE id=$2`, hash, id)
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
