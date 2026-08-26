package store

import (
	"database/sql"
	"errors"
	"time"

	"certtracker/internal/auth"
	"certtracker/internal/models"
)

var ErrSessionInvalid = errors.New("session invalid or expired")

// CreateSession issues a session for a user and returns the raw token, which
// is the only time it exists outside the client's cookie.
func (s *Store) CreateSession(userID int64, ttl time.Duration) (string, time.Time, error) {
	token, digest, err := auth.NewToken()
	if err != nil {
		return "", time.Time{}, err
	}
	expires := time.Now().Add(ttl)
	_, err = s.db.Exec(
		`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1,$2,$3)`,
		digest, userID, expires)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

// LookupSession resolves a raw session token to its (active) user. Disabled
// accounts are rejected here too, so a live cookie stops working the moment
// an admin disables the account.
func (s *Store) LookupSession(token string) (*models.User, error) {
	if token == "" {
		return nil, ErrSessionInvalid
	}
	var (
		u        models.User
		disabled sql.NullTime
	)
	err := s.db.QueryRow(
		`SELECT u.id, u.username, u.display_name, u.email, u.role, u.disabled_at
		   FROM sessions s JOIN users u ON u.id = s.user_id
		  WHERE s.token_hash = $1 AND s.expires_at > now()`,
		auth.HashToken(token),
	).Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.Role, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSessionInvalid
	}
	if err != nil {
		return nil, err
	}
	if disabled.Valid {
		return nil, ErrUserDisabled
	}
	return &u, nil
}

// TouchSession slides the expiry forward so active users are not logged out
// mid-session.
func (s *Store) TouchSession(token string, ttl time.Duration) error {
	_, err := s.db.Exec(
		`UPDATE sessions SET expires_at = $1 WHERE token_hash = $2`,
		time.Now().Add(ttl), auth.HashToken(token))
	return err
}

func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token_hash = $1`, auth.HashToken(token))
	return err
}

// PurgeExpiredSessions drops rows that can no longer authenticate anyone.
func (s *Store) PurgeExpiredSessions() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}
