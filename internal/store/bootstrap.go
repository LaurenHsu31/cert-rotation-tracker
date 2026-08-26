package store

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"certtracker/internal/models"
)

// BootstrapResult describes what the first-run setup did.
type BootstrapResult struct {
	Created           bool
	User              *models.User
	GeneratedPassword string // non-empty only when the tracker invented one
	AdoptedOrphans    int64
}

// Bootstrap makes sure an administrator exists. It runs on every startup but
// only acts when the users table is empty, so restarting never resets an
// existing deployment's accounts.
//
// Certificates created before ownership existed are adopted by that admin —
// otherwise they would have no owner and nobody but an admin could ever edit
// them again.
func (s *Store) Bootstrap(username, password string) (*BootstrapResult, error) {
	n, err := s.CountUsers()
	if err != nil {
		return nil, err
	}

	res := &BootstrapResult{}
	if n == 0 {
		if username == "" {
			username = "admin"
		}
		if password == "" {
			password, err = generatePassword()
			if err != nil {
				return nil, err
			}
			res.GeneratedPassword = password
		}
		u, err := s.CreateUser(username, "Administrator", "", password, models.RoleAdmin)
		if err != nil {
			return nil, fmt.Errorf("create bootstrap admin: %w", err)
		}
		res.Created = true
		res.User = u
	} else {
		u, err := s.firstActiveAdmin()
		if err != nil {
			return nil, err
		}
		res.User = u
	}

	if res.User != nil {
		adopted, err := s.AdoptOrphans(res.User.ID)
		if err != nil {
			return nil, err
		}
		res.AdoptedOrphans = adopted
	}
	return res, nil
}

func (s *Store) firstActiveAdmin() (*models.User, error) {
	u, err := scanUser(s.db.QueryRow(
		`SELECT ` + userColumns + ` FROM users
		  WHERE role = 'admin' AND disabled_at IS NULL
		  ORDER BY id ASC LIMIT 1`))
	if err != nil {
		return nil, err
	}
	return u, nil
}

func generatePassword() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
