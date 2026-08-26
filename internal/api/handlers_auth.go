package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"certtracker/internal/auth"
	"certtracker/internal/models"
	"certtracker/internal/store"
)

type loginInput struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// login exchanges credentials for a session cookie.
func (a *API) login(w http.ResponseWriter, r *http.Request) {
	if !a.cfg.AuthEnabled {
		writeError(w, http.StatusBadRequest, "Authentication is disabled on this deployment")
		return
	}
	var in loginInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if in.Username == "" || in.Password == "" {
		writeError(w, http.StatusBadRequest, "Username and password are required")
		return
	}

	u, err := a.store.Authenticate(in.Username, in.Password)
	if err != nil {
		// Both "no such user" and "wrong password" answer identically, so the
		// endpoint cannot be used to enumerate accounts.
		if errors.Is(err, store.ErrBadCredentials) || errors.Is(err, store.ErrUserDisabled) {
			_ = a.store.Audit(store.Actor{Username: store.NormalizeUsername(in.Username)},
				store.ActionLoginFailed, "user", nil, map[string]any{"remote": clientIP(r)})
			writeError(w, http.StatusUnauthorized, "Invalid username or password")
			return
		}
		a.serverError(w, "authenticate", err)
		return
	}

	token, _, err := a.store.CreateSession(u.ID, a.cfg.SessionTTL)
	if err != nil {
		a.serverError(w, "create session", err)
		return
	}
	auth.SetCookie(w, token, int(a.cfg.SessionTTL.Seconds()), a.cfg.CookieSecure)

	if err := a.store.Audit(store.Actor{ID: u.ID, Username: u.Username},
		store.ActionLogin, "user", &u.ID, map[string]any{"remote": clientIP(r)}); err != nil {
		a.log.Warn("audit login", "error", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": u})
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	actor, _ := a.actor(r)
	if token := auth.TokenFromRequest(r); token != "" {
		if err := a.store.DeleteSession(token); err != nil {
			a.log.Warn("delete session", "error", err)
		}
	}
	auth.ClearCookie(w, a.cfg.CookieSecure)
	if err := a.store.Audit(actor, store.ActionLogout, "user", &actor.ID, nil); err != nil {
		a.log.Warn("audit logout", "error", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// session reports who (if anyone) the caller is. Public, so the SPA can decide
// between rendering the login form and the dashboard without a failed request.
func (a *API) session(w http.ResponseWriter, r *http.Request) {
	if !a.cfg.AuthEnabled {
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": true,
			"auth_enabled":  false,
			"user": &models.User{
				ID:       a.devIdentity.UserID,
				Username: a.devIdentity.Username,
				Role:     a.devIdentity.Role,
			},
		})
		return
	}
	u, err := a.store.LookupSession(auth.TokenFromRequest(r))
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false, "auth_enabled": true})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true, "auth_enabled": true, "user": u,
	})
}

type passwordInput struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// changePassword updates the caller's own password. The current password is
// required so a hijacked, unattended session cannot lock the owner out.
func (a *API) changePassword(w http.ResponseWriter, r *http.Request) {
	actor, _ := a.actor(r)
	var in passwordInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if _, err := a.store.Authenticate(actor.Username, in.CurrentPassword); err != nil {
		writeError(w, http.StatusUnauthorized, "Current password is incorrect")
		return
	}
	if err := auth.ValidatePasswordPolicy(in.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Keep this session alive, drop every other one — a password change should
	// evict anyone else who was signed in as this account.
	var keep []byte
	if token := auth.TokenFromRequest(r); token != "" {
		keep = auth.HashToken(token)
	}
	if err := a.store.SetPassword(actor.ID, in.NewPassword, keep); err != nil {
		a.storeError(w, "set password", err)
		return
	}
	if err := a.store.Audit(actor, store.ActionUserPassword, "user", &actor.ID,
		map[string]any{"self_service": true}); err != nil {
		a.log.Warn("audit password change", "error", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func clientIP(r *http.Request) string {
	if f := r.Header.Get("X-Forwarded-For"); f != "" {
		if i := strings.Index(f, ","); i > 0 {
			return strings.TrimSpace(f[:i])
		}
		return strings.TrimSpace(f)
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}
