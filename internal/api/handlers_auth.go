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
	// Username carries the login identifier: an email address for accounts
	// created since email became the identity, a username for older ones. The
	// field keeps its name so existing scripts keep working.
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
		writeError(w, http.StatusBadRequest, "Email and password are required")
		return
	}

	u, err := a.store.Authenticate(in.Username, in.Password)
	if err != nil {
		// Both "no such user" and "wrong password" answer identically, so the
		// endpoint cannot be used to enumerate accounts.
		if errors.Is(err, store.ErrPasswordExpired) {
			_ = a.store.Audit(store.Actor{Username: store.NormalizeEmail(in.Username)},
				store.ActionLoginFailed, "user", nil,
				map[string]any{"remote": clientIP(r), "reason": "expired one-time password"})
			writeError(w, http.StatusUnauthorized,
				"That one-time password has expired. Request a new one.")
			return
		}
		if errors.Is(err, store.ErrBadCredentials) || errors.Is(err, store.ErrUserDisabled) {
			_ = a.store.Audit(store.Actor{Username: store.NormalizeEmail(in.Username)},
				store.ActionLoginFailed, "user", nil, map[string]any{"remote": clientIP(r)})
			writeError(w, http.StatusUnauthorized, "Invalid email or password")
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

type forgotInput struct {
	Email string `json:"email"`
}

// forgotPassword mails a one-time password to the address on the account.
//
// The response is deliberately identical whether or not the address is known:
// this endpoint is public, so anything that distinguished the two would turn it
// into a way to test which addresses have accounts. The same holds for the
// cooldown — a suppressed repeat looks exactly like a sent one.
func (a *API) forgotPassword(w http.ResponseWriter, r *http.Request) {
	if !a.cfg.AuthEnabled {
		writeError(w, http.StatusBadRequest, "Authentication is disabled on this deployment")
		return
	}
	var in forgotInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	email := store.NormalizeEmail(in.Email)
	if email == "" || !strings.Contains(email, "@") {
		writeError(w, http.StatusBadRequest, "Enter the email address for your account")
		return
	}
	// Not being able to send is a fact about the deployment, not about the
	// address, so saying so plainly leaks nothing and saves a support ticket.
	if a.dispatcher.Email == nil {
		writeError(w, http.StatusServiceUnavailable,
			"Password reset by email is not set up on this deployment. Ask an administrator to reset it for you.")
		return
	}

	// Everything past here is best-effort and silent; the caller always gets
	// the same answer.
	a.issueReset(email, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// issueReset does the work behind forgotPassword. Failures are logged rather
// than returned — the response must not vary.
func (a *API) issueReset(email, remote string) {
	u, err := a.store.GetUserByEmail(email)
	if err != nil {
		if !errors.Is(err, store.ErrUserNotFound) {
			a.log.Error("forgot password lookup", "error", err)
		}
		return
	}
	if u.Disabled {
		a.log.Warn("password reset requested for a disabled account", "user", u.Username)
		return
	}

	otp, err := auth.NewOneTimePassword()
	if err != nil {
		a.log.Error("generate one-time password", "error", err)
		return
	}
	issued, err := a.store.IssueOneTimePassword(u.ID, otp, a.cfg.PasswordResetTTL, a.cfg.PasswordResetCooldown)
	if err != nil {
		a.log.Error("issue one-time password", "user", u.Username, "error", err)
		return
	}
	if !issued {
		a.log.Info("password reset suppressed by cooldown", "user", u.Username)
		return
	}

	if err := a.dispatcher.Email.SendOneTimePassword(u.Email, otp, a.cfg.BaseURL, a.cfg.PasswordResetTTL); err != nil {
		// The password is already replaced at this point, so a send failure
		// locks the account until an admin resets it. Log it loudly.
		a.log.Error("send one-time password", "user", u.Username, "error", err)
		return
	}
	if err := a.store.Audit(store.Actor{ID: u.ID, Username: u.Username},
		store.ActionPasswordReset, "user", &u.ID,
		map[string]any{"remote": remote, "self_service": true}); err != nil {
		a.log.Warn("audit password reset", "error", err)
	}
	a.log.Info("one-time password sent", "user", u.Username)
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
	if err := a.store.VerifyCurrentPassword(actor.ID, in.CurrentPassword); err != nil {
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
	// mustChange=false: the holder picked this one themselves, which is exactly
	// what lifts a forced change.
	if err := a.store.SetPassword(actor.ID, in.NewPassword, keep, false); err != nil {
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
