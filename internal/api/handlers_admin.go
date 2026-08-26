package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"certtracker/internal/auth"
	"certtracker/internal/models"
	"certtracker/internal/store"
)

// listUsers is readable by every signed-in user so the UI can offer an owner
// picker and show who reviewed what. Email addresses are held back from
// non-admins — the transfer dropdown only needs a username.
func (a *API) listUsers(w http.ResponseWriter, r *http.Request) {
	_, isAdmin := a.actor(r)
	users, err := a.store.ListUsers()
	if err != nil {
		a.serverError(w, "list users", err)
		return
	}
	if !isAdmin {
		for _, u := range users {
			u.Email = ""
		}
	}
	writeJSON(w, http.StatusOK, users)
}

type userInput struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	Role        string `json:"role"`
	Disabled    bool   `json:"disabled"`
}

func decodeUser(w http.ResponseWriter, r *http.Request) (*userInput, bool) {
	var in userInput
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
		return nil, false
	}
	return &in, true
}

func (a *API) createUser(w http.ResponseWriter, r *http.Request) {
	actor, _ := a.actor(r)
	in, ok := decodeUser(w, r)
	if !ok {
		return
	}

	username := store.NormalizeUsername(in.Username)
	if !validUsername(username) {
		writeError(w, http.StatusBadRequest,
			"Username must be 3-32 characters: letters, digits, dot, dash or underscore")
		return
	}
	if in.Role == "" {
		in.Role = models.RoleUser
	}
	if !models.ValidRole(in.Role) {
		writeError(w, http.StatusBadRequest, "Role must be admin or user")
		return
	}
	if err := auth.ValidatePasswordPolicy(in.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	u, err := a.store.CreateUser(username, in.DisplayName, in.Email, in.Password, in.Role)
	if err != nil {
		a.storeError(w, "create user", err)
		return
	}
	if err := a.store.Audit(actor, store.ActionUserCreate, "user", &u.ID,
		map[string]any{"username": u.Username, "role": u.Role}); err != nil {
		a.log.Warn("audit create user", "error", err)
	}
	writeJSON(w, http.StatusCreated, u)
}

func (a *API) updateUser(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	actor, _ := a.actor(r)
	in, ok2 := decodeUser(w, r)
	if !ok2 {
		return
	}
	if !models.ValidRole(in.Role) {
		writeError(w, http.StatusBadRequest, "Role must be admin or user")
		return
	}
	// Disabling yourself would end the very session making the request.
	if id == actor.ID && in.Disabled {
		writeError(w, http.StatusBadRequest, "You cannot disable your own account")
		return
	}

	u, err := a.store.UpdateUser(id, in.DisplayName, in.Email, in.Role, in.Disabled)
	if err != nil {
		a.storeError(w, "update user", err)
		return
	}
	if err := a.store.Audit(actor, store.ActionUserUpdate, "user", &u.ID, map[string]any{
		"username": u.Username, "role": u.Role, "disabled": u.Disabled,
	}); err != nil {
		a.log.Warn("audit update user", "error", err)
	}
	writeJSON(w, http.StatusOK, u)
}

type resetInput struct {
	NewPassword string `json:"new_password"`
}

// resetUserPassword is the admin recovery path for a forgotten password. Every
// session belonging to that account is dropped, so a reset always evicts
// whoever was signed in.
func (a *API) resetUserPassword(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	actor, _ := a.actor(r)
	var in resetInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if err := auth.ValidatePasswordPolicy(in.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.store.SetPassword(id, in.NewPassword, nil); err != nil {
		a.storeError(w, "reset password", err)
		return
	}
	if err := a.store.Audit(actor, store.ActionUserPassword, "user", &id,
		map[string]any{"self_service": false}); err != nil {
		a.log.Warn("audit reset password", "error", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// listAudit is the tracker-wide history. Admin-only, because the detail
// payloads reference every certificate regardless of owner.
func (a *API) listAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.AuditFilter{
		EntityType: q.Get("entity_type"),
		Action:     q.Get("action"),
	}
	if cat := q.Get("category"); cat != "" {
		if !store.IsAuditCategory(cat) {
			writeError(w, http.StatusBadRequest, "Unknown audit category")
			return
		}
		f.Actions = store.CategoryActions(cat)
	}
	if v := q.Get("entity_id"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid entity_id")
			return
		}
		f.EntityID = &id
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			writeError(w, http.StatusBadRequest, "Invalid limit")
			return
		}
		f.Limit = n
	}

	entries, err := a.store.ListAudit(f)
	if err != nil {
		a.serverError(w, "list audit", err)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

func validUsername(u string) bool {
	if len(u) < 3 || len(u) > 32 {
		return false
	}
	for _, r := range u {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_':
		default:
			return false
		}
	}
	return !strings.HasPrefix(u, ".") && !strings.HasSuffix(u, ".")
}
