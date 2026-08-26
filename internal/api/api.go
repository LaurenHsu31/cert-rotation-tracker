package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"certtracker/internal/auth"
	"certtracker/internal/config"
	"certtracker/internal/models"
	"certtracker/internal/notify"
	"certtracker/internal/scheduler"
	"certtracker/internal/severity"
	"certtracker/internal/store"
	"certtracker/internal/web"
)

type API struct {
	cfg        *config.Config
	store      *store.Store
	dispatcher *notify.Dispatcher
	scheduler  *scheduler.Scheduler
	cuts       severity.Cutoffs
	log        *slog.Logger

	// devIdentity stands in for a session when AUTH_ENABLED=false. It points
	// at a real account so ownership still works while developing locally.
	devIdentity *auth.Identity
}

func New(cfg *config.Config, st *store.Store, d *notify.Dispatcher, sch *scheduler.Scheduler, log *slog.Logger) *API {
	return &API{
		cfg:        cfg,
		store:      st,
		dispatcher: d,
		scheduler:  sch,
		cuts: severity.Cutoffs{
			Notice:   cfg.SeverityNoticeDays,
			Warning:  cfg.SeverityWarningDays,
			Urgent:   cfg.SeverityUrgentDays,
			Critical: cfg.SeverityCriticalDays,
		},
		log: log,
	}
}

// SetDevIdentity wires the account used when authentication is disabled.
func (a *API) SetDevIdentity(id *auth.Identity) { a.devIdentity = id }

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()

	// --- public ---
	mux.HandleFunc("GET /api/health", a.health)
	mux.HandleFunc("POST /api/auth/login", a.login)
	mux.HandleFunc("GET /api/auth/session", a.session)

	// --- authenticated ---
	signed := a.authed
	mux.Handle("POST /api/auth/logout", signed(a.logout))
	mux.Handle("POST /api/auth/password", signed(a.changePassword))
	mux.Handle("GET /api/config", signed(a.getConfig))

	mux.Handle("GET /api/certificates", signed(a.listCertificates))
	mux.Handle("POST /api/certificates", signed(a.createCertificate))
	mux.Handle("GET /api/certificates/{id}", signed(a.getCertificate))
	mux.Handle("PUT /api/certificates/{id}", signed(a.updateCertificate))
	mux.Handle("DELETE /api/certificates/{id}", signed(a.deleteCertificate))
	mux.Handle("POST /api/certificates/{id}/test", signed(a.testCertificate))
	mux.Handle("PUT /api/certificates/{id}/owner", signed(a.transferOwner))
	mux.Handle("GET /api/certificates/{id}/audit", signed(a.certificateAudit))

	// Renewal (rotation) workflow.
	mux.Handle("GET /api/renewals", signed(a.listRenewals))
	mux.Handle("POST /api/certificates/{id}/renewals", signed(a.submitRenewal))
	mux.Handle("GET /api/renewals/{id}", signed(a.getRenewal))
	mux.Handle("GET /api/renewals/{id}/evidence", signed(a.renewalEvidence))
	mux.Handle("POST /api/renewals/{id}/approve", signed(a.approveRenewal))
	mux.Handle("POST /api/renewals/{id}/reject", signed(a.rejectRenewal))
	mux.Handle("POST /api/renewals/{id}/withdraw", signed(a.withdrawRenewal))

	mux.Handle("GET /api/users", signed(a.listUsers))

	// --- admin only ---
	admin := a.adminOnly
	mux.Handle("POST /api/users", admin(a.createUser))
	mux.Handle("PUT /api/users/{id}", admin(a.updateUser))
	mux.Handle("POST /api/users/{id}/password", admin(a.resetUserPassword))
	mux.Handle("GET /api/audit", admin(a.listAudit))
	mux.Handle("POST /api/certificates/{id}/restore", admin(a.restoreCertificate))
	mux.Handle("POST /api/tasks/run-check", admin(a.runCheck))

	// Frontend (embedded static assets).
	mux.Handle("/", web.Handler())

	return logRequests(a.log, a.checkOrigin(mux))
}

// ---------- middleware ----------

// authed resolves the session cookie into an Identity and rejects anonymous
// callers. Every non-public route goes through it, so no handler ever has to
// wonder whether r has an identity attached.
func (a *API) authed(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := a.identify(w, r)
		if !ok {
			return
		}
		h(w, r.WithContext(auth.WithIdentity(r.Context(), id)))
	})
}

func (a *API) adminOnly(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := a.identify(w, r)
		if !ok {
			return
		}
		if !id.IsAdmin() {
			writeError(w, http.StatusForbidden, "Administrator access is required for this action")
			return
		}
		h(w, r.WithContext(auth.WithIdentity(r.Context(), id)))
	})
}

func (a *API) identify(w http.ResponseWriter, r *http.Request) (*auth.Identity, bool) {
	if !a.cfg.AuthEnabled {
		if a.devIdentity == nil {
			writeError(w, http.StatusInternalServerError, "Auth is disabled but no local account is configured")
			return nil, false
		}
		return a.devIdentity, true
	}

	token := auth.TokenFromRequest(r)
	u, err := a.store.LookupSession(token)
	if err != nil {
		if errors.Is(err, store.ErrUserDisabled) {
			auth.ClearCookie(w, a.cfg.CookieSecure)
			writeError(w, http.StatusUnauthorized, "This account has been disabled")
			return nil, false
		}
		if !errors.Is(err, store.ErrSessionInvalid) {
			a.log.Error("session lookup", "error", err)
		}
		writeError(w, http.StatusUnauthorized, "Sign in to continue")
		return nil, false
	}

	// Slide the expiry so an active session does not die mid-task. Cheap
	// enough at this scale; a failure here is not worth failing the request.
	if err := a.store.TouchSession(token, a.cfg.SessionTTL); err != nil {
		a.log.Warn("touch session", "error", err)
	}
	return &auth.Identity{UserID: u.ID, Username: u.Username, Role: u.Role}, true
}

// checkOrigin is the CSRF defence for cookie-authenticated, state-changing
// requests. Combined with SameSite=Lax on the session cookie it means a page
// on another origin cannot make the browser act as the signed-in user.
// Bearer-token callers are exempt: a token is never attached automatically,
// so those requests cannot be forged this way.
func (a *API) checkOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/api/") ||
			strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			next.ServeHTTP(w, r)
			return
		}

		origin := r.Header.Get("Origin")
		if origin == "" {
			writeError(w, http.StatusForbidden, "Missing Origin header on a state-changing request")
			return
		}
		if !a.originAllowed(origin, r) {
			a.log.Warn("rejected cross-origin request", "origin", origin, "path", r.URL.Path)
			writeError(w, http.StatusForbidden, "Cross-origin request rejected")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) originAllowed(origin string, r *http.Request) bool {
	if a.cfg.TrustedOrigin != "" && strings.EqualFold(origin, a.cfg.TrustedOrigin) {
		return true
	}
	// Fall back to same-origin: compare the Origin's host with the Host the
	// request arrived on, which is what a browser sends for same-site fetches.
	host := origin
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	return strings.EqualFold(host, r.Host)
}

// ---------- shared helpers ----------

func (a *API) actor(r *http.Request) (store.Actor, bool) {
	id := auth.FromContext(r.Context())
	if id == nil {
		return store.Actor{}, false
	}
	return store.Actor{ID: id.UserID, Username: id.Username}, id.IsAdmin()
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "env": a.cfg.AppEnv})
}

func (a *API) getConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"app_env":               a.cfg.AppEnv,
		"environments":          []string{models.EnvDev, models.EnvStg, models.EnvPrd},
		"reminder_default_days": a.cfg.ReminderDefaultDays,
		"reminder_options":      []int{30, 45, 60, 75, 90},
		"reminder_escalation":   a.cfg.ReminderEscalation,
		"severity_cutoffs": map[string]int{
			"notice":   a.cfg.SeverityNoticeDays,
			"warning":  a.cfg.SeverityWarningDays,
			"urgent":   a.cfg.SeverityUrgentDays,
			"critical": a.cfg.SeverityCriticalDays,
		},
		"audit_categories": store.AuditCategories,
		"email_enabled":    a.cfg.EmailEnabled(),
		"auth_enabled":     a.cfg.AuthEnabled,
		"max_upload_bytes": a.cfg.MaxUploadBytes,
	})
}

func parseID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "Invalid id")
		return 0, false
	}
	return id, true
}

func (a *API) serverError(w http.ResponseWriter, op string, err error) {
	a.log.Error(op, "error", err)
	writeError(w, http.StatusInternalServerError, "Something went wrong. Check the server logs.")
}

// storeError maps the store's sentinel errors onto HTTP status codes so every
// handler reports permission and lifecycle failures the same way.
func (a *API) storeError(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "Certificate not found")
	case errors.Is(err, store.ErrForbidden):
		writeError(w, http.StatusForbidden,
			"Only the certificate's owner or an administrator can change it")
	case errors.Is(err, store.ErrCertLocked):
		writeError(w, http.StatusConflict,
			"This certificate has already been rotated or deleted")
	case errors.Is(err, store.ErrRenewalNotFound):
		writeError(w, http.StatusNotFound, "Renewal request not found")
	case errors.Is(err, store.ErrRenewalNotOpen):
		writeError(w, http.StatusConflict, "This renewal request has already been actioned")
	case errors.Is(err, store.ErrRenewalOpen):
		writeError(w, http.StatusConflict, store.ErrRenewalOpen.Error())
	case errors.Is(err, store.ErrSelfReview):
		writeError(w, http.StatusForbidden, store.ErrSelfReview.Error())
	case errors.Is(err, store.ErrNoEvidence):
		writeError(w, http.StatusBadRequest, "Attach the new certificate as proof")
	case errors.Is(err, store.ErrUserNotFound):
		writeError(w, http.StatusNotFound, "User not found")
	case errors.Is(err, store.ErrUserDisabled):
		writeError(w, http.StatusBadRequest, "That account is disabled")
	case errors.Is(err, store.ErrUserExists):
		writeError(w, http.StatusConflict, "That username is already taken")
	case errors.Is(err, store.ErrLastAdmin):
		writeError(w, http.StatusConflict,
			"There must always be at least one active administrator")
	default:
		a.serverError(w, op, err)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func logRequests(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			attrs := []any{
				"method", r.Method, "path", r.URL.Path,
				"status", sw.status, "duration", time.Since(start).String(),
			}
			if id := auth.FromContext(r.Context()); id != nil {
				attrs = append(attrs, "user", id.Username)
			}
			log.Info("request", attrs...)
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}
