package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
)

// CookieName is the session cookie. Prefixed "__Host-" would be stricter but
// breaks plain-HTTP on-prem deployments, so the Secure attribute is set from
// config instead.
const CookieName = "ct_session"

// NewToken returns a 256-bit random session token (URL-safe) and the SHA-256
// digest that gets stored. The raw token never touches the database.
func NewToken() (token string, digest []byte, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", nil, err
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, HashToken(token), nil
}

// HashToken digests a session token for storage/lookup.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// TokenFromRequest pulls the session token out of the cookie, falling back to
// a bearer header so scripts and health probes can authenticate too.
func TokenFromRequest(r *http.Request) string {
	if c, err := r.Cookie(CookieName); err == nil && c.Value != "" {
		return c.Value
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	return ""
}

// SetCookie writes the session cookie. SameSite=Lax plus the Origin check in
// the API middleware is the CSRF defence.
func SetCookie(w http.ResponseWriter, token string, maxAgeSeconds int, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   maxAgeSeconds,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearCookie expires the session cookie.
func ClearCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ---------- request-scoped identity ----------

type ctxKey struct{}

// Identity is the authenticated caller, attached to the request context by the
// API middleware. Every ownership decision downstream reads from here.
type Identity struct {
	UserID   int64
	Username string
	Role     string
}

func (i *Identity) IsAdmin() bool { return i != nil && i.Role == "admin" }

// WithIdentity returns a context carrying the caller's identity.
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext returns the caller's identity, or nil when unauthenticated.
func FromContext(ctx context.Context) *Identity {
	id, _ := ctx.Value(ctxKey{}).(*Identity)
	return id
}
