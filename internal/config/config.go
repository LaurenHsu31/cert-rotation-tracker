package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"certtracker/internal/reminder"
)

// Config holds all runtime configuration. Everything comes from the
// environment so the same binary/image runs unchanged across dev/stg/prd
// and on-prem vs cloud — only the injected values differ.
type Config struct {
	AppEnv   string // dev | stg | prd — the tracker's own deployment env (display/logging only)
	HTTPAddr string

	DatabaseURL string

	// Scheduler
	SchedulerEnabled bool
	SchedulerRunAt   string // "HH:MM" local-to-Timezone, daily reminder scan
	Timezone         string // IANA name, e.g. "Asia/Taipei"; falls back to UTC
	Location         *time.Location

	// Severity cutoffs (days remaining). Independent of per-cert reminder
	// thresholds: these drive colour/level in the UI and notification escalation.
	SeverityNoticeDays   int
	SeverityWarningDays  int
	SeverityUrgentDays   int
	SeverityCriticalDays int

	// Default reminder thresholds offered in the UI / applied when none given.
	// These are MILESTONES: each fires once as it is crossed.
	ReminderDefaultDays []int

	// Escalating repeat cadence layered on top of the milestones: the closer
	// expiry gets, the more often the same alert repeats.
	ReminderEscalation reminder.Rules

	// --- authentication / authorization ---
	AuthEnabled   bool          // false only for local development
	SessionTTL    time.Duration // how long a login lasts
	CookieSecure  bool          // set the Secure flag on the session cookie
	TrustedOrigin string        // expected Origin for state-changing requests (CSRF)

	// First-run bootstrap. Applied only when the users table is empty.
	BootstrapAdminUser     string
	BootstrapAdminPassword string

	// Renewal evidence upload ceiling.
	MaxUploadBytes int64

	// SMTP (email channel). If SMTPHost is empty, email sending is disabled.
	SMTPHost               string
	SMTPPort               int
	SMTPUsername           string
	SMTPPassword           string
	SMTPFrom               string
	SMTPUseTLS             bool // implicit TLS (e.g. port 465). STARTTLS is auto-negotiated otherwise.
	SMTPInsecureSkipVerify bool // skip TLS cert verification (internal relays with self-signed certs)

	BaseURL string // optional, used to build links inside notifications
}

func Load() (*Config, error) {
	c := &Config{
		AppEnv:   getEnv("APP_ENV", "dev"),
		HTTPAddr: getEnv("HTTP_ADDR", ":8080"),

		DatabaseURL: getEnv("DATABASE_URL", ""),

		SchedulerEnabled: getBool("SCHEDULER_ENABLED", true),
		SchedulerRunAt:   getEnv("SCHEDULER_RUN_AT", "09:00"),
		Timezone:         getEnv("TIMEZONE", "UTC"),

		SeverityNoticeDays:   getInt("SEVERITY_NOTICE_DAYS", 90),
		SeverityWarningDays:  getInt("SEVERITY_WARNING_DAYS", 60),
		SeverityUrgentDays:   getInt("SEVERITY_URGENT_DAYS", 30),
		SeverityCriticalDays: getInt("SEVERITY_CRITICAL_DAYS", 7),

		ReminderDefaultDays: getIntSlice("REMINDER_DEFAULT_DAYS", []int{30, 45, 60, 75, 90}),

		AuthEnabled: getBool("AUTH_ENABLED", true),
		SessionTTL:  time.Duration(getInt("SESSION_TTL_HOURS", 12)) * time.Hour,

		BootstrapAdminUser:     getEnv("BOOTSTRAP_ADMIN_USERNAME", "admin"),
		BootstrapAdminPassword: getEnv("BOOTSTRAP_ADMIN_PASSWORD", ""),

		MaxUploadBytes: int64(getInt("MAX_UPLOAD_MB", 5)) * 1024 * 1024,

		SMTPHost:               getEnv("SMTP_HOST", ""),
		SMTPPort:               getInt("SMTP_PORT", 587),
		SMTPUsername:           getEnv("SMTP_USERNAME", ""),
		SMTPPassword:           getEnv("SMTP_PASSWORD", ""),
		SMTPFrom:               getEnv("SMTP_FROM", ""),
		SMTPUseTLS:             getBool("SMTP_USE_TLS", false),
		SMTPInsecureSkipVerify: getBool("SMTP_INSECURE_SKIP_VERIFY", false),

		BaseURL: getEnv("BASE_URL", ""),
	}

	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}

	loc, err := time.LoadLocation(c.Timezone)
	if err != nil {
		loc = time.UTC
		c.Timezone = "UTC"
	}
	c.Location = loc

	esc, err := reminder.Parse(getEnv("REMINDER_ESCALATION", ""), reminder.DefaultRules)
	if err != nil {
		return nil, fmt.Errorf("REMINDER_ESCALATION: %w", err)
	}
	c.ReminderEscalation = esc

	// The session cookie should carry Secure whenever the tracker is actually
	// reachable over TLS. Derived from BASE_URL so the common case needs no
	// extra knob, with an explicit override for reverse-proxy setups where the
	// proxy terminates TLS but BASE_URL was left unset.
	httpsBase := strings.HasPrefix(strings.ToLower(c.BaseURL), "https://")
	c.CookieSecure = getBool("COOKIE_SECURE", httpsBase)

	// Origin allowed to make state-changing requests. Defaults to BASE_URL's
	// origin; empty means "same-origin only", enforced by comparing against
	// the request Host.
	c.TrustedOrigin = strings.TrimSpace(getEnv("TRUSTED_ORIGIN", ""))
	if c.TrustedOrigin == "" && c.BaseURL != "" {
		if u, err := url.Parse(c.BaseURL); err == nil && u.Host != "" {
			c.TrustedOrigin = u.Scheme + "://" + u.Host
		}
	}

	if c.AuthEnabled && c.BootstrapAdminPassword != "" {
		if len([]rune(c.BootstrapAdminPassword)) < 10 {
			return nil, fmt.Errorf("BOOTSTRAP_ADMIN_PASSWORD must be at least 10 characters")
		}
	}

	return c, nil
}

// DefaultReminderDays exposes the configured milestone defaults.
func (c *Config) DefaultReminderDays() []int { return c.ReminderDefaultDays }

// EmailEnabled reports whether the SMTP channel is usable.
func (c *Config) EmailEnabled() bool { return c.SMTPHost != "" && c.SMTPFrom != "" }

func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func getInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return def
}

func getBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			return b
		}
	}
	return def
}

func getIntSlice(key string, def []int) []int {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	var out []int
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if n, err := strconv.Atoi(part); err == nil {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return def
	}
	return out
}
