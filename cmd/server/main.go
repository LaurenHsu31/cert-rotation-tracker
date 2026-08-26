package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	// Embed the timezone database so TIMEZONE (IANA names) resolves even on
	// minimal base images (distroless/scratch) that ship no tzdata.
	_ "time/tzdata"

	"certtracker/internal/api"
	"certtracker/internal/auth"
	"certtracker/internal/config"
	"certtracker/internal/notify"
	"certtracker/internal/scheduler"
	"certtracker/internal/store"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load()
	if err != nil {
		log.Error("config", "error", err)
		os.Exit(1)
	}
	log.Info("starting cert-rotation-tracker",
		"app_env", cfg.AppEnv, "timezone", cfg.Timezone, "email_enabled", cfg.EmailEnabled())

	st, err := store.Open(cfg.DatabaseURL)
	if err != nil {
		log.Error("database", "error", err)
		os.Exit(1)
	}
	defer st.Close()

	boot, err := st.Bootstrap(cfg.BootstrapAdminUser, cfg.BootstrapAdminPassword)
	if err != nil {
		log.Error("bootstrap", "error", err)
		os.Exit(1)
	}
	if boot.Created {
		log.Warn("created the first administrator account", "username", boot.User.Username)
		if boot.GeneratedPassword != "" {
			// Printed once, to stdout only. Set BOOTSTRAP_ADMIN_PASSWORD to
			// choose the password yourself and keep it out of the logs.
			fmt.Printf("\n=== cert-rotation-tracker first run ===\n"+
				"  username: %s\n  password: %s\n"+
				"  Sign in and change this password immediately.\n\n",
				boot.User.Username, boot.GeneratedPassword)
		}
	}
	if boot.AdoptedOrphans > 0 {
		log.Info("assigned ownerless certificates to the bootstrap admin",
			"count", boot.AdoptedOrphans, "owner", boot.User.Username)
	}
	if !cfg.AuthEnabled {
		log.Warn("AUTH_ENABLED=false — every request runs as the bootstrap admin. Never do this outside local development.",
			"acting_as", boot.User.Username)
	}

	var emailClient *notify.EmailClient
	if cfg.EmailEnabled() {
		emailClient = notify.NewEmailClient(notify.EmailConfig{
			Host:               cfg.SMTPHost,
			Port:               cfg.SMTPPort,
			Username:           cfg.SMTPUsername,
			Password:           cfg.SMTPPassword,
			From:               cfg.SMTPFrom,
			UseTLS:             cfg.SMTPUseTLS,
			InsecureSkipVerify: cfg.SMTPInsecureSkipVerify,
		})
	}
	dispatcher := notify.NewDispatcher(emailClient)
	sch := scheduler.New(cfg, st, dispatcher, log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if cfg.SchedulerEnabled {
		go sch.Start(ctx)
	} else {
		log.Info("scheduler disabled")
	}

	// Expired sessions are dead weight; sweep them alongside the daily scan.
	go purgeSessions(ctx, st, log)

	a := api.New(cfg, st, dispatcher, sch, log)
	a.SetDevIdentity(&auth.Identity{
		UserID:   boot.User.ID,
		Username: boot.User.Username,
		Role:     boot.User.Role,
	})
	handler := a.Handler()
	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Info("http server listening", "addr", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server", "error", err)
			stop()
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("shutdown", "error", err)
	}
}

// purgeSessions deletes rows whose expiry has passed, hourly.
func purgeSessions(ctx context.Context, st *store.Store, log *slog.Logger) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if n, err := st.PurgeExpiredSessions(); err != nil {
				log.Warn("purge sessions", "error", err)
			} else if n > 0 {
				log.Info("purged expired sessions", "count", n)
			}
		}
	}
}
