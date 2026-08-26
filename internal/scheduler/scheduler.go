package scheduler

import (
	"context"
	"log/slog"
	"time"

	"certtracker/internal/config"
	"certtracker/internal/models"
	"certtracker/internal/notify"
	"certtracker/internal/reminder"
	"certtracker/internal/severity"
	"certtracker/internal/store"
)

// expiredSentinel is the threshold_day recorded once an "expired" alert fires.
const expiredSentinel = -1

type Scheduler struct {
	cfg        *config.Config
	store      *store.Store
	dispatcher *notify.Dispatcher
	cuts       severity.Cutoffs
	log        *slog.Logger
}

func New(cfg *config.Config, st *store.Store, d *notify.Dispatcher, log *slog.Logger) *Scheduler {
	return &Scheduler{
		cfg:        cfg,
		store:      st,
		dispatcher: d,
		cuts: severity.Cutoffs{
			Notice:   cfg.SeverityNoticeDays,
			Warning:  cfg.SeverityWarningDays,
			Urgent:   cfg.SeverityUrgentDays,
			Critical: cfg.SeverityCriticalDays,
		},
		log: log,
	}
}

// Start blocks and runs the daily scan at the configured time until ctx is done.
func (s *Scheduler) Start(ctx context.Context) {
	s.log.Info("scheduler started", "run_at", s.cfg.SchedulerRunAt, "timezone", s.cfg.Timezone)
	for {
		next := s.nextRun(time.Now())
		wait := time.Until(next)
		s.log.Info("next reminder scan scheduled", "at", next.Format(time.RFC3339))
		select {
		case <-ctx.Done():
			s.log.Info("scheduler stopped")
			return
		case <-time.After(wait):
			if _, err := s.RunOnce(ctx); err != nil {
				s.log.Error("reminder scan failed", "error", err)
			}
		}
	}
}

func (s *Scheduler) nextRun(now time.Time) time.Time {
	n := now.In(s.cfg.Location)
	hh, mm := 9, 0
	if t, err := time.Parse("15:04", s.cfg.SchedulerRunAt); err == nil {
		hh, mm = t.Hour(), t.Minute()
	}
	run := time.Date(n.Year(), n.Month(), n.Day(), hh, mm, 0, 0, s.cfg.Location)
	if !run.After(n) {
		run = run.Add(24 * time.Hour)
	}
	return run
}

// RunOnce performs a single reminder scan across all certificates. It is used
// by the daily loop and by the manual "run check now" endpoint. Returns the
// number of alerts sent.
func (s *Scheduler) RunOnce(ctx context.Context) (int, error) {
	certs, err := s.store.ListLiveCertificates()
	if err != nil {
		return 0, err
	}
	now := time.Now()
	today := now.In(s.cfg.Location)
	emailEnabled := s.dispatcher.Email != nil
	sent := 0

	for _, c := range certs {
		select {
		case <-ctx.Done():
			return sent, ctx.Err()
		default:
		}

		c.Enrich(now, s.cfg.Location, s.cuts)

		alreadySent, err := s.store.SentThresholds(c.ID)
		if err != nil {
			s.log.Error("read sent thresholds", "cert_id", c.ID, "error", err)
			continue
		}

		d := s.evaluate(c, alreadySent, today)
		if !d.send {
			continue // nothing new to send
		}

		if !deliverable(c, emailEnabled) {
			s.log.Warn("certificate due for alert but has no deliverable channel",
				"cert_id", c.ID, "name", c.Name)
			continue // don't mark; re-evaluate once a channel is added
		}

		alert := notify.Alert{
			Kind:          d.kind,
			CertName:      c.Name,
			Environment:   c.Environment,
			DaysRemaining: c.DaysRemaining,
			ExpiryDate:    models.DateOnly(c.ExpiryDate),
			Severity:      c.Severity,
			BaseURL:       s.cfg.BaseURL,
			Owner:         c.OwnerUsername,
			Cadence:       reminder.Describe(d.interval),
		}

		if errs := s.dispatcher.Dispatch(alert, c.TeamsWebhook, c.NotifyEmails); len(errs) > 0 {
			for _, e := range errs {
				s.log.Error("dispatch failed", "cert_id", c.ID, "name", c.Name, "error", e)
			}
			continue // don't mark; retry next scan
		}

		if err := s.store.RecordNotification(c.ID, d.thresholds, today); err != nil {
			s.log.Error("record notification", "cert_id", c.ID, "error", err)
			continue
		}
		s.log.Info("alert sent", "cert_id", c.ID, "name", c.Name,
			"kind", d.kind, "trigger", d.trigger, "repeat_every_days", d.interval,
			"days_remaining", c.DaysRemaining, "severity", c.Severity)
		sent++
	}

	s.log.Info("reminder scan complete", "certificates", len(certs), "alerts_sent", sent)
	return sent, nil
}

// decision is the outcome of evaluating one certificate on one scan day.
type decision struct {
	send       bool
	kind       string // "reminder" | "expired"
	trigger    string // "milestone" | "cadence" — for the log, not the message
	interval   int    // active repeat interval in days, 0 when milestone-only
	thresholds []int  // milestone threshold_day values this alert consumes
}

// evaluate decides whether an alert is due for a certificate today.
//
// Two independent layers can trigger it:
//
//   - MILESTONES — the per-certificate reminder_days. Each fires exactly once,
//     the first scan after days-remaining drops to or below it.
//   - CADENCE — the configured escalation ladder. Once a certificate is inside
//     a rung, the alert repeats on that rung's interval and keeps repeating,
//     tightening as expiry approaches and continuing after expiry.
//
// Whichever fires, at most ONE alert goes out per certificate per scan — the
// point is to escalate urgency, not to multiply mail.
func (s *Scheduler) evaluate(c *models.Certificate, sent map[int]bool, today time.Time) decision {
	interval := s.cfg.ReminderEscalation.IntervalFor(c.DaysRemaining)

	// --- milestones ---
	var due []int
	if c.DaysRemaining < 0 {
		if !sent[expiredSentinel] {
			// Mark the expired sentinel plus every reminder threshold (all crossed).
			due = append([]int{expiredSentinel}, c.ReminderDays...)
		}
	} else {
		for _, t := range c.ReminderDays {
			if c.DaysRemaining <= t && !sent[t] {
				due = append(due, t)
			}
		}
	}

	kind := "reminder"
	if c.DaysRemaining < 0 {
		kind = "expired"
	}

	if len(due) > 0 {
		// One alert reflecting current state; collapse any backfilled thresholds.
		return decision{send: true, kind: kind, trigger: "milestone", interval: interval, thresholds: due}
	}

	// --- cadence ---
	if interval > 0 && cadenceDue(c.LastNotifiedOn, today, interval) {
		return decision{send: true, kind: kind, trigger: "cadence", interval: interval}
	}
	return decision{}
}

// cadenceDue reports whether enough calendar days have passed since the last
// alert. A certificate that has never been alerted is due immediately, which
// is what makes a cert added late (already inside an escalation rung) get its
// first nag on the very next scan.
func cadenceDue(last *time.Time, today time.Time, interval int) bool {
	if last == nil {
		return true
	}
	// Compare the calendar fields directly. last_notified_on is a DATE and
	// today is already in the tracker's timezone, so converting either into a
	// common location could shift it across midnight and skip or repeat a day.
	l := time.Date(last.Year(), last.Month(), last.Day(), 0, 0, 0, 0, time.UTC)
	t := time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, time.UTC)
	return int(t.Sub(l).Hours()/24) >= interval
}

func deliverable(c *models.Certificate, emailEnabled bool) bool {
	if c.TeamsWebhook != "" {
		return true
	}
	return emailEnabled && len(c.NotifyEmails) > 0
}
