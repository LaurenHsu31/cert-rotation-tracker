package scheduler

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"certtracker/internal/config"
	"certtracker/internal/models"
	"certtracker/internal/reminder"
)

func testScheduler() *Scheduler {
	return &Scheduler{
		cfg: &config.Config{
			Location:           time.UTC,
			ReminderEscalation: reminder.DefaultRules,
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func certAt(daysRemaining int, lastNotified *time.Time) *models.Certificate {
	return &models.Certificate{
		ID:             1,
		DaysRemaining:  daysRemaining,
		ReminderDays:   []int{30, 45, 60, 75, 90},
		LastNotifiedOn: lastNotified,
	}
}

func daysAgo(today time.Time, n int) *time.Time {
	t := today.AddDate(0, 0, -n)
	return &t
}

func TestMilestoneFiresOncePerThreshold(t *testing.T) {
	s := testScheduler()
	today := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)

	// 90 days out, nothing sent yet: the 90-day milestone is due.
	d := s.evaluate(certAt(90, nil), map[int]bool{}, today)
	if !d.send || d.trigger != "milestone" {
		t.Fatalf("expected a milestone alert, got %+v", d)
	}
	if len(d.thresholds) != 1 || d.thresholds[0] != 90 {
		t.Errorf("expected to consume threshold 90, got %v", d.thresholds)
	}

	// Same day next scan: already consumed, and 90 days is outside every
	// escalation rung, so nothing repeats.
	d = s.evaluate(certAt(90, daysAgo(today, 0)), map[int]bool{90: true}, today)
	if d.send {
		t.Errorf("90 days out should not repeat, got %+v", d)
	}
	d = s.evaluate(certAt(89, daysAgo(today, 30)), map[int]bool{90: true}, today)
	if d.send {
		t.Errorf("89 days out should stay quiet until the next milestone, got %+v", d)
	}
}

func TestCadenceRepeatsOnItsInterval(t *testing.T) {
	s := testScheduler()
	today := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	// Every milestone (including the expired sentinel) already burnt, so only
	// the cadence layer can fire.
	consumed := map[int]bool{expiredSentinel: true, 30: true, 45: true, 60: true, 75: true, 90: true}

	cases := []struct {
		name         string
		days         int
		sinceLast    int
		wantSend     bool
		wantInterval int
	}{
		{"44 days, 4 since last: too soon", 44, 4, false, 5},
		{"44 days, 5 since last: due", 44, 5, true, 5},
		{"29 days, 2 since last: too soon", 29, 2, false, 3},
		{"29 days, 3 since last: due", 29, 3, true, 3},
		{"9 days, 1 since last: due daily", 9, 1, true, 1},
		{"9 days, 0 since last: already sent today", 9, 0, false, 1},
		{"expired, 1 since last: still daily", -3, 1, true, 1},
		{"120 days: no cadence at all", 120, 90, false, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := s.evaluate(certAt(c.days, daysAgo(today, c.sinceLast)), consumed, today)
			if d.send != c.wantSend {
				t.Fatalf("send = %v, want %v (%+v)", d.send, c.wantSend, d)
			}
			if d.send && d.trigger != "cadence" {
				t.Errorf("trigger = %q, want cadence", d.trigger)
			}
			if d.send && d.interval != c.wantInterval {
				t.Errorf("interval = %d, want %d", d.interval, c.wantInterval)
			}
		})
	}
}

func TestNeverNotifiedInsideARungFiresImmediately(t *testing.T) {
	s := testScheduler()
	today := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)

	// A cert added when it is already down to 20 days: every milestone is
	// backfilled in one alert rather than five.
	d := s.evaluate(certAt(20, nil), map[int]bool{}, today)
	if !d.send || d.trigger != "milestone" {
		t.Fatalf("expected an immediate alert, got %+v", d)
	}
	if len(d.thresholds) != 5 {
		t.Errorf("expected all five crossed milestones consumed, got %v", d.thresholds)
	}
	if d.interval != 3 {
		t.Errorf("interval = %d, want 3 (inside the 30-day rung)", d.interval)
	}
}

func TestExpiredSentinelConsumedOnce(t *testing.T) {
	s := testScheduler()
	today := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)

	d := s.evaluate(certAt(-1, nil), map[int]bool{}, today)
	if !d.send || d.kind != "expired" {
		t.Fatalf("expected an expired alert, got %+v", d)
	}
	if d.thresholds[0] != expiredSentinel {
		t.Errorf("expected the expired sentinel first, got %v", d.thresholds)
	}

	// Sentinel already burnt: it falls through to the daily cadence instead of
	// re-firing the milestone.
	sent := map[int]bool{expiredSentinel: true, 30: true, 45: true, 60: true, 75: true, 90: true}
	d = s.evaluate(certAt(-2, daysAgo(today, 1)), sent, today)
	if !d.send || d.trigger != "cadence" || d.kind != "expired" {
		t.Errorf("expected a daily cadence repeat, got %+v", d)
	}
}

func TestCadenceDueAcrossMonthBoundary(t *testing.T) {
	today := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	last := time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)
	if !cadenceDue(&last, today, 3) {
		t.Error("3 days across a month boundary should be due")
	}
	if cadenceDue(&last, today, 5) {
		t.Error("only 3 days elapsed; a 5-day interval is not due")
	}
}
