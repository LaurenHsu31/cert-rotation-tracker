package store

import (
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"time"

	_ "github.com/lib/pq"
)

//go:embed all:migrations
var migrationsFS embed.FS

// Store wraps the database connection and all persistence operations.
type Store struct {
	db *sql.DB
}

// Open connects to Postgres and applies the schema.
func Open(databaseURL string) (*Store, error) {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	// Retry ping briefly so `docker-compose up` works before Postgres is ready.
	var pingErr error
	for i := 0; i < 15; i++ {
		if pingErr = db.Ping(); pingErr == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if pingErr != nil {
		return nil, fmt.Errorf("ping db: %w", pingErr)
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// migrate runs every .sql file under migrations/ in filename order. The schema
// is idempotent, so re-running is safe.
func (s *Store) migrate() error {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		b, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		if _, err := s.db.Exec(string(b)); err != nil {
			return fmt.Errorf("apply %s: %w", name, err)
		}
	}
	return nil
}

// --- notification dedup log ---

// SentThresholds returns the set of threshold_day values already notified for a cert.
func (s *Store) SentThresholds(certID int64) (map[int]bool, error) {
	rows, err := s.db.Query(
		`SELECT threshold_day FROM notifications_sent WHERE certificate_id = $1`, certID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[int]bool)
	for rows.Next() {
		var t int
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out[t] = true
	}
	return out, rows.Err()
}

// RecordNotification marks a scan's outcome for one certificate: the
// milestone thresholds it consumed (so they never fire twice) and the calendar
// date the alert went out (which paces the escalating repeat cadence). Both
// land in one transaction so a crash can't leave the cert nagging daily
// because only half the bookkeeping stuck.
func (s *Store) RecordNotification(certID int64, thresholds []int, on time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if len(thresholds) > 0 {
		stmt, err := tx.Prepare(
			`INSERT INTO notifications_sent (certificate_id, threshold_day)
			 VALUES ($1, $2)
			 ON CONFLICT (certificate_id, threshold_day) DO NOTHING`)
		if err != nil {
			return err
		}
		defer stmt.Close()

		for _, t := range thresholds {
			if _, err := stmt.Exec(certID, t); err != nil {
				return err
			}
		}
	}

	if _, err := tx.Exec(
		`UPDATE certificates SET last_notified_on = $1 WHERE id = $2`,
		on.Format("2006-01-02"), certID); err != nil {
		return err
	}
	return tx.Commit()
}

// ClearSent removes all dedup records for a cert and resets its cadence
// clock (a re-arm after rotation).
func (s *Store) ClearSent(certID int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM notifications_sent WHERE certificate_id = $1`, certID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE certificates SET last_notified_on = NULL WHERE id = $1`, certID); err != nil {
		return err
	}
	return tx.Commit()
}
