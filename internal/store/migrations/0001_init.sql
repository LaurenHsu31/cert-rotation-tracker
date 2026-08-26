-- Certificate rotation tracker schema.
-- Written to be idempotent so it can be applied safely on every startup.
-- For versioned migrations later, golang-migrate/goose can consume this file.

CREATE TABLE IF NOT EXISTS certificates (
    id                BIGSERIAL PRIMARY KEY,
    name              TEXT        NOT NULL,
    environment       TEXT        NOT NULL CHECK (environment IN ('dev', 'stg', 'prd')),
    issued_date       DATE        NOT NULL,
    expiry_date       DATE        NOT NULL,
    reminder_days     INTEGER[]   NOT NULL DEFAULT '{30,45,60,75,90}',
    teams_webhook_url TEXT        NOT NULL DEFAULT '',
    notify_emails     TEXT[]      NOT NULL DEFAULT '{}',
    notes             TEXT        NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_certificates_expiry ON certificates (expiry_date);
CREATE INDEX IF NOT EXISTS idx_certificates_env ON certificates (environment);

-- Dedup log: records which reminder threshold has already fired for a cert,
-- so the daily scan never re-sends the same alert. threshold_day = -1 is the
-- sentinel for the "expired" notification. Rows are cleared for a cert when
-- its expiry_date changes (a re-arm after rotation).
CREATE TABLE IF NOT EXISTS notifications_sent (
    id             BIGSERIAL PRIMARY KEY,
    certificate_id BIGINT      NOT NULL REFERENCES certificates (id) ON DELETE CASCADE,
    threshold_day  INTEGER     NOT NULL,
    sent_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (certificate_id, threshold_day)
);
