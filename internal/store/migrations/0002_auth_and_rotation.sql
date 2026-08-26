-- Identity, ownership, audit trail and the renewal (rotation) workflow.
-- Idempotent like 0001 so the startup migrator can re-apply it safely.

-- ---------------------------------------------------------------- users

CREATE TABLE IF NOT EXISTS users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT        NOT NULL UNIQUE,
    display_name  TEXT        NOT NULL DEFAULT '',
    email         TEXT        NOT NULL DEFAULT '',
    password_hash TEXT        NOT NULL,
    role          TEXT        NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
    -- Disabled rather than deleted: certificates and audit rows keep pointing
    -- at a real identity, so history never loses its actor.
    disabled_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Server-side sessions. Only the SHA-256 of the token is stored, so a database
-- dump does not hand out live sessions.
CREATE TABLE IF NOT EXISTS sessions (
    token_hash BYTEA       PRIMARY KEY,
    user_id    BIGINT      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions (expires_at);

-- ------------------------------------------------------- certificates

ALTER TABLE certificates ADD COLUMN IF NOT EXISTS owner_id         BIGINT REFERENCES users (id);
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS deleted_at       TIMESTAMPTZ;
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS deleted_by       BIGINT REFERENCES users (id);
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS rotated_at       TIMESTAMPTZ;
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS rotated_by       BIGINT REFERENCES users (id);
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS renewed_from_id  BIGINT REFERENCES certificates (id);
-- Drives the escalating reminder cadence: the calendar date (in the tracker's
-- timezone) an alert last went out for this cert.
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS last_notified_on DATE;

CREATE INDEX IF NOT EXISTS idx_certificates_owner ON certificates (owner_id);
CREATE INDEX IF NOT EXISTS idx_certificates_live  ON certificates (expiry_date)
    WHERE deleted_at IS NULL AND rotated_at IS NULL;

-- ------------------------------------------------------------- audit

CREATE TABLE IF NOT EXISTS audit_log (
    id             BIGSERIAL PRIMARY KEY,
    actor_id       BIGINT REFERENCES users (id),
    actor_username TEXT        NOT NULL DEFAULT '',
    action         TEXT        NOT NULL,
    entity_type    TEXT        NOT NULL,
    entity_id      BIGINT,
    detail         JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_entity  ON audit_log (entity_type, entity_id, created_at DESC);

-- ----------------------------------------------------------- renewals

-- A renewal request: the owner says "I rotated this", attaches proof, and a
-- second person has to approve before the old cert is marked rotated and the
-- replacement row is created. Submitter and reviewer are always different
-- people (enforced in code and by the CHECK below).
CREATE TABLE IF NOT EXISTS renewals (
    id                 BIGSERIAL PRIMARY KEY,
    certificate_id     BIGINT      NOT NULL REFERENCES certificates (id) ON DELETE CASCADE,
    status             TEXT        NOT NULL DEFAULT 'pending_review'
                                   CHECK (status IN ('pending_review', 'approved', 'rejected', 'withdrawn')),
    new_issued_date    DATE        NOT NULL,
    new_expiry_date    DATE        NOT NULL,
    note               TEXT        NOT NULL DEFAULT '',

    evidence           BYTEA       NOT NULL,
    evidence_mime      TEXT        NOT NULL,
    evidence_filename  TEXT        NOT NULL DEFAULT '',
    evidence_size      INTEGER     NOT NULL DEFAULT 0,
    evidence_sha256    TEXT        NOT NULL DEFAULT '',

    submitted_by       BIGINT      NOT NULL REFERENCES users (id),
    submitted_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_by        BIGINT      REFERENCES users (id),
    reviewed_at        TIMESTAMPTZ,
    review_note        TEXT        NOT NULL DEFAULT '',
    new_certificate_id BIGINT      REFERENCES certificates (id),

    CHECK (reviewed_by IS NULL OR reviewed_by <> submitted_by)
);

-- At most one open request per certificate.
CREATE UNIQUE INDEX IF NOT EXISTS idx_renewals_one_open
    ON renewals (certificate_id) WHERE status = 'pending_review';

CREATE INDEX IF NOT EXISTS idx_renewals_cert   ON renewals (certificate_id, submitted_at DESC);
CREATE INDEX IF NOT EXISTS idx_renewals_status ON renewals (status, submitted_at DESC);
