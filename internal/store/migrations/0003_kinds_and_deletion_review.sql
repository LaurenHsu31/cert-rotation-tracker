-- Two additions:
--   1. Tracked items now have a KIND — a certificate or a token. Both expire
--      and both need rotating, so they share every column; only the wording in
--      the UI and in notifications differs.
--   2. Deleting a tracked item is a four-eyes action, like renewing one: the
--      requester states a reason, a second person approves, and only then is
--      the row soft-deleted.
-- Idempotent like 0001/0002 so the startup migrator can re-apply it safely.

-- --------------------------------------------------------------- kind

ALTER TABLE certificates ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'certificate';

DO $$
BEGIN
    ALTER TABLE certificates
        ADD CONSTRAINT certificates_kind_check CHECK (kind IN ('certificate', 'token'));
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

CREATE INDEX IF NOT EXISTS idx_certificates_kind ON certificates (kind);

-- ----------------------------------------------------- deletion review

-- The approved reason is denormalized onto the row so "why is this gone?" is
-- answerable from the certificate itself, without joining the request table.
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS deletion_reason TEXT NOT NULL DEFAULT '';

-- A deletion request: someone says "this should go and here is why", and a
-- different person has to approve before anything is hidden. Requester and
-- reviewer are always different people (enforced in code and by the CHECK).
CREATE TABLE IF NOT EXISTS deletion_requests (
    id             BIGSERIAL PRIMARY KEY,
    certificate_id BIGINT      NOT NULL REFERENCES certificates (id) ON DELETE CASCADE,
    status         TEXT        NOT NULL DEFAULT 'pending_review'
                               CHECK (status IN ('pending_review', 'approved', 'rejected', 'withdrawn')),
    reason         TEXT        NOT NULL CHECK (length(btrim(reason)) > 0),

    requested_by   BIGINT      NOT NULL REFERENCES users (id),
    requested_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_by    BIGINT      REFERENCES users (id),
    reviewed_at    TIMESTAMPTZ,
    review_note    TEXT        NOT NULL DEFAULT '',

    CHECK (reviewed_by IS NULL OR reviewed_by <> requested_by)
);

-- At most one open request per certificate.
CREATE UNIQUE INDEX IF NOT EXISTS idx_deletions_one_open
    ON deletion_requests (certificate_id) WHERE status = 'pending_review';

CREATE INDEX IF NOT EXISTS idx_deletions_cert   ON deletion_requests (certificate_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_deletions_status ON deletion_requests (status, requested_at DESC);
