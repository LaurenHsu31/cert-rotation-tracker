-- Email becomes the account identifier, plus the self-service password reset
-- that depends on it: a one-time password mailed to the address on file, and a
-- flag that forces the holder to choose a real password before doing anything.
-- Idempotent like the earlier migrations.

-- Normalize before enforcing uniqueness: addresses only ever differ by case
-- for the person typing them, never for the mail server.
UPDATE users SET email = lower(btrim(email)) WHERE email <> lower(btrim(email));

-- Refuse to start on ambiguous logins rather than silently letting one of two
-- accounts become unreachable. The operator has to pick which address wins.
DO $$
DECLARE dup TEXT;
BEGIN
    SELECT string_agg(email, ', ') INTO dup
      FROM (SELECT email FROM users WHERE email <> '' GROUP BY email HAVING count(*) > 1) d;
    IF dup IS NOT NULL THEN
        RAISE EXCEPTION
            'cannot make email the login identifier: these addresses are on more than one account (%). Give each account its own address, then restart.', dup;
    END IF;
END $$;

-- Partial, so accounts predating this migration (the bootstrap admin has no
-- address) do not all collide on the empty string.
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email
    ON users (email) WHERE email <> '';

-- must_change_password gates every authenticated route except signing out and
-- setting a new password, so a one-time password cannot be used as a password.
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false;

-- Set only for a one-time password. A NULL here means an ordinary, non-expiring
-- password; a past timestamp means the OTP is dead and a new one is needed.
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_expires_at TIMESTAMPTZ;

-- When the last reset mail went out, so the endpoint cannot be used to flood
-- somebody's inbox (or to burn their current password) on repeat.
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_at TIMESTAMPTZ;
