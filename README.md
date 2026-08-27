# Certificate Rotation Tracker

A small self-hosted service that tracks **certificates and tokens** and their
expiry, shows how much runway each one has left with escalating severity, and
sends reminders to **Microsoft Teams** and/or **email** before rotation is due.

One central instance tracks them across all environments (`dev` / `stg` /
`prd`); the environment is a tag on each item, not a separate deployment.

## Highlights

- **Single Go binary.** The web UI — including Vue — is vendored and embedded via
  `go:embed`. No Node build step, and no CDN at runtime, so it runs **fully
  offline on-prem**.
- **One image + Postgres.** `docker compose up` and you're running.
- **Env-driven config (12-factor).** The same image runs across dev/stg/prd; only
  the injected values change. On-prem today, cloud later with no code change.
- **Escalating severity.** Each certificate shows a colour-coded "days left"
  countdown and a life-runway bar. Cutoffs are configurable.
- **Two channels behind one interface.** Per-certificate Teams webhook URL and/or
  email recipient list. A failure in one channel never blocks the other.
- **Smart, escalating reminders.** One alert per milestone as the deadline
  approaches, then a repeat cadence that tightens the closer expiry gets —
  every 5 days under 45, every 3 under 30, daily under 10. De-duplicated so you
  are never spammed twice in a day.
- **Certificates and tokens.** An API or service token expires and needs
  rotating exactly like a certificate, so both are tracked the same way. The
  type is picked when you add it, drives the wording in every notification, and
  is fixed thereafter — its history already refers to it by that name.
- **Ownership, not a free-for-all.** Whoever creates a certificate owns it. Only
  the owner and administrators can edit, delete or test it; everyone else gets a
  read-only view with the Teams webhook URL and recipient list redacted.
- **Four-eyes rotation.** "Mark renewed" requires a picture of the new
  certificate and a **second person's** approval. On approval the old
  certificate is marked rotated and its replacement is created automatically,
  inheriting the reminder configuration.
- **Four-eyes deletion.** Deleting is a request, not a click: the requester must
  say **why**, a second person approves it, and once it goes through everyone on
  the item's notification channels is told who asked, who approved and the
  reason. The delete itself stays soft, so it is still recoverable.
- **Everything is audited.** Every change records who did it and when, filtered
  on two axes — what happened (changes, rotations, deletions, users, sign-in,
  system) and what it happened to (certificates, tokens) — and deletes are soft,
  so "who touched my reminder settings" is always answerable and an accidental
  delete is recoverable.
- **The account is an email address.** People sign in with their address, and
  a forgotten password self-serves: a one-time password is mailed out, works
  once, expires, and the tracker refuses to do anything else until the holder
  has chosen a real password.

## Quick start (on-prem, Docker)

```bash
cp .env.example .env      # adjust TIMEZONE, SMTP_*, etc.
docker compose up --build
```

Open http://localhost:18090. Postgres runs as a compose service with a persistent
volume; the schema is applied automatically on first start.

To test email locally without a real relay, start the bundled MailHog:

```bash
docker compose --profile mailtest up --build
# then in .env: SMTP_HOST=mailhog  SMTP_PORT=1025  SMTP_FROM=cert-tracker@local
# captured mail is visible at http://localhost:18025
```

## Architecture

```
┌────────────────────────────────────────────┐
│ certtracker (single Go binary)             │
│                                            │
│  HTTP API  ──────────────┐                 │
│  Embedded Vue SPA (offline)                │
│  Daily scheduler ────────┤                 │
│                          ▼                 │
│                     Notifier (interface)   │
│                     ├── Teams (webhook)    │
│                     └── Email (SMTP)       │
└──────────────┬─────────────────────────────┘
               ▼
          PostgreSQL
```

- `cmd/server` — wiring, HTTP server, graceful shutdown.
- `internal/config` — all env config.
- `internal/auth` — password hashing (PBKDF2-HMAC-SHA256, stdlib only), session
  tokens and the request-scoped `Identity`.
- `internal/models` — the `Certificate` (certificate or token), `User`,
  `Renewal`, `DeletionRequest` and audit types.
- `internal/reminder` — the escalating repeat cadence.
- `internal/severity` — days-remaining → level, with configurable cutoffs.
- `internal/store` — Postgres access + embedded schema (`internal/store/migrations`).
- `internal/notify` — `Notifier` interface + Teams and Email implementations + dispatcher.
- `internal/scheduler` — the daily reminder scan (also callable on demand).
- `internal/api` — REST handlers and router (Go 1.22 `ServeMux`).
- `internal/web` — the embedded frontend (`static/`).

## How reminders work

Three independent concepts:

- **Milestones** (per certificate, e.g. `30, 45, 60, 75, 90`) each fire **once**,
  the first scan after days-remaining drops to or below them.
- **Escalation cadence** (`REMINDER_ESCALATION`, tracker-wide) then **repeats**
  the alert on an interval that shortens as expiry approaches.
- **Severity** (`healthy → notice → warning → urgent → critical → expired`) decides
  how each certificate *looks*, derived from configurable day cutoffs.

The default ladder, reading top to bottom as a certificate ages:

| Days remaining | What fires |
|---|---|
| 90, 75, 60 | one milestone alert each, as they are crossed |
| 45 and below | milestone at 45, then **every 5 days** |
| 30 and below | milestone at 30, then **every 3 days** |
| 10 and below | **every day** |
| expired | one "EXPIRED" alert, then **every day** until rotated |

The scan (daily at `SCHEDULER_RUN_AT`, or on demand via **Run check now**) does this
per certificate:

1. Compute days remaining.
2. Find milestones that are now due and not already sent.
3. If none, check whether the cadence interval has elapsed since the last alert.
4. Send **one** alert either way, then record the milestones consumed and today's
   date.

Consequences, by design:

- **At most one alert per certificate per scan.** The point is to escalate
  urgency, not to multiply mail. Every alert says how often it will repeat and
  how to make it stop.
- **De-duplicated milestones.** A given milestone alerts once. Re-running the
  scan does nothing until the cadence is due or the next milestone is crossed.
- **Backfill collapse.** A certificate added when it's already, say, 20 days out
  sends *one* alert now — not five — and then falls straight into the 3-day
  cadence.
- **Re-arm on rotation.** Changing a certificate's expiry date clears both its
  milestone history and its cadence clock, so the new cycle starts fresh.
- **Rotated and deleted certificates go quiet.** Once a rotation is approved the
  old certificate stops alerting entirely — its replacement is what matters now.
- **No channel, no mark.** A certificate that's due but has no deliverable channel is
  skipped and left un-marked, so it alerts as soon as you add one. Transient send
  failures are retried on the next scan.

## Access control

Authentication is local accounts with server-side sessions — no external
identity provider needed, so the tracker still runs air-gapped.

| | read everything | edit / test / request deletion | approve a rotation or deletion | manage users, audit, run scan |
|---|---|---|---|---|
| **owner** | ✅ | ✅ own only | ✅ others' requests | — |
| **user** | ✅ (redacted) | — | ✅ others' requests | — |
| **admin** | ✅ | ✅ any | ✅ others' requests | ✅ |

Nobody — administrators included — can delete a tracked certificate or token on
their own; see [Deletion workflow](#deletion-workflow-four-eyes).

Details worth knowing:

- **Redaction.** A Teams webhook URL is a bearer credential — anyone holding it
  can post to that channel — and the recipient list is personal data. Neither is
  returned to a viewer who is not the owner or an admin; the UI shows only
  "Teams configured".
- **Ownership transfer.** Owners can hand a certificate to anyone active, and
  admins can move any certificate. Do this before someone leaves, or their
  certificates need an admin to unstick.
- **Soft delete.** Deletes hide the row; an admin can restore it. Any open
  renewal request on a deleted certificate is withdrawn automatically.
- **Accounts are disabled, never deleted**, so ownership and audit history keep
  pointing at a real person. Disabling kills that account's live sessions
  immediately. The tracker refuses to demote or disable the last active admin.
- **First run.** If the users table is empty the tracker creates an admin from
  `BOOTSTRAP_ADMIN_USERNAME` / `BOOTSTRAP_ADMIN_PASSWORD`, generating and
  printing a password if you left it blank. Any certificates that predate
  ownership are adopted by that admin.
- **CSRF.** Session cookies are `HttpOnly`, `SameSite=Lax`, and `Secure`
  whenever `BASE_URL` is https. State-changing requests must additionally carry
  a same-origin `Origin` header. `Authorization: Bearer <token>` callers are
  exempt, since a token is never attached automatically.
- **Passwords** are PBKDF2-HMAC-SHA256, 600 000 iterations, salted per user,
  implemented on the standard library so the single-dependency build survives.

Set `AUTH_ENABLED=false` for local development only: it runs every request as
the bootstrap admin with no login at all.

## Passwords and account recovery

An account **is** an email address. That is what people type to sign in and
where a one-time password goes; the short handle you see on cards and in the
audit log is derived from it and is only cosmetic.

```
forgot your password
  └─ POST /api/auth/forgot { email }        ← always answers 200, always the same
         │                                    body: a public endpoint that
         │                                    distinguished known from unknown
         ▼                                    addresses would be an account oracle
   one-time password
     • replaces the current password outright   ← so the old one cannot be reused
     • expires (PASSWORD_RESET_TTL_MINUTES, default 30)
     • drops every live session for the account
     • one per PASSWORD_RESET_COOLDOWN_SECONDS (default 120)
         │
         ▼
   sign in with it → the account is FROZEN
         │
         │  every route answers 403 { code: "password_change_required" }
         │  except: POST /api/auth/password, POST /api/auth/logout, GET /api/config
         ▼
   choose a new password (new + confirm) → frozen state lifts, OTP is dead
```

The freeze is enforced in the auth middleware, not per handler, so a route added
later is covered by default and has to be listed explicitly to escape it.

The same freeze applies to any password somebody else chose: an account created
by an administrator, and an administrator's password reset, both hand over a
credential the admin knows, so the holder has to replace it before the account
can do anything. A bootstrap admin password that the tracker *generated* is
treated the same way, because it is printed to the startup log.

**Self-service reset needs SMTP.** With `SMTP_HOST` blank the whole email
channel is off — no expiry reminders, and no password reset — and the reset
endpoint says so plainly (`503`) rather than pretending to send. That is a fact
about the deployment, not about the address, so it leaks nothing. Startup logs
`email_enabled` so you can tell at a glance. Until a relay is configured,
password recovery is the admin `Reset password` button.

**Legacy accounts.** Accounts created before email became the identifier can
still sign in with their username, so upgrading does not lock anyone out. Give
them an address on the Users screen to move them across.

## Rotation workflow (four eyes)

Marking a certificate renewed is a two-person operation, so no single account
can retire a certificate and quietly stop its alerts.

```
owner clicks "Mark renewed"
  ├─ new issued + expiry dates
  └─ proof image (PNG/JPEG/WebP/GIF, validated by magic bytes, ≤ MAX_UPLOAD_MB)
         │
         ▼
   status: pending_review        ← the certificate keeps alerting meanwhile
         │
         ├── anyone EXCEPT the submitter reviews the evidence
         │
    ┌────┴────┐
 approve    reject (reason required)
    │            └─ owner fixes it and resubmits
    ▼
 one transaction:
   • old certificate  → rotated_at set, stops alerting
   • new certificate  → created with the new dates, inheriting name,
                        environment, milestones, webhook, recipients and owner
   • renewal          → approved, linked to both
   • audit            → two entries
```

While a request is open the certificate shows an **In review** status in the
list and keeps alerting — a submitted rotation is not a completed one.

The evidence image is stored in Postgres (so it is covered by the same backup as
everything else), hashed with SHA-256 for tamper-evidence, and served back with
`nosniff` and a `default-src 'none'; sandbox` CSP. Only real images are
accepted — the browser's declared content type is ignored in favour of the
bytes themselves.

## Deletion workflow (four eyes)

Removing a certificate or token is the one action that makes its alerts stop
forever, so it needs the same two people a rotation does — plus a reason on the
record.

```
owner clicks "Request deletion…"
  └─ reason (required, stored permanently and read by everyone notified)
         │
         ▼
   status: pending_review        ← the item keeps alerting meanwhile
         │
         ├── anyone EXCEPT the requester reviews the reason
         │
    ┌────┴────┐
 approve    refuse (note required)
    │            └─ nothing is removed; the item carries on as before
    ▼
 one transaction:
   • certificate      → deleted_at set + the approved reason stamped on the row
   • open renewal     → withdrawn (it could never be actioned now)
   • deletion request → approved, linked to both people
   • audit            → one entry on the request, one on the certificate
         │
         ▼
 notification to the item's Teams webhook and email recipients,
 plus the owner's own address: what was deleted, who asked, who
 approved, the reason and the reviewer's note
```

The delete stays **soft** — an administrator can restore the row, which also
clears the recorded reason. A restored item starts alerting again.

`DELETE /api/certificates/{id}` is therefore no longer a delete: it answers
`409` pointing at this workflow, so an old script fails loudly instead of
silently doing nothing.

If the item has no Teams webhook and no email recipients, the deletion still
goes through and the API reports `notification.sent: false` with the reason —
there was simply nobody to tell.

## Teams setup (important)

The legacy Office 365 "Incoming Webhook" connector was **retired in 2026**, so old
`*.webhook.office.com` URLs no longer work. Create a webhook the current way:

1. In the target Teams channel, add a **Workflow** → template
   *"Post to a channel when a webhook request is received"*.
2. Copy the generated URL and paste it into the certificate's **Teams webhook URL**
   field.

The app posts a MessageCard whose `themeColor` reflects severity. Use **Send test**
on a certificate to confirm delivery.

## Email setup

Set the `SMTP_*` variables. Email is disabled until `SMTP_HOST` and `SMTP_FROM` are
both set. For internal relays with self-signed certificates, set
`SMTP_INSECURE_SKIP_VERIFY=true`. Port 465 (implicit TLS) → `SMTP_USE_TLS=true`;
port 587 negotiates STARTTLS automatically.

## Configuration reference

| Variable | Default | Purpose |
|---|---|---|
| `APP_ENV` | `dev` | Tracker's own env; shown in UI/logs |
| `HTTP_ADDR` | `:18090` | Listen address (pinned by docker-compose) |
| `DATABASE_URL` | — | Postgres DSN (assembled from `POSTGRES_*` in compose) |
| `SCHEDULER_ENABLED` | `true` | Run the daily scan |
| `SCHEDULER_RUN_AT` | `09:00` | Daily scan time (HH:MM in `TIMEZONE`) |
| `TIMEZONE` | `UTC` | IANA name, e.g. `Asia/Taipei` |
| `SEVERITY_NOTICE_DAYS` | `90` | ≤ this ⇒ notice |
| `SEVERITY_WARNING_DAYS` | `60` | ≤ this ⇒ warning |
| `SEVERITY_URGENT_DAYS` | `30` | ≤ this ⇒ urgent |
| `SEVERITY_CRITICAL_DAYS` | `7` | ≤ this ⇒ critical |
| `REMINDER_DEFAULT_DAYS` | `30,45,60,75,90` | Default milestones in the form |
| `REMINDER_ESCALATION` | `45:5,30:3,10:1` | Repeat ladder, `within_days:every_days` |
| `AUTH_ENABLED` | `true` | `false` runs everything as the bootstrap admin (dev only) |
| `SESSION_TTL_HOURS` | `12` | Sliding session lifetime |
| `COOKIE_SECURE` | from `BASE_URL` | `Secure` flag on the session cookie |
| `TRUSTED_ORIGIN` | from `BASE_URL` | Origin allowed to make state-changing calls |
| `BOOTSTRAP_ADMIN_USERNAME` | `admin` | First-run admin (only when no users exist) |
| `BOOTSTRAP_ADMIN_PASSWORD` | generated | First-run password; printed once if blank |
| `MAX_UPLOAD_MB` | `5` | Ceiling per renewal evidence image |
| `PASSWORD_RESET_TTL_MINUTES` | `30` | How long a mailed one-time password stays usable |
| `PASSWORD_RESET_COOLDOWN_SECONDS` | `120` | Minimum gap between reset mails for one account |
| `SMTP_HOST` / `SMTP_PORT` | — / `587` | SMTP relay |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | — | Optional SMTP auth |
| `SMTP_FROM` | — | From address (required to enable email) |
| `SMTP_USE_TLS` | `false` | Implicit TLS (port 465) |
| `SMTP_INSECURE_SKIP_VERIFY` | `false` | Skip TLS verify (internal relays) |
| `BASE_URL` | — | Link back to the tracker in notifications |

## API

All `/api/*` routes except the three marked *public* require a session cookie
(or `Authorization: Bearer <token>`). State-changing requests need a same-origin
`Origin` header.

| Method | Path | Access | Purpose |
|---|---|---|---|
| `GET` | `/api/health` | public | Liveness |
| `POST` | `/api/auth/login` | public | Exchange credentials for a session (email, or a legacy username) |
| `POST` | `/api/auth/forgot` | public | Mail a one-time password; always answers `200` |
| `GET` | `/api/auth/session` | public | Who am I (or `authenticated:false`) |
| `POST` | `/api/auth/logout` | any | End this session |
| `POST` | `/api/auth/password` | any | Change your own password |
| `GET` | `/api/config` | any | Cutoffs, defaults, escalation ladder, limits |
| `GET` | `/api/certificates` | any | List, enriched, most-urgent first (redacted unless owned) |
| `POST` | `/api/certificates` | any | Create (`kind`: `certificate` \| `token`, default `certificate`) — you become the owner |
| `GET` | `/api/certificates/{id}` | any | Read |
| `PUT` | `/api/certificates/{id}` | owner/admin | Update (re-arms reminders if expiry changed) |
| `DELETE` | `/api/certificates/{id}` | — | Gone: answers `409` pointing at the deletion workflow |
| `POST` | `/api/certificates/{id}/restore` | admin | Undo a soft delete (clears the recorded reason) |
| `PUT` | `/api/certificates/{id}/owner` | owner/admin | Transfer ownership |
| `POST` | `/api/certificates/{id}/test` | owner/admin | Send a test notification |
| `GET` | `/api/certificates/{id}/audit` | owner/admin | History of one certificate |
| `POST` | `/api/certificates/{id}/renewals` | owner/admin | Open a renewal request (multipart, with evidence) |
| `GET` | `/api/renewals` | any | List requests (`?status=`, `?certificate_id=`) |
| `GET` | `/api/renewals/{id}` | any | Read one |
| `GET` | `/api/renewals/{id}/evidence` | any | The proof image |
| `POST` | `/api/renewals/{id}/approve` | **not the submitter** | Approve — rotates and creates the replacement |
| `POST` | `/api/renewals/{id}/reject` | **not the submitter** | Reject with a reason |
| `POST` | `/api/renewals/{id}/withdraw` | submitter/admin | Cancel your own request |
| `POST` | `/api/certificates/{id}/deletions` | owner/admin | Open a deletion request (`{"reason": "…"}`, required) |
| `GET` | `/api/deletions` | any | List requests (`?status=`, `?certificate_id=`) |
| `GET` | `/api/deletions/{id}` | any | Read one |
| `POST` | `/api/deletions/{id}/approve` | **not the requester** | Approve — soft-deletes and notifies the channels |
| `POST` | `/api/deletions/{id}/reject` | **not the requester** | Refuse with a reason |
| `POST` | `/api/deletions/{id}/withdraw` | requester/admin | Cancel your own request |
| `GET` | `/api/users` | any | Roster (emails hidden from non-admins) |
| `POST` | `/api/users` | admin | Create an account from an email address (handle is derived) |
| `PUT` | `/api/users/{id}` | admin | Role, profile, disable |
| `POST` | `/api/users/{id}/password` | admin | Set a temporary password (holder must then replace it) |
| `GET` | `/api/audit` | admin | Tracker-wide history (`?category=certificate\|rotation\|deletion\|user\|auth\|system`) |
| `POST` | `/api/tasks/run-check` | admin | Run the reminder scan now |

## Local development

Needs Go 1.22+ and a Postgres you can point at.

```bash
make test         # unit tests: password KAT vectors, escalation ladder, scan decisions
```

```bash
export DATABASE_URL="postgres://certuser:certpass@localhost:15432/certtracker?sslmode=disable"
make run          # go run ./cmd/server
# other targets:
make build        # static binary in bin/
make up / down    # docker compose
make vendor-vue   # refresh the embedded Vue runtime
```

## Extending

- **MySQL** instead of Postgres: swap the driver and the array columns
  (`reminder_days`, `notify_emails`) for a join table or JSON. The store package is
  the only place that touches SQL.
- **Cloud:** nothing here is on-prem-specific beyond your config. Point
  `DATABASE_URL` at RDS/Cloud SQL and run the same image on ECS/Fargate, App Runner,
  or EKS. The scheduler is in-process; to run multiple replicas, either keep the
  scan on one instance or drive `/api/tasks/run-check` from an external cron and set
  `SCHEDULER_ENABLED=false`.
- **Full SPA:** the frontend is decoupled from the API. The embedded single-file UI
  can be replaced with a Vite Vue project served the same way, or hosted separately
  against the same endpoints.
