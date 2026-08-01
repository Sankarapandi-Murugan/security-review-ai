# Vigil AI (security-review-ai)

> **Mission:** Build autonomous AI security engineers that discover, validate, and remediate
> vulnerabilities faster than human teams.

Vigil AI is a multi-tenant, API-first platform running 9 autonomous security agents (White Box,
Black Box, Red Team, Blue Team, API Security, Cloud Security, Dependency Security, Secret
Detection, and Auto-Remediation) that continuously scan applications, APIs, infrastructure, and
cloud environments — then fix what they safely can and hand the rest to your team with
reproducible evidence. A marketing/mission landing page is served at `/`; the operator dashboard
lives at `/ui/`.

## Run locally

```bash
cd backend
.venv/bin/uvicorn security_review.main:app --host 0.0.0.0 --port 8000
```

Then open `http://localhost:8000/` for the landing page or `http://localhost:8000/ui/` for the
dashboard.

## Plans & billing

Every organization is on a plan (`free`, `pro`, or `enterprise`) that caps total assessments and
scan jobs. Payment processing is pluggable (`infrastructure/billing/payment_provider.py`):

- **`MockPaymentProvider`** (default, `SECURITY_REVIEW_PAYMENT_PROVIDER` unset/`mock`) — activates
  plan changes immediately with no real payment collection. Good for local dev/demos.
- **`StripePaymentProvider`** (`SECURITY_REVIEW_PAYMENT_PROVIDER=stripe`) — a real integration:
  upgrading to Pro creates a Stripe Checkout Session (hosted by Stripe) and the plan is only
  activated once Stripe confirms payment via webhook; downgrading to Free cancels any existing
  subscription immediately; Enterprise is "contact sales" (no self-serve checkout). Requires:
  - `STRIPE_SECRET_KEY` — your Stripe secret key.
  - `STRIPE_PRICE_ID_PRO` — the Stripe Price id for the Pro plan.
  - `STRIPE_WEBHOOK_SECRET` — the signing secret for your webhook endpoint (needed to verify
    `POST /billing/webhooks/stripe`, which Stripe calls — configure this URL in the Stripe
    Dashboard, or via `stripe listen --forward-to localhost:8000/billing/webhooks/stripe` locally).

  Missing/invalid configuration fails loudly (`PaymentProviderError`) rather than silently
  granting access — there is no fake/simulated Stripe behavior.

```bash
# Public pricing catalog (no auth required)
curl http://127.0.0.1:8000/billing/plans

# Current plan + usage for the authenticated organization
curl http://127.0.0.1:8000/billing/usage -H "Authorization: Bearer <access_token>"

# Change plan (mock provider: activates immediately; Stripe provider: may return a
# checkout_url you must redirect the user to instead)
curl -X POST http://127.0.0.1:8000/billing/subscribe \
  -H "Content-Type: application/json" -H "Authorization: Bearer <access_token>" \
  -d '{"plan": "pro"}'
```

Creating an assessment or scan job beyond the plan's limit returns `402 Payment Required`. The
dashboard (`/ui/`) has a "Billing & plans" button showing live plan/usage, subscribing to a
different tier, and redirecting to Stripe Checkout when payment collection is required.

## Login/signup UI and authorization-consent audit trail

The dashboard (`/ui/`) now has a sign-in widget (top of the sidebar) backed by `/auth/login` and
`/auth/signup` — the issued bearer token is stored in the browser and automatically attached to
every request. Signing in (or signing up) is now **required** to use the dashboard or API at all
(see "Authentication is required everywhere" below) — there is no anonymous/demo mode. Log out
clears the stored token.

Every time a scan job is created with `target_authorization_confirmed: true` (required for active/
intrusive scanning — Black Box crawling and injection probes, API Security rate-limit and JWT
tests), the backend records an **immutable** entry in a dedicated audit log: who confirmed it (the
signed-in user's email), the target, the agent type, and the timestamp. This is stored separately
from the assessment itself so the trail survives assessment deletion.

```bash
curl http://127.0.0.1:8000/audit/consent-log -H "Authorization: Bearer <access_token>"
```

View it in the dashboard via the "Consent audit log" sidebar button. `ScanJob` responses also
include `authorized_by`/`authorized_at` fields directly.

## Password reset

`POST /auth/forgot-password` (rate-limited, 5/60s by default) always returns the same generic
response regardless of whether the email is registered, to avoid leaking which emails have
accounts. If it is registered, a single-use reset token (30-minute expiry) is generated — only a
SHA-256 hash of it is stored in the database, never the raw token — and emailed via a pluggable
`EmailProvider` (`infrastructure/email/email_provider.py`):

- **`ConsoleEmailProvider`** (default) — logs the reset link instead of sending it (the standard,
  safe local-dev behavior, like Django's console email backend).
- **`SmtpEmailProvider`** (`SECURITY_REVIEW_EMAIL_PROVIDER=smtp`) — sends a real email via any
  standard SMTP server (Gmail, SES, Mailgun, Postmark, etc. all expose SMTP). Requires
  `SECURITY_REVIEW_SMTP_HOST`, `SECURITY_REVIEW_SMTP_FROM_ADDRESS`, and usually
  `SECURITY_REVIEW_SMTP_USERNAME`/`_PASSWORD`; fails loudly if misconfigured.

```bash
curl -X POST http://127.0.0.1:8000/auth/forgot-password -H "Content-Type: application/json" \
  -d '{"email": "you@acme.com"}'

curl -X POST http://127.0.0.1:8000/auth/reset-password -H "Content-Type: application/json" \
  -d '{"token": "<token from the emailed link>", "new_password": "a-new-strong-password"}'
```

The dashboard (`/ui/`) has a "Forgot password?" link on the login form, and automatically shows a
"set new password" form when loaded with a `?reset_token=...` query parameter (the link sent by
email points at `/ui/?reset_token=...`).

## Team management & roles

Every user has a role — `owner`, `admin`, or `member` — enforced on these endpoints:

- **Invite a teammate** (`POST /team/invite`) — owner or admin. Creates the account immediately
  under a randomly-generated, never-disclosed password and emails a "set your password" link
  (reusing the same single-use token mechanism as password reset).
- **Change a member's role** (`PATCH /team/members/{user_id}/role`) and **remove a member**
  (`DELETE /team/members/{user_id}`) — owner only. Both refuse to demote/remove the organization's
  only remaining owner (`409 Conflict`).
- **List members** (`GET /team/members`) — any authenticated member of the organization.
- **Change the billing plan** (`POST /billing/subscribe`) — owner only.
- **Delete an assessment or repository** — owner or admin only.

Everything else (creating assessments, running scans, viewing reports/findings) remains open to
any authenticated member — RBAC is applied only to destructive/financial/team-management actions.

```bash
curl -X POST http://127.0.0.1:8000/team/invite -H "Content-Type: application/json" \
  -H "Authorization: Bearer <owner_or_admin_access_token>" \
  -d '{"email": "teammate@acme.com", "role": "member"}'

curl http://127.0.0.1:8000/team/members -H "Authorization: Bearer <access_token>"
```

Manage your team from the dashboard (`/ui/`) via the "Team" sidebar button.

## Observability

- **Structured JSON logging**: every log line (application and uvicorn access/error logs) is a
  single JSON object on stdout — `{"timestamp", "level", "logger", "message", ...}` — ready to
  ingest into CloudWatch/Datadog/ELK/etc. without custom parsing. Level is controlled by
  `SECURITY_REVIEW_LOG_LEVEL` (default `INFO`).
- **Metrics**: `GET /metrics` exposes Prometheus-format metrics (public, no auth required, like
  `/health`): `vigil_http_requests_total` and `vigil_http_request_duration_seconds` (by
  method/path/status), `vigil_scan_jobs_total` (by agent type and outcome), `vigil_findings_total`
  (by severity), and `vigil_unhandled_exceptions_total`.
- **Error tracking**: optional Sentry integration — set `SECURITY_REVIEW_SENTRY_DSN` and install
  `sentry-sdk` (`uv add sentry-sdk`) to forward unhandled exceptions; without it, exceptions are
  still fully captured in the structured logs (with traceback) and counted in
  `vigil_unhandled_exceptions_total`. This is a soft dependency — the app runs fine without it.

```bash
curl http://127.0.0.1:8000/metrics
```

## Run with Docker Compose

```bash
docker compose up --build
```

Then open http://localhost:8000/ for the landing page or http://localhost:8000/ui/ for the dashboard.

## User accounts & multi-tenancy

The API supports organization-scoped accounts. Each signup creates a new organization and an
`owner` user; all assessments created by that user are scoped to their organization and are not
visible to other organizations.

```bash
# Sign up (creates an organization + owner user, returns a bearer token)
curl -X POST http://127.0.0.1:8000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"organization_name": "Acme Inc", "email": "you@acme.com", "password": "supersecret123"}'

# Log in (returns a bearer token)
curl -X POST http://127.0.0.1:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "you@acme.com", "password": "supersecret123"}'

# Use the token on assessment endpoints
curl http://127.0.0.1:8000/assessments \
  -H "Authorization: Bearer <access_token>"
```

Set `SECURITY_REVIEW_JWT_SECRET` to a random 32+ byte secret in production (tokens are signed
with HMAC-SHA256 and expire after 12 hours).

### Secrets hardening (fail-loud in production)

Set `SECURITY_REVIEW_ENVIRONMENT=production` to enable startup validation: the backend **refuses
to start** (raises `InsecureConfigurationError`, logged and re-raised — not silently ignored) if:

- `SECURITY_REVIEW_JWT_SECRET` is unset, still the insecure development default, or shorter than
  32 characters.
- `SECURITY_REVIEW_AUTH_REQUIRED=true` but `SECURITY_REVIEW_API_KEY` is unset or still `demo-key`.
- `SECURITY_REVIEW_WEBHOOK_SECRET` is set to a known placeholder value copied verbatim from
  `.env.example` instead of a real secret.

This is a no-op in any other environment (local dev, tests, staging), so it never blocks everyday
development — only a real production deployment with insecure secrets. Generate strong secrets
with e.g. `openssl rand -hex 32`.

### Authentication is required everywhere

Every assessment/billing/audit endpoint requires a valid bearer token — there is no
anonymous/legacy-organization fallback. Requests without a valid `Authorization: Bearer <token>`
header return `401 Unauthorized`. Sign up or log in first, then use the returned `access_token`
on all subsequent requests. This applies equally to the dashboard UI and direct API/`curl` usage.

`/auth/login` and `/auth/signup` are rate-limited per client IP to mitigate brute-force/credential-
stuffing attempts: 10 login attempts and 5 signups per 60-second window by default. Exceeding the
limit returns `429 Too Many Requests` with a `Retry-After` header. Tune with
`SECURITY_REVIEW_LOGIN_RATE_LIMIT`, `SECURITY_REVIEW_LOGIN_RATE_WINDOW_SECONDS`,
`SECURITY_REVIEW_SIGNUP_RATE_LIMIT`, and `SECURITY_REVIEW_SIGNUP_RATE_WINDOW_SECONDS`. Backed by an
in-memory counter by default (single-process only); set `REDIS_URL` to share rate-limit state
across multiple backend instances (see "Production data stores" below).

## Production data stores: Postgres and Redis

By default the backend runs entirely on a local SQLite file and an in-memory rate limiter — zero
external dependencies, ideal for local dev and the test suite. For a real multi-instance production
deployment, set these environment variables and nothing else needs to change (every repository and
the rate limiter pick them up automatically via the same pluggable-backend pattern used for
payments and error tracking):

- **`DATABASE_URL`** — a SQLAlchemy URL, e.g. `postgresql+psycopg://user:pass@host:5432/dbname`.
  All persistence (organizations/users, assessments, the consent audit log) shares one connection
  pool via this URL. Falls back to a local SQLite file when unset.
- **`REDIS_URL`** — e.g. `redis://host:6379/0`. Shares login/signup rate-limit counters across every
  backend instance. Falls back to in-memory (single-process) when unset, or if Redis is
  unreachable (fails open to in-memory with a logged warning — rate limiting degrades gracefully
  rather than breaking auth).

```bash
# Start Postgres + Redis alongside the backend
docker compose --profile production up --build
```

Then set `DATABASE_URL=postgresql+psycopg://vigil:vigil@postgres:5432/vigil` and
`REDIS_URL=redis://redis:6379/0` on the `backend` service in `docker-compose.yml` (commented
template lines are already there) and restart it.

## Deleting assessments and repositories

```bash
# Delete a repository (also removes its cloned copy from disk)
curl -X DELETE http://127.0.0.1:8000/assessments/{id}/repositories/{repository_id}

# Delete an assessment (also cleans up any repositories it ingested)
curl -X DELETE http://127.0.0.1:8000/assessments/{id}
```

Both return `204 No Content` on success and `404` if the resource doesn't exist or isn't visible
to the caller's organization.

## Auto-Remediation Agent

Run `agent_type: "auto_remediation"` as a scan job to automatically fix a curated set of
safe, mechanical findings instead of just reporting them:

```bash
curl -X POST http://127.0.0.1:8000/assessments/{id}/scan-jobs \
  -H "Content-Type: application/json" \
  -d '{"agent_type": "auto_remediation", "target": "/path/to/target"}'
```

Today it fixes missing timeouts on `requests` calls (Bandit B113 / CWE-400 unbounded resource
consumption): it runs the White Box scanner for a baseline, patches affected files, re-runs the
scan to verify the finding is resolved, and reports before/after finding counts. If the target is
a git repository with a configured remote and the `gh` CLI is authenticated, it also best-effort
commits the fix to a `security-review-ai/auto-remediation` branch and opens a pull request (skipped
silently otherwise — this is a convenience, not a requirement). The scope is intentionally narrow:
automatically rewriting arbitrary source code is risky, so only behavior-preserving, unambiguous
fixes are applied.

## Black Box and Red Team agents

`agent_type: "black_box"` performs external reconnaissance (open-port checks against common
services) plus, when the target is an `http(s)://` URL, a same-origin crawl (capped at 15 pages)
that checks for missing security headers, forms without visible CSRF protection, reflected XSS
(via a unique marker in query parameters), and error-based SQL injection (via a probe `'`
character) — each finding includes a reproducible `curl` proof-of-concept as evidence.

Because this active testing sends real requests to the target, it only runs when the scan job sets
`target_authorization_confirmed: true`; otherwise a "Deep active testing skipped" finding is
returned instead:

```bash
curl -X POST http://127.0.0.1:8000/assessments/{id}/scan-jobs \
  -H "Content-Type: application/json" \
  -d '{"agent_type": "black_box", "target": "https://your-authorized-target.example.com", "target_authorization_confirmed": true}'
```

`agent_type: "red_team"` performs static analysis to simulate attacker behavior against a source
tree: in addition to the existing dangerous-code, weak-auth, and injection checks, it now flags
potential privilege-escalation vectors (elevated shell-outs, `chmod 777`, trust-the-caller admin
checks), lateral-movement indicators (hardcoded internal/private network addresses), and — when
multiple weaknesses land in the same file — a single higher-severity "chained attack path" finding
describing the end-to-end exploit path an attacker could take (e.g. harvest credentials -> bypass
weak auth -> achieve code execution).

## API Security: OpenAPI hidden-endpoint discovery

`agent_type: "api_security"` now imports the target's OpenAPI/Swagger spec — either fetched from a
well-known path on a live `http(s)://` target (`/openapi.json`, `/swagger.json`, `/v3/api-docs`,
etc.) or loaded directly from a local spec file — and cross-references its documented paths against
a curated list of commonly-forgotten admin/debug/internal endpoints (`/admin`, `/actuator/env`,
`/api/v2`, `/.env`, `/graphql`, etc.). Any candidate that responds live but isn't declared in the
spec is reported as a "hidden/undocumented endpoint", along with a `curl` PoC and its access level
(publicly accessible vs. access-controlled). As with Black Box, this active probing only runs when
`target_authorization_confirmed: true` is set on the scan job:

```bash
curl -X POST http://127.0.0.1:8000/assessments/{id}/scan-jobs \
  -H "Content-Type: application/json" \
  -d '{"agent_type": "api_security", "target": "https://your-authorized-api.example.com", "target_authorization_confirmed": true}'
```

It also (when authorized) tests **rate limiting** by sending a burst of consecutive requests and
flagging endpoints that never respond `429 Too Many Requests`, and tests **JWT validation** by
sending crafted `alg: none` tokens (no signature required) with an admin claim and an expired claim
— if either is accepted where an unauthenticated request is rejected, it's flagged as a critical JWT
validation weakness. Independently of authorization, any JWT observed in a response body is also
passively decoded (without verification) to flag `alg: none` tokens or tokens missing an `exp` claim.

## Blue Team: log ingestion

`agent_type: "blue_team"` now ingests SIEM/EDR/firewall-style log files (plain-text or JSON-lines) in
addition to its existing static source-code checks. Point `target` at a single log file or a
directory — the agent scans it (and any nested `*.log`, `*access*.log*`, `*auth*.log*`,
`*audit*.log*`, `*.jsonl` files, capped at 20 files / 5,000 lines each) and detects:

- **Brute-force login attempts**: 5+ failed-auth log lines from the same source IP.
- **Web attack payloads**: SQLi/XSS signatures (`union select`, `<script>`, `../../../`, etc.) in
  request logs.
- **Suspicious privileged commands**: `chmod 777`, `useradd`, `sudo su`, reverse-shell patterns, etc.
- **Automated vulnerability scanning**: repeated probes of well-known sensitive paths
  (`/wp-login.php`, `/.env`, `/.git/config`, ...).

Each detection includes a recommended SIEM/EDR detection rule and mitigation as its `remediation`,
and an overall "incident summary" finding aggregates the count/severity breakdown — mirroring an
actual incident report. If logs were ingested but nothing suspicious was found, a baseline set of
recommended detection rules is still returned.

```bash
curl -X POST http://127.0.0.1:8000/assessments/{id}/scan-jobs \
  -H "Content-Type: application/json" \
  -d '{"agent_type": "blue_team", "target": "/var/log/myapp"}'
```

## Listing assessments (pagination)

`GET /assessments` accepts `limit` (1-200, default 50) and `offset` (default 0) query parameters,
ordered newest-first. The total matching count is returned in the `X-Total-Count` response header:

```bash
curl "http://127.0.0.1:8000/assessments?limit=20&offset=0"
```

## Additional scanner requirements

- The project includes adapters for `bandit` (Python SAST) and `safety` (dependency checks) which are installed via Python dependencies.
- `Trivy` is supported for filesystem/container vulnerability scanning but is a separate CLI tool and must be installed on the host or container. See https://aquasecurity.github.io/trivy/installation/ for installation instructions. The backend Docker image installs Trivy automatically.

## Repository ingestion (git clone)

Assessments can ingest a real remote repository, which the backend shallow-clones (`git clone --depth 1`)
to local disk so scanners operate on actual source code instead of a manually-provided path:

```bash
curl -X POST http://127.0.0.1:8000/assessments/{id}/repositories \
  -H "Content-Type: application/json" \
  -d '{"name": "my-app", "url": "https://github.com/org/my-app", "branch": "main"}'
```

The response returns immediately with `"status": "pending"` — cloning happens in the background.
Poll `GET /assessments/{id}/repositories/{repository_id}` until `status` becomes `"ready"`
(or `"failed"`, with `error_message` explaining why). Once ready, reference the repository directly
when creating a scan job instead of specifying a filesystem `target`:

```bash
curl -X POST http://127.0.0.1:8000/assessments/{id}/scan-jobs \
  -H "Content-Type: application/json" \
  -d '{"agent_type": "white_box", "repository_id": "<repository_id>"}'
```

Creating a scan job with a `repository_id` that isn't `ready` yet returns `409 Conflict`.

Security notes:
- Only `http://` and `https://` repository URLs are accepted (no `file://`, `ssh://`, or other git transports),
  which blocks SSRF-style access to the server's local filesystem and other transport helpers.
- Clones are shallow (`--depth 1`, single branch) and time out after `SECURITY_REVIEW_GIT_CLONE_TIMEOUT_SECONDS`
  seconds (default `120`).
- Cloned repositories are stored under `SECURITY_REVIEW_REPO_WORKDIR` (default `data/repos`), which is
  mounted as a Docker volume so clones persist across container restarts.

## Scan job webhooks

Scan jobs and Trivy scans accept an optional `webhook_url`. When the scan completes (or fails), the backend
sends a `POST` request to that URL with a JSON payload:

```json
{
  "scan_job_id": "...",
  "agent_type": "trivy",
  "status": "completed",
  "target": "/path/to/target",
  "error_message": null,
  "finding_count": 3,
  "findings": [ ... ]
}
```

Example:

```bash
curl -X POST http://127.0.0.1:8000/assessments/{id}/scan-jobs \
  -H "Content-Type: application/json" \
  -d '{"agent_type": "white_box", "target": "/workspace/repo", "webhook_url": "https://example.com/webhook"}'
```

Webhook delivery is best-effort: failures to reach the webhook URL do not affect the scan job result.

### Webhook signing (HMAC-SHA256)

Set the `SECURITY_REVIEW_WEBHOOK_SECRET` environment variable on the backend to have every webhook request
signed with an `X-Signature-256` header, similar to GitHub webhooks:

```
X-Signature-256: sha256=<hex-encoded HMAC-SHA256 of the raw request body>
```

Receivers should verify the signature before trusting the payload:

```python
import hashlib
import hmac

def verify_signature(secret: str, body: bytes, header_value: str) -> bool:
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header_value)
```

If `SECURITY_REVIEW_WEBHOOK_SECRET` is not set, webhooks are sent unsigned (no `X-Signature-256` header) —
recommended only for local development.

## Live scan status via Server-Sent Events (SSE)

Stream real-time scan job status updates without polling:

```
GET /assessments/{assessment_id}/scan-jobs/{scan_job_id}/stream
```

The endpoint emits `text/event-stream` events whenever the job's status changes, and closes automatically once
the job reaches `completed` or `failed`:

```bash
curl -N http://127.0.0.1:8000/assessments/{assessment_id}/scan-jobs/{scan_job_id}/stream
```

Example event:

```
data: {"id": "...", "status": "running", "agent_type": "white_box", ...}

data: {"id": "...", "status": "completed", "agent_type": "white_box", ...}
```

From the browser, use `EventSource`:

```javascript
const source = new EventSource(`/assessments/${assessmentId}/scan-jobs/${scanJobId}/stream`);
source.onmessage = (event) => {
  const scanJob = JSON.parse(event.data);
  console.log(scanJob.status);
  if (scanJob.status === "completed" || scanJob.status === "failed") {
    source.close();
  }
};
```

## CI security scanning

[.github/workflows/ci.yml](.github/workflows/ci.yml) runs on every push/PR and includes:
- `ruff` lint and `pytest` test suite
- `bandit` static analysis and `safety` dependency checks
- `Trivy` filesystem scan of the backend source tree

Scan reports are uploaded as workflow artifacts for review.