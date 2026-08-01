# Vigil AI (security-review-ai) — Project Guidelines

Mission: build autonomous AI security engineers that discover, validate, and remediate
vulnerabilities faster than human teams. See [README.md](../README.md) for product docs and
setup; see [docs/](../docs/) for architecture/ADR notes.

## Architecture

Layered under `backend/src/security_review/`:
- `domain/` — dataclasses/Pydantic models, enums, exceptions. No I/O.
- `application/` — services (`assessment_service.py`, `auth_service.py`, `billing_service.py`)
  orchestrating domain + infrastructure. This is where business rules and use cases live.
- `infrastructure/` — persistence (SQLite by default, Postgres via `DATABASE_URL` — see below),
  the 9 security-scanning agents (`scanners/`), git ingestion (`vcs/`), password hashing
  (`security/`), and the pluggable billing payment provider (`billing/`).
- `api/routers/` — FastAPI routers; translate domain exceptions to HTTP status codes here
  (e.g. `KeyError` → 404, `PlanLimitExceededError` → 402, `RepositoryNotReadyError` → 409).
- `ui/` — static HTML/JS dashboard (`/ui/`) and marketing landing page (`/`). No build step.

## Build and Test

```bash
cd backend
uv run pytest -q          # full suite must pass before considering work done
uv run ruff check src tests
.venv/bin/uvicorn security_review.main:app --host 0.0.0.0 --port 8000  # no --reload; restart after code changes
```

## Conventions

- **Security agents** (`infrastructure/scanners/*.py`) implement `Agent.execute(target, *,
  authorized: bool = False) -> list[Finding]` (see `core/agent.py`). `Finding` always has
  `title`/`severity`/`description`/`evidence`/`remediation`. New agent types are registered
  in `AgentFactory` and the `AgentType` enum (`domain/assessment/models.py`).
- **Active/intrusive testing** (crawling, injection probes, rate-limit bursts, JWT tampering,
  live port/endpoint probing) must be gated behind `authorized` — only run when the caller
  passes `target_authorization_confirmed: true` on the scan job. Passive/static-analysis
  checks should run unconditionally.
- **Multi-tenancy**: every resource is scoped by `organization_id`. Authentication is
  required on every assessment/billing/audit endpoint (`get_current_organization_id`
  requires a valid bearer token — there is no anonymous/legacy-organization fallback).
  `NIL_ORGANIZATION_ID` (all-zero UUID) still exists as a domain-model default/sentinel
  value but is no longer reachable from the API.
- **Billing**: plan limits live in `domain/billing/models.py` (`PLAN_CATALOG`). Payment
  processing goes through the pluggable `PaymentProvider` abstraction
  (`infrastructure/billing/payment_provider.py`) — `MockPaymentProvider` (default) activates
  plans instantly with no real payment; `StripePaymentProvider` is a real integration (Checkout
  Sessions + `POST /billing/webhooks/stripe`) requiring `STRIPE_SECRET_KEY`/`STRIPE_PRICE_ID_PRO`/
  `STRIPE_WEBHOOK_SECRET` — never hardcode a real processor's logic inline, and unconfigured/real
  providers must fail loudly (`PaymentProviderError`), not silently grant access. Paid-plan
  activation is deferred (`SubscriptionResult.activated_immediately=False`) until the webhook
  confirms payment — don't persist a plan change before that.
- **Persistence is pluggable**: all three repositories (`sqlite_assessment_repository.py`,
  `sqlite_user_repository.py`, `sqlite_audit_log_repository.py` — names kept for backward
  compatibility) use SQLAlchemy Core against a shared engine from
  `infrastructure/persistence/database.py`. Defaults to a local SQLite file; set `DATABASE_URL`
  to run against Postgres instead — no other code changes needed. When adding a new table/query,
  write dialect-portable SQL (standard `ON CONFLICT ... DO UPDATE`, TEXT columns, no
  SQLite-only pragmas) and always split `CREATE TABLE` and any schema-inspection (`inspect(...)
  .get_columns(...)`) into separate `engine.begin()` blocks — Postgres won't see a table created
  in an uncommitted transaction.
- **Rate limiting is pluggable** too (`api/rate_limiter.py`): in-memory by default, or Redis
  (`REDIS_URL`) to share counters across multiple instances — falls back to in-memory with a
  logged warning if Redis is unreachable.
- **Secrets hardening**: `infrastructure/security/secrets_validation.py` runs at startup
  (`main.py`) and raises `InsecureConfigurationError` — refusing to boot — if
  `SECURITY_REVIEW_ENVIRONMENT=production` and `SECURITY_REVIEW_JWT_SECRET`/`_API_KEY`/
  `_WEBHOOK_SECRET` are missing, default, or too weak. It's a no-op outside production. When
  adding a new secret-backed env var, add a corresponding check there rather than trusting
  callers to set it correctly.
- **Password reset**: tokens are single-use, 30-minute-expiry, and stored as a SHA-256 hash
  (`infrastructure/security/password_hasher.py`'s `hash_token`/`verify_token` — deterministic,
  unlike the salted `hash_password`, so the token can be looked up by equality). Email delivery
  goes through the pluggable `EmailProvider` (`infrastructure/email/email_provider.py`):
  `ConsoleEmailProvider` (default) just logs the link; `SmtpEmailProvider` sends real mail via
  stdlib `smtplib`. `POST /auth/forgot-password` must always return the same generic response
  whether or not the email is registered (no user enumeration).
- **RBAC**: `UserRole` (`owner`/`admin`/`member`) is enforced via the `require_roles(*roles)`
  dependency factory (`api/dependencies.py`), applied per-route (see `billing.py`'s `/subscribe`
  — owner only — and `team.py`). Most endpoints stay open to any authenticated org member;
  only gate destructive/financial/team-management actions. `TeamService`
  (`application/team_service.py`) refuses to demote/remove an organization's last remaining
  owner (`LastOwnerError` → 409). Inviting a teammate reuses the password-reset token mechanism
  (creates the account with a random never-disclosed password, emails a "set password" link)
  rather than a separate invite-token system.
- **Tests**: prefer mocked/duck-typed `httpx` clients over real network calls (see
  `tests/test_black_box_agent.py`, `tests/test_api_security_agent.py` for the pattern).
  `backend/data/security_review.db` persists across local test runs (no per-test DB reset),
  so tests against the shared legacy org should not assume it starts empty.
- **No markdown docs** beyond `README.md` unless explicitly requested — update `README.md`
  when adding a user-facing capability (new agent finding type, endpoint, plan, env var).
