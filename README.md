# security-review-ai

## Run locally

```bash
cd backend
.venv/bin/uvicorn security_review.main:app --host 0.0.0.0 --port 8000
```

## Run with Docker Compose

```bash
docker compose up --build
```

Then open http://localhost:8000/ui/.

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

Requests made **without** a bearer token fall back to a shared "legacy" organization, preserving
the original single-tenant demo behavior (used by the dashboard UI and existing API consumers).
This means: authenticated users get full data isolation from each other, while unauthenticated
usage continues to work exactly as before.

`/auth/login` and `/auth/signup` are rate-limited per client IP (in-memory, single-process) to
mitigate brute-force/credential-stuffing attempts: 10 login attempts and 5 signups per 60-second
window by default. Exceeding the limit returns `429 Too Many Requests` with a `Retry-After` header.
Tune with `SECURITY_REVIEW_LOGIN_RATE_LIMIT`, `SECURITY_REVIEW_LOGIN_RATE_WINDOW_SECONDS`,
`SECURITY_REVIEW_SIGNUP_RATE_LIMIT`, and `SECURITY_REVIEW_SIGNUP_RATE_WINDOW_SECONDS`.

## Deleting assessments and repositories

```bash
# Delete a repository (also removes its cloned copy from disk)
curl -X DELETE http://127.0.0.1:8000/assessments/{id}/repositories/{repository_id}

# Delete an assessment (also cleans up any repositories it ingested)
curl -X DELETE http://127.0.0.1:8000/assessments/{id}
```

Both return `204 No Content` on success and `404` if the resource doesn't exist or isn't visible
to the caller's organization.

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