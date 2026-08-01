import logging
import os
import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response

from security_review.api.routers import assessment_router, audit_router, auth_router, billing_router, team_router
from security_review.infrastructure.observability.error_tracking import (
    capture_exception,
    init_error_tracking,
)
from security_review.infrastructure.observability.logging_config import configure_logging
from security_review.infrastructure.observability.metrics import (
    HTTP_REQUEST_DURATION_SECONDS,
    HTTP_REQUESTS_TOTAL,
    UNHANDLED_EXCEPTIONS_TOTAL,
    render_metrics,
)
from security_review.infrastructure.security.secrets_validation import validate_production_secrets

configure_logging()
init_error_tracking()
validate_production_secrets()

logger = logging.getLogger(__name__)

app = FastAPI(title="Vigil AI", description="Autonomous AI security engineers.")

ui_dir = Path(__file__).resolve().parent / "ui"


def _auth_enabled() -> bool:
    return os.getenv("SECURITY_REVIEW_AUTH_REQUIRED", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _expected_api_key() -> str:
    return os.getenv("SECURITY_REVIEW_API_KEY", "demo-key")


@app.middleware("http")
async def observe_requests(request: Request, call_next):
    """Structured request logging + Prometheus metrics + unhandled-exception capture."""
    start = time.perf_counter()
    path = request.url.path
    method = request.method

    try:
        response = await call_next(request)
    except Exception as exc:
        duration = time.perf_counter() - start
        UNHANDLED_EXCEPTIONS_TOTAL.labels(path=path).inc()
        capture_exception(exc)
        logger.exception(
            "Unhandled exception while processing request",
            extra={"method": method, "path": path, "duration_ms": round(duration * 1000, 2)},
        )
        raise

    duration = time.perf_counter() - start
    HTTP_REQUESTS_TOTAL.labels(method=method, path=path, status_code=response.status_code).inc()
    HTTP_REQUEST_DURATION_SECONDS.labels(method=method, path=path).observe(duration)
    logger.info(
        "request completed",
        extra={
            "method": method,
            "path": path,
            "status_code": response.status_code,
            "duration_ms": round(duration * 1000, 2),
        },
    )
    return response


@app.middleware("http")
async def enforce_api_key(request: Request, call_next):
    if request.url.path in {
        "/",
        "/health",
        "/metrics",
        "/docs",
        "/openapi.json",
        "/redoc",
        "/billing/plans",
        "/billing/webhooks/stripe",
    } or request.url.path.startswith("/auth"):
        return await call_next(request)

    if not _auth_enabled():
        return await call_next(request)

    provided_key = request.headers.get("x-api-key")
    if provided_key != _expected_api_key():
        return JSONResponse(status_code=401, content={"detail": "Authentication required"})

    return await call_next(request)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/metrics", include_in_schema=False)
def metrics() -> Response:
    body, content_type = render_metrics()
    return Response(content=body, media_type=content_type)


@app.get("/", include_in_schema=False)
def landing_page() -> FileResponse:
    """Mission/marketing landing page — the functional dashboard lives at /ui/."""
    return FileResponse(str(ui_dir / "landing.html"))


app.include_router(auth_router)
app.include_router(assessment_router)
app.include_router(billing_router)
app.include_router(audit_router)
app.include_router(team_router)

app.mount("/ui", StaticFiles(directory=str(ui_dir), html=True), name="ui")