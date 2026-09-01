import logging
import os
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
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

logger = logging.getLogger(__name__)


def _startup_validation_error() -> Exception | None:
    """Return the current startup validation error for the active environment."""
    try:
        validate_production_secrets()
    except Exception as exc:  # pragma: no cover - exercised via health checks in tests
        logger.critical("Application startup validation failed; service will remain degraded.", exc_info=exc)
        return exc
    return None


def _run_startup_validation() -> None:
    """Persist the latest startup validation result on the app state."""
    if hasattr(app, "state"):
        app.state.startup_error = _startup_validation_error()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Validate configuration during startup without crashing the process."""
    logger.info(
        "Starting Vigil AI",
        extra={
            "environment": os.getenv("SECURITY_REVIEW_ENVIRONMENT", "development"),
            "auth_required": os.getenv("SECURITY_REVIEW_AUTH_REQUIRED", "false"),
            "log_level": os.getenv("SECURITY_REVIEW_LOG_LEVEL", "INFO"),
        },
    )
    _run_startup_validation()
    if app.state.startup_error is not None:
        logger.warning("Application started in degraded mode due to startup validation failure.")
    else:
        logger.info("Startup validation passed; application ready to serve traffic.")
    yield


app = FastAPI(title="Vigil AI", description="Autonomous AI security engineers.", lifespan=lifespan)
_run_startup_validation()

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


@app.get("/livez", include_in_schema=False)
def liveness() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/readyz", include_in_schema=False)
def readiness() -> Response:
    app.state.startup_error = _startup_validation_error()
    if app.state.startup_error is not None:
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "detail": str(app.state.startup_error),
            },
        )
    return JSONResponse({"status": "ready"})


@app.get("/health")
def health():
    app.state.startup_error = _startup_validation_error()
    if app.state.startup_error is not None:
        return JSONResponse(
            status_code=503,
            content={
                "status": "degraded",
                "detail": str(app.state.startup_error),
            },
        )
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