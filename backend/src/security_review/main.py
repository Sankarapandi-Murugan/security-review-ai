import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.requests import Request
from starlette.responses import JSONResponse

from security_review.api.routers import assessment_router, auth_router

app = FastAPI(title="Security Review AI")


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
async def enforce_api_key(request: Request, call_next):
    if request.url.path in {"/health", "/docs", "/openapi.json", "/redoc"} or request.url.path.startswith(
        "/auth"
    ):
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


app.include_router(auth_router)
app.include_router(assessment_router)

ui_dir = Path(__file__).resolve().parent / "ui"
app.mount("/ui", StaticFiles(directory=str(ui_dir), html=True), name="ui")