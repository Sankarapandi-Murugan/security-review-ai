import importlib

from fastapi.testclient import TestClient

import security_review.main as main_module
from tests._auth_helpers import signup_headers


def test_health_endpoint() -> None:
    routes = {getattr(route, "path", None) for route in main_module.app.router.routes}

    assert "/health" in routes
    assert "/livez" in routes
    assert "/readyz" in routes


def test_liveness_and_readiness_endpoints_are_clean_in_default_env() -> None:
    client = TestClient(main_module.app)

    liveness = client.get("/livez")
    readiness = client.get("/readyz")

    assert liveness.status_code == 200
    assert readiness.status_code == 200


def test_health_degrades_gracefully_when_startup_validation_fails(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_REVIEW_ENVIRONMENT", "production")
    monkeypatch.delenv("SECURITY_REVIEW_JWT_SECRET", raising=False)

    reloaded_module = importlib.reload(main_module)
    client = TestClient(reloaded_module.app)

    response = client.get("/health")

    assert response.status_code == 503
    assert response.json()["status"] == "degraded"


def test_auth_required_when_enabled(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_REVIEW_AUTH_REQUIRED", "true")
    monkeypatch.setenv("SECURITY_REVIEW_API_KEY", "test-key")

    client = TestClient(main_module.app)
    # /auth/* is exempt from the API-key middleware, so signup still works.
    auth_headers = signup_headers(client)

    unauthorized_response = client.get("/assessments")
    assert unauthorized_response.status_code == 401

    # Both the API key (middleware) and a bearer token (organization scoping) are required.
    authorized_response = client.get(
        "/assessments", headers={"x-api-key": "test-key", **auth_headers}
    )
    assert authorized_response.status_code == 200
