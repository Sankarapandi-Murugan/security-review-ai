from fastapi.testclient import TestClient

from security_review.main import app
from tests._auth_helpers import signup_headers


def test_health_endpoint() -> None:
    routes = {getattr(route, "path", None) for route in app.router.routes}

    assert "/health" in routes


def test_auth_required_when_enabled(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_REVIEW_AUTH_REQUIRED", "true")
    monkeypatch.setenv("SECURITY_REVIEW_API_KEY", "test-key")

    client = TestClient(app)
    # /auth/* is exempt from the API-key middleware, so signup still works.
    auth_headers = signup_headers(client)

    unauthorized_response = client.get("/assessments")
    assert unauthorized_response.status_code == 401

    # Both the API key (middleware) and a bearer token (organization scoping) are required.
    authorized_response = client.get(
        "/assessments", headers={"x-api-key": "test-key", **auth_headers}
    )
    assert authorized_response.status_code == 200
