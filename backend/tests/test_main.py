from fastapi.testclient import TestClient

from security_review.main import app


def test_health_endpoint() -> None:
    routes = {getattr(route, "path", None) for route in app.router.routes}

    assert "/health" in routes


def test_auth_required_when_enabled(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_REVIEW_AUTH_REQUIRED", "true")
    monkeypatch.setenv("SECURITY_REVIEW_API_KEY", "test-key")

    client = TestClient(app)

    unauthorized_response = client.get("/assessments")
    assert unauthorized_response.status_code == 401

    authorized_response = client.get("/assessments", headers={"x-api-key": "test-key"})
    assert authorized_response.status_code == 200
