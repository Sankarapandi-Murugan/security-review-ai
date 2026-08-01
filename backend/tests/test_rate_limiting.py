import uuid

from fastapi.testclient import TestClient

from security_review.main import app


def test_login_returns_429_after_rate_limit_exceeded() -> None:
    client = TestClient(app)
    email = f"user-{uuid.uuid4().hex}@example.com"

    for _ in range(10):
        response = client.post("/auth/login", json={"email": email, "password": "wrong-password"})
        assert response.status_code == 401

    limited_response = client.post("/auth/login", json={"email": email, "password": "wrong-password"})
    assert limited_response.status_code == 429
    assert "Retry-After" in limited_response.headers


def test_signup_returns_429_after_rate_limit_exceeded() -> None:
    client = TestClient(app)

    for _ in range(5):
        response = client.post(
            "/auth/signup",
            json={
                "organization_name": "Rate limit org",
                "email": f"user-{uuid.uuid4().hex}@example.com",
                "password": "supersecret123",
            },
        )
        assert response.status_code == 201

    limited_response = client.post(
        "/auth/signup",
        json={
            "organization_name": "Rate limit org",
            "email": f"user-{uuid.uuid4().hex}@example.com",
            "password": "supersecret123",
        },
    )
    assert limited_response.status_code == 429
    assert "Retry-After" in limited_response.headers


def test_login_and_signup_rate_limits_are_independent() -> None:
    client = TestClient(app)
    email = f"user-{uuid.uuid4().hex}@example.com"

    for _ in range(10):
        response = client.post("/auth/login", json={"email": email, "password": "wrong-password"})
        assert response.status_code == 401

    # Exhausting the login limiter must not affect the signup limiter.
    signup_response = client.post(
        "/auth/signup",
        json={
            "organization_name": "Independent limiter org",
            "email": f"user-{uuid.uuid4().hex}@example.com",
            "password": "supersecret123",
        },
    )
    assert signup_response.status_code == 201
