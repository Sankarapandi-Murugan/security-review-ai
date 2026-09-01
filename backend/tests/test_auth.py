import uuid

from fastapi.testclient import TestClient

from security_review.main import app


def _unique_email() -> str:
    return f"user-{uuid.uuid4().hex}@example.com"


def test_signup_creates_organization_and_returns_token() -> None:
    client = TestClient(app)
    email = _unique_email()

    response = client.post(
        "/auth/signup",
        json={"organization_name": "Acme Inc", "email": email, "password": "supersecret123"},
    )

    assert response.status_code == 201
    body = response.json()
    assert body["access_token"]
    assert body["token_type"] == "bearer"
    assert body["user"]["email"] == email
    assert body["user"]["role"] == "owner"
    assert body["user"]["organization_id"]


def test_signup_rejects_duplicate_email() -> None:
    client = TestClient(app)
    email = _unique_email()

    first = client.post(
        "/auth/signup",
        json={"organization_name": "Acme Inc", "email": email, "password": "supersecret123"},
    )
    assert first.status_code == 201

    second = client.post(
        "/auth/signup",
        json={"organization_name": "Other Org", "email": email, "password": "anotherpassword"},
    )
    assert second.status_code == 409


def test_signup_rejects_blank_organization_name() -> None:
    client = TestClient(app)
    response = client.post(
        "/auth/signup",
        json={"organization_name": "", "email": _unique_email(), "password": "supersecret123"},
    )
    assert response.status_code == 422


def test_signup_rejects_invalid_email() -> None:
    client = TestClient(app)
    response = client.post(
        "/auth/signup",
        json={"organization_name": "Acme Inc", "email": "not-an-email", "password": "supersecret123"},
    )
    assert response.status_code == 422


def test_signup_rejects_short_password() -> None:
    client = TestClient(app)
    response = client.post(
        "/auth/signup",
        json={"organization_name": "Acme Inc", "email": _unique_email(), "password": "short"},
    )
    assert response.status_code == 422


def test_signup_round_trip_allows_me_and_login() -> None:
    client = TestClient(app)
    email = _unique_email()

    signup_response = client.post(
        "/auth/signup",
        json={"organization_name": "Round Trip Org", "email": email, "password": "supersecret123"},
    )
    assert signup_response.status_code == 201

    token = signup_response.json()["access_token"]
    me_response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_response.status_code == 200
    assert me_response.json()["email"] == email

    login_response = client.post(
        "/auth/login",
        json={"email": email, "password": "supersecret123"},
    )
    assert login_response.status_code == 200
    assert login_response.json()["user"]["email"] == email


def test_login_succeeds_with_correct_password() -> None:
    client = TestClient(app)
    email = _unique_email()
    client.post(
        "/auth/signup",
        json={"organization_name": "Acme Inc", "email": email, "password": "supersecret123"},
    )

    response = client.post("/auth/login", json={"email": email, "password": "supersecret123"})
    assert response.status_code == 200
    assert response.json()["access_token"]


def test_login_fails_with_wrong_password() -> None:
    client = TestClient(app)
    email = _unique_email()
    client.post(
        "/auth/signup",
        json={"organization_name": "Acme Inc", "email": email, "password": "supersecret123"},
    )

    response = client.post("/auth/login", json={"email": email, "password": "wrong-password"})
    assert response.status_code == 401


def test_login_fails_for_unknown_email() -> None:
    client = TestClient(app)
    response = client.post(
        "/auth/login", json={"email": _unique_email(), "password": "whatever123"}
    )
    assert response.status_code == 401


def test_me_requires_valid_token() -> None:
    client = TestClient(app)

    no_token_response = client.get("/auth/me")
    assert no_token_response.status_code == 401

    invalid_token_response = client.get("/auth/me", headers={"Authorization": "Bearer not-a-real-token"})
    assert invalid_token_response.status_code == 401


def test_me_returns_current_user_with_valid_token() -> None:
    client = TestClient(app)
    email = _unique_email()
    signup_response = client.post(
        "/auth/signup",
        json={"organization_name": "Acme Inc", "email": email, "password": "supersecret123"},
    )
    token = signup_response.json()["access_token"]

    response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["email"] == email
