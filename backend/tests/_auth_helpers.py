"""Shared test helper: sign up a fresh organization/user and return auth headers.

Now that all assessment/billing/audit endpoints require authentication (no more
anonymous "legacy organization" fallback), most tests need a signed-up user.
"""

import uuid

from fastapi.testclient import TestClient


def signup_headers(client: TestClient, organization_name: str = "Test org") -> dict[str, str]:
    email = f"user-{uuid.uuid4().hex}@example.com"
    response = client.post(
        "/auth/signup",
        json={"organization_name": organization_name, "email": email, "password": "supersecret123"},
    )
    assert response.status_code == 201, response.text
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
