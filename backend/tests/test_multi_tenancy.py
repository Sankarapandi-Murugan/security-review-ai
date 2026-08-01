import uuid

from fastapi.testclient import TestClient

from security_review.main import app


def _unique_email() -> str:
    return f"user-{uuid.uuid4().hex}@example.com"


def _signup(client: TestClient, org_name: str) -> str:
    email = _unique_email()
    response = client.post(
        "/auth/signup",
        json={"organization_name": org_name, "email": email, "password": "supersecret123"},
    )
    assert response.status_code == 201
    return response.json()["access_token"]


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_assessments_are_isolated_between_organizations() -> None:
    client = TestClient(app)
    token_a = _signup(client, "Org A")
    token_b = _signup(client, "Org B")

    create_response = client.post(
        "/assessments",
        json={"name": "Org A assessment", "description": "belongs to org A"},
        headers=_auth_headers(token_a),
    )
    assert create_response.status_code == 201
    assessment_id = create_response.json()["id"]

    # Org A can fetch its own assessment.
    own_response = client.get(f"/assessments/{assessment_id}", headers=_auth_headers(token_a))
    assert own_response.status_code == 200

    # Org B must not be able to see Org A's assessment.
    other_response = client.get(f"/assessments/{assessment_id}", headers=_auth_headers(token_b))
    assert other_response.status_code == 404

    # Org B's assessment list must not include Org A's assessment.
    list_response = client.get("/assessments", headers=_auth_headers(token_b))
    assert list_response.status_code == 200
    assert all(item["id"] != assessment_id for item in list_response.json())

    # Org A's assessment list does include it.
    own_list_response = client.get("/assessments", headers=_auth_headers(token_a))
    assert any(item["id"] == assessment_id for item in own_list_response.json())


def test_unauthenticated_requests_require_login() -> None:
    client = TestClient(app)

    # There is no anonymous/legacy organization fallback anymore -- every
    # assessment endpoint requires signing up or logging in first.
    create_response = client.post(
        "/assessments",
        json={"name": "No auth assessment", "description": "no auth token used"},
    )
    assert create_response.status_code == 401
