import uuid

from fastapi.testclient import TestClient

from security_review.main import app


def _signup(client: TestClient) -> str:
    email = f"user-{uuid.uuid4().hex}@example.com"
    response = client.post(
        "/auth/signup",
        json={"organization_name": "Billing org", "email": email, "password": "supersecret123"},
    )
    assert response.status_code == 201
    return response.json()["access_token"]


def test_list_plans_is_public():
    client = TestClient(app)
    response = client.get("/billing/plans")

    assert response.status_code == 200
    tiers = {plan["tier"] for plan in response.json()}
    assert tiers == {"free", "pro", "enterprise"}


def test_new_organization_defaults_to_free_plan_and_reports_usage():
    client = TestClient(app)
    token = _signup(client)
    headers = {"Authorization": f"Bearer {token}"}

    usage = client.get("/billing/usage", headers=headers)

    assert usage.status_code == 200
    body = usage.json()
    assert body["plan"]["tier"] == "free"
    assert body["assessments_used"] == 0
    assert body["scan_jobs_used"] == 0


def test_free_plan_blocks_assessment_creation_past_limit():
    client = TestClient(app)
    token = _signup(client)
    headers = {"Authorization": f"Bearer {token}"}

    for i in range(3):
        response = client.post(
            "/assessments", json={"name": f"Assessment {i}"}, headers=headers
        )
        assert response.status_code == 201

    over_limit = client.post("/assessments", json={"name": "Assessment 4"}, headers=headers)
    assert over_limit.status_code == 402


def test_subscribing_to_pro_raises_the_limit():
    client = TestClient(app)
    token = _signup(client)
    headers = {"Authorization": f"Bearer {token}"}

    for i in range(3):
        response = client.post(
            "/assessments", json={"name": f"Assessment {i}"}, headers=headers
        )
        assert response.status_code == 201

    upgrade = client.post("/billing/subscribe", json={"plan": "pro"}, headers=headers)
    assert upgrade.status_code == 200
    assert upgrade.json()["tier"] == "pro"

    now_allowed = client.post("/assessments", json={"name": "Assessment 4"}, headers=headers)
    assert now_allowed.status_code == 201

    usage = client.get("/billing/usage", headers=headers)
    assert usage.json()["plan"]["tier"] == "pro"
    assert usage.json()["assessments_used"] == 4


def test_unauthenticated_requests_require_login():
    client = TestClient(app)

    # There is no anonymous/legacy organization fallback anymore -- every
    # assessment/billing endpoint requires signing up or logging in first.
    response = client.post("/assessments", json={"name": f"Anon {uuid.uuid4().hex}"})
    assert response.status_code == 401
