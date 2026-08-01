import uuid

from fastapi.testclient import TestClient

from security_review.main import app


def _signup(client: TestClient) -> tuple[str, str]:
    email = f"user-{uuid.uuid4().hex}@example.com"
    response = client.post(
        "/auth/signup",
        json={"organization_name": "Audit org", "email": email, "password": "supersecret123"},
    )
    assert response.status_code == 201
    return response.json()["access_token"], email


def test_authorized_scan_job_is_recorded_in_consent_audit_log():
    client = TestClient(app)
    token, email = _signup(client)
    headers = {"Authorization": f"Bearer {token}"}

    assessment = client.post("/assessments", json={"name": "Audit trail review"}, headers=headers)
    assert assessment.status_code == 201
    assessment_id = assessment.json()["id"]

    scan = client.post(
        f"/assessments/{assessment_id}/scan-jobs",
        json={
            "agent_type": "black_box",
            "target": "https://example.com",
            "target_authorization_confirmed": True,
        },
        headers=headers,
    )
    assert scan.status_code == 201
    scan_job = scan.json()
    assert scan_job["target_authorization_confirmed"] is True
    assert scan_job["authorized_by"] == email
    assert scan_job["authorized_at"] is not None

    audit_log = client.get("/audit/consent-log", headers=headers)
    assert audit_log.status_code == 200
    entries = audit_log.json()
    assert len(entries) == 1
    assert entries[0]["scan_job_id"] == scan_job["id"]
    assert entries[0]["confirmed_by"] == email
    assert entries[0]["agent_type"] == "black_box"
    assert entries[0]["target"] == "https://example.com"


def test_unconfirmed_scan_job_is_not_recorded_in_audit_log():
    client = TestClient(app)
    token, _email = _signup(client)
    headers = {"Authorization": f"Bearer {token}"}

    assessment = client.post("/assessments", json={"name": "No consent review"}, headers=headers)
    assessment_id = assessment.json()["id"]

    scan = client.post(
        f"/assessments/{assessment_id}/scan-jobs",
        json={"agent_type": "white_box", "target": "requirements.txt"},
        headers=headers,
    )
    assert scan.status_code == 201
    assert scan.json()["authorized_by"] is None

    audit_log = client.get("/audit/consent-log", headers=headers)
    assert audit_log.json() == []


def test_anonymous_scan_job_creation_requires_login():
    client = TestClient(app)

    assessment = client.post("/assessments", json={"name": f"Anon audit {uuid.uuid4().hex}"})
    assert assessment.status_code == 401
