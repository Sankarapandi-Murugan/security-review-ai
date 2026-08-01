from fastapi.testclient import TestClient

from security_review.main import app


def test_assessment_can_accept_scan_jobs() -> None:
    client = TestClient(app)

    assessment_response = client.post(
        "/assessments",
        json={"name": "Quarterly review", "description": "Autonomous security assessment"},
    )
    assert assessment_response.status_code == 201
    assessment_id = assessment_response.json()["id"]

    scan_response = client.post(
        f"/assessments/{assessment_id}/scan-jobs",
        json={"agent_type": "white_box", "target": "/workspaces/security-review-ai/backend/src"},
    )
    assert scan_response.status_code == 201
    scan_job = scan_response.json()
    assert scan_job["status"] == "pending"
    assert scan_job["name"] == "white_box scan"

    detail_response = client.get(f"/assessments/{assessment_id}")
    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert len(detail["scan_jobs"]) == 1
    # Real Bandit scanner finds multiple findings
    assert len(detail["findings"]) > 0


def test_multiple_scan_jobs_are_allowed_for_completed_assessments() -> None:
    client = TestClient(app)

    assessment_response = client.post(
        "/assessments",
        json={"name": "Repeat scan review", "description": "Test repeated scans"},
    )
    assert assessment_response.status_code == 201
    assessment_id = assessment_response.json()["id"]

    first_scan_response = client.post(
        f"/assessments/{assessment_id}/scan-jobs",
        json={"agent_type": "white_box", "target": "/workspaces/security-review-ai/backend/src"},
    )
    assert first_scan_response.status_code == 201

    second_scan_response = client.post(
        f"/assessments/{assessment_id}/scan-jobs",
        json={"agent_type": "blue_team", "target": "/workspaces/security-review-ai/backend/src"},
    )
    assert second_scan_response.status_code == 201

    detail_response = client.get(f"/assessments/{assessment_id}")
    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert len(detail["scan_jobs"]) == 2
    # Real scanners produce findings
    assert len(detail["findings"]) > 0
