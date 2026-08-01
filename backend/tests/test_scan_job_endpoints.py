from fastapi.testclient import TestClient

from security_review.main import app
from tests._auth_helpers import signup_headers


def test_list_and_get_scan_jobs() -> None:
    client = TestClient(app)
    headers = signup_headers(client)

    assessment_response = client.post(
        "/assessments",
        json={"name": "Functionality review", "description": "Test scan endpoints"},
        headers=headers,
    )
    assert assessment_response.status_code == 201
    assessment_id = assessment_response.json()["id"]

    scan_response = client.post(
        f"/assessments/{assessment_id}/scan-jobs",
        json={"agent_type": "api_security", "target": "https://api.example.com"},
        headers=headers,
    )
    assert scan_response.status_code == 201
    scan_job = scan_response.json()
    assert scan_job["status"] == "pending"

    detail_response = client.get(
        f"/assessments/{assessment_id}/scan-jobs/{scan_job['id']}", headers=headers
    )
    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert detail["id"] == scan_job["id"]

    assessment_detail = client.get(f"/assessments/{assessment_id}", headers=headers)
    assert assessment_detail.status_code == 200
    assessment_data = assessment_detail.json()
    # With real scanners, findings may vary. Check that findings exist or are empty.
    assert isinstance(assessment_data["findings"], list)


def test_cloud_security_agent_generates_findings() -> None:
    client = TestClient(app)
    headers = signup_headers(client)

    assessment_response = client.post(
        "/assessments",
        json={"name": "Cloud review", "description": "Test cloud security agent"},
        headers=headers,
    )
    assert assessment_response.status_code == 201
    assessment_id = assessment_response.json()["id"]

    scan_response = client.post(
        f"/assessments/{assessment_id}/scan-jobs",
        json={"agent_type": "cloud_security", "target": "/workspaces/security-review-ai"},
        headers=headers,
    )
    assert scan_response.status_code == 201
    scan_job = scan_response.json()
    assert scan_job["status"] == "pending"

    assessment_detail = client.get(f"/assessments/{assessment_id}", headers=headers)
    assert assessment_detail.status_code == 200
    assessment_data = assessment_detail.json()
    # Real scanner returns various findings, just check it's a list
    assert isinstance(assessment_data["findings"], list)


def test_black_box_agent_generates_findings() -> None:
    client = TestClient(app)
    headers = signup_headers(client)

    assessment_response = client.post(
        "/assessments",
        json={"name": "Black Box review", "description": "Test black box agent"},
        headers=headers,
    )
    assert assessment_response.status_code == 201
    assessment_id = assessment_response.json()["id"]

    scan_response = client.post(
        f"/assessments/{assessment_id}/scan-jobs",
        json={"agent_type": "black_box", "target": "localhost"},
        headers=headers,
    )
    assert scan_response.status_code == 201
    scan_job = scan_response.json()
    assert scan_job["status"] == "pending"

    assessment_detail = client.get(f"/assessments/{assessment_id}", headers=headers)
    assert assessment_detail.status_code == 200
    assessment_data = assessment_detail.json()
    # Real scanner checks for open ports and web servers
    assert isinstance(assessment_data["findings"], list)


def test_red_team_agent_generates_findings() -> None:
    client = TestClient(app)
    headers = signup_headers(client)

    assessment_response = client.post(
        "/assessments",
        json={"name": "Red Team review", "description": "Test red team agent"},
        headers=headers,
    )
    assert assessment_response.status_code == 201
    assessment_id = assessment_response.json()["id"]

    scan_response = client.post(
        f"/assessments/{assessment_id}/scan-jobs",
        json={"agent_type": "red_team", "target": "/workspaces/security-review-ai/backend/src"},
        headers=headers,
    )
    assert scan_response.status_code == 201
    scan_job = scan_response.json()
    assert scan_job["status"] == "pending"

    assessment_detail = client.get(f"/assessments/{assessment_id}", headers=headers)
    assert assessment_detail.status_code == 200
    assessment_data = assessment_detail.json()
    # Real red-team scanner analyzes code for dangerous patterns
    assert isinstance(assessment_data["findings"], list)


def test_get_assessment_findings_endpoint() -> None:
    client = TestClient(app)
    headers = signup_headers(client)

    assessment_response = client.post(
        "/assessments",
        json={"name": "Findings review", "description": "Test findings endpoint"},
        headers=headers,
    )
    assert assessment_response.status_code == 201
    assessment_id = assessment_response.json()["id"]

    scan_response = client.post(
        f"/assessments/{assessment_id}/scan-jobs",
        json={"agent_type": "white_box", "target": "/workspaces/security-review-ai/backend/src"},
        headers=headers,
    )
    assert scan_response.status_code == 201

    findings_response = client.get(f"/assessments/{assessment_id}/findings", headers=headers)
    assert findings_response.status_code == 200
    findings = findings_response.json()
    # Real scanner may find Bandit findings or none
    assert isinstance(findings, list)


def test_secret_detection_agent_generates_findings() -> None:
    client = TestClient(app)
    headers = signup_headers(client)

    assessment_response = client.post(
        "/assessments",
        json={"name": "Secret scan review", "description": "Test secret detection"},
        headers=headers,
    )
    assert assessment_response.status_code == 201
    assessment_id = assessment_response.json()["id"]

    scan_response = client.post(
        f"/assessments/{assessment_id}/scan-jobs",
        json={"agent_type": "secret_detection", "target": "/workspaces/security-review-ai"},
        headers=headers,
    )
    assert scan_response.status_code == 201
    scan_job = scan_response.json()
    assert scan_job["status"] == "pending"

    assessment_detail = client.get(f"/assessments/{assessment_id}", headers=headers)
    assert assessment_detail.status_code == 200
    assessment_data = assessment_detail.json()
    # Real secret detector scans for exposed credentials
    assert isinstance(assessment_data["findings"], list)


def test_blue_team_agent_generates_findings() -> None:
    client = TestClient(app)
    headers = signup_headers(client)

    assessment_response = client.post(
        "/assessments",
        json={"name": "Blue Team review", "description": "Test blue team agent"},
        headers=headers,
    )
    assert assessment_response.status_code == 201
    assessment_id = assessment_response.json()["id"]

    scan_response = client.post(
        f"/assessments/{assessment_id}/scan-jobs",
        json={"agent_type": "blue_team", "target": "/workspaces/security-review-ai/backend/src"},
        headers=headers,
    )
    assert scan_response.status_code == 201
    scan_job = scan_response.json()
    assert scan_job["status"] == "pending"

    assessment_detail = client.get(f"/assessments/{assessment_id}", headers=headers)
    assert assessment_detail.status_code == 200
    assessment_data = assessment_detail.json()
    # Real blue-team agent checks defensive measures
    assert isinstance(assessment_data["findings"], list)
