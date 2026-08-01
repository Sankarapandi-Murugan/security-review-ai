from fastapi.testclient import TestClient

from security_review.main import app
from tests._auth_helpers import signup_headers


def test_assessment_report_includes_summary_metrics() -> None:
    client = TestClient(app)
    headers = signup_headers(client)

    assessment_response = client.post(
        "/assessments",
        json={"name": "Executive report", "description": "Test report generation"},
        headers=headers,
    )
    assert assessment_response.status_code == 201
    assessment_id = assessment_response.json()["id"]

    scan_response = client.post(
        f"/assessments/{assessment_id}/scan-jobs",
        json={"agent_type": "dependency_security", "target": "requirements.txt"},
        headers=headers,
    )
    assert scan_response.status_code == 201

    report_response = client.get(f"/assessments/{assessment_id}/report", headers=headers)
    assert report_response.status_code == 200
    report = report_response.json()
    assert report["assessment_id"] == assessment_id
    assert report["finding_count"] >= 1
    assert report["severity_counts"]["critical"] >= 1
    assert report["recommendations"].__len__() >= 1


def test_ui_root_serves_dashboard() -> None:
    client = TestClient(app)

    response = client.get("/ui/")
    assert response.status_code == 200
    assert "Security Review AI Dashboard" in response.text
