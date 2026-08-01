import json

from fastapi.testclient import TestClient

from security_review.main import app


def test_stream_scan_job_status_returns_final_event() -> None:
    client = TestClient(app)

    assessment_response = client.post(
        "/assessments",
        json={"name": "Stream review", "description": "Test SSE scan status"},
    )
    assert assessment_response.status_code == 201
    assessment_id = assessment_response.json()["id"]

    scan_response = client.post(
        f"/assessments/{assessment_id}/scan-jobs",
        json={"agent_type": "white_box", "target": "/workspaces/security-review-ai/backend/src"},
    )
    assert scan_response.status_code == 201
    scan_job_id = scan_response.json()["id"]

    with client.stream(
        "GET", f"/assessments/{assessment_id}/scan-jobs/{scan_job_id}/stream"
    ) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")

        events = []
        for line in response.iter_lines():
            if line.startswith("data:"):
                events.append(json.loads(line[len("data:"):].strip()))

    assert len(events) >= 1
    assert events[-1]["status"] in ("completed", "failed")
    assert events[-1]["id"] == scan_job_id


def test_stream_scan_job_status_returns_404_for_unknown_job() -> None:
    client = TestClient(app)

    assessment_response = client.post(
        "/assessments",
        json={"name": "Stream 404 review", "description": "Test SSE 404"},
    )
    assert assessment_response.status_code == 201
    assessment_id = assessment_response.json()["id"]

    unknown_scan_job_id = "00000000-0000-0000-0000-000000000000"
    response = client.get(
        f"/assessments/{assessment_id}/scan-jobs/{unknown_scan_job_id}/stream"
    )
    assert response.status_code == 404
