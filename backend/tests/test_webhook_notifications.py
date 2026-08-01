import hashlib
import hmac
import json
from unittest.mock import patch

from fastapi.testclient import TestClient

from security_review.main import app


def test_scan_job_webhook_is_called_on_completion() -> None:
    client = TestClient(app)

    assessment_response = client.post(
        "/assessments",
        json={"name": "Webhook review", "description": "Test webhook notification"},
    )
    assert assessment_response.status_code == 201
    assessment_id = assessment_response.json()["id"]

    with patch("security_review.application.assessment_service.httpx.post") as mock_post:
        scan_response = client.post(
            f"/assessments/{assessment_id}/scan-jobs",
            json={
                "agent_type": "white_box",
                "target": "/workspaces/security-review-ai/backend/src",
                "webhook_url": "https://example.com/webhook",
            },
        )
        assert scan_response.status_code == 201

        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert call_args[0][0] == "https://example.com/webhook"
        payload = json.loads(call_args[1]["content"])
        assert payload["status"] == "completed"
        assert "findings" in payload
        # No secret configured in test environment, so no signature header expected.
        assert "X-Signature-256" not in call_args[1]["headers"]


def test_scan_job_without_webhook_url_does_not_call_httpx() -> None:
    client = TestClient(app)

    assessment_response = client.post(
        "/assessments",
        json={"name": "No webhook review", "description": "Test without webhook"},
    )
    assert assessment_response.status_code == 201
    assessment_id = assessment_response.json()["id"]

    with patch("security_review.application.assessment_service.httpx.post") as mock_post:
        scan_response = client.post(
            f"/assessments/{assessment_id}/scan-jobs",
            json={"agent_type": "white_box", "target": "/workspaces/security-review-ai/backend/src"},
        )
        assert scan_response.status_code == 201
        mock_post.assert_not_called()


def test_trivy_scan_webhook_is_called_on_completion() -> None:
    client = TestClient(app)

    assessment_response = client.post(
        "/assessments",
        json={"name": "Trivy webhook review", "description": "Test trivy webhook"},
    )
    assert assessment_response.status_code == 201
    assessment_id = assessment_response.json()["id"]

    with patch("security_review.application.assessment_service.httpx.post") as mock_post:
        scan_response = client.post(
            f"/assessments/{assessment_id}/trivy-scan",
            json={
                "target": "/workspaces/security-review-ai/backend/src",
                "webhook_url": "https://example.com/trivy-webhook",
            },
        )
        assert scan_response.status_code == 200
        mock_post.assert_called_once()
        assert mock_post.call_args[0][0] == "https://example.com/trivy-webhook"


def test_webhook_payload_is_signed_when_secret_configured(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_REVIEW_WEBHOOK_SECRET", "top-secret")
    client = TestClient(app)

    assessment_response = client.post(
        "/assessments",
        json={"name": "Signed webhook review", "description": "Test signed webhook"},
    )
    assert assessment_response.status_code == 201
    assessment_id = assessment_response.json()["id"]

    with patch("security_review.application.assessment_service.httpx.post") as mock_post:
        scan_response = client.post(
            f"/assessments/{assessment_id}/scan-jobs",
            json={
                "agent_type": "white_box",
                "target": "/workspaces/security-review-ai/backend/src",
                "webhook_url": "https://example.com/signed-webhook",
            },
        )
        assert scan_response.status_code == 201

        mock_post.assert_called_once()
        call_args = mock_post.call_args
        body = call_args[1]["content"]
        headers = call_args[1]["headers"]

        expected_signature = hmac.new(b"top-secret", body, hashlib.sha256).hexdigest()
        assert headers["X-Signature-256"] == f"sha256={expected_signature}"
