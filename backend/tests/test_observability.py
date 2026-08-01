import json
import logging

from fastapi.testclient import TestClient

from security_review.infrastructure.observability.error_tracking import init_error_tracking
from security_review.infrastructure.observability.logging_config import JsonFormatter
from security_review.main import app


def test_metrics_endpoint_is_public_and_exposes_http_metrics():
    client = TestClient(app)

    # Generate at least one request so a metric sample exists.
    client.get("/health")

    response = client.get("/metrics")
    assert response.status_code == 200
    assert "vigil_http_requests_total" in response.text
    assert "vigil_scan_jobs_total" in response.text


def test_health_endpoint_still_works_with_observability_middleware():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_json_formatter_produces_valid_json_with_expected_fields():
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="test.logger",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello %s",
        args=("world",),
        exc_info=None,
    )
    formatted = formatter.format(record)
    parsed = json.loads(formatted)

    assert parsed["level"] == "INFO"
    assert parsed["logger"] == "test.logger"
    assert parsed["message"] == "hello world"
    assert "timestamp" in parsed


def test_init_error_tracking_is_noop_without_dsn(monkeypatch):
    monkeypatch.delenv("SECURITY_REVIEW_SENTRY_DSN", raising=False)

    import security_review.infrastructure.observability.error_tracking as error_tracking_module

    error_tracking_module._initialized = False

    assert init_error_tracking() is False
