"""Prometheus metrics for HTTP requests and scan-job outcomes.

Exposed at GET /metrics in Prometheus text exposition format.
"""

from __future__ import annotations

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

HTTP_REQUESTS_TOTAL = Counter(
    "vigil_http_requests_total",
    "Total HTTP requests processed.",
    ["method", "path", "status_code"],
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "vigil_http_request_duration_seconds",
    "HTTP request duration in seconds.",
    ["method", "path"],
)

SCAN_JOBS_TOTAL = Counter(
    "vigil_scan_jobs_total",
    "Total scan jobs executed, by agent type and outcome.",
    ["agent_type", "status"],
)

FINDINGS_TOTAL = Counter(
    "vigil_findings_total",
    "Total findings produced by scan jobs, by severity.",
    ["severity"],
)

UNHANDLED_EXCEPTIONS_TOTAL = Counter(
    "vigil_unhandled_exceptions_total",
    "Total unhandled exceptions raised while processing a request.",
    ["path"],
)


def render_metrics() -> tuple[bytes, str]:
    """Return (body, content_type) for the /metrics endpoint."""
    return generate_latest(), CONTENT_TYPE_LATEST
