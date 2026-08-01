"""Structured JSON logging configuration.

Uses only the standard library (no extra dependency) so every log line — whether
from application code or third-party libraries — is emitted as a single JSON
object: easy to ingest into any log aggregator (CloudWatch, Datadog, ELK, etc.)
without extra parsing rules.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import UTC, datetime

_RESERVED_LOG_RECORD_ATTRS = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        # Include any extra= fields passed to the logger call (e.g. organization_id,
        # request_path) without duplicating the standard LogRecord attributes.
        for key, value in record.__dict__.items():
            if key not in _RESERVED_LOG_RECORD_ATTRS and key not in payload:
                payload[key] = value

        return json.dumps(payload, default=str)


def configure_logging() -> None:
    """Configure root logging to emit structured JSON to stdout.

    Level is controlled by SECURITY_REVIEW_LOG_LEVEL (default INFO). Idempotent —
    safe to call multiple times (e.g. once per worker/import).
    """
    level_name = os.getenv("SECURITY_REVIEW_LOG_LEVEL", "INFO").strip().upper()
    level = getattr(logging, level_name, logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Replace any existing handlers (e.g. uvicorn's default) so every log line goes
    # through the same JSON formatter.
    root_logger.handlers.clear()

    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(JsonFormatter())
    root_logger.addHandler(handler)

    # Keep uvicorn's access/error loggers flowing through the same JSON handler
    # instead of their own default formatters.
    for logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(logger_name)
        logger.handlers.clear()
        logger.propagate = True
