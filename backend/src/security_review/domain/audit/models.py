"""Audit domain: an immutable trail of who confirmed authorization for active
(intrusive) security scanning of a target, and when.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import BaseModel


@dataclass
class ConsentAuditEntry:
    id: UUID = field(default_factory=uuid4)
    organization_id: UUID = field(default_factory=uuid4)
    assessment_id: UUID = field(default_factory=uuid4)
    scan_job_id: UUID = field(default_factory=uuid4)
    agent_type: str = ""
    target: str = ""
    confirmed_by: str = "unknown"
    confirmed_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class ConsentAuditEntryResponse(BaseModel):
    id: UUID
    organization_id: UUID
    assessment_id: UUID
    scan_job_id: UUID
    agent_type: str
    target: str
    confirmed_by: str
    confirmed_at: datetime
