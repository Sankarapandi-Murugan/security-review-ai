from __future__ import annotations

from datetime import datetime
from pathlib import Path
from uuid import UUID

from sqlalchemy import text

from security_review.domain.audit.models import ConsentAuditEntry
from security_review.infrastructure.persistence.database import get_engine


class SqliteAuditLogRepository:
    """Append-only log of authorization-consent confirmations for active scanning.

    Deliberately separate from the assessments table (which stores mutable JSON blobs
    that can be edited/deleted) so the audit trail survives assessment deletion.
    Backed by SQLite (local/dev/test) or Postgres in production (set ``DATABASE_URL``)
    via the shared SQLAlchemy engine.
    """

    def __init__(self, db_path: str | Path = "data/security_review.db") -> None:
        self.db_path = Path(db_path)
        self._engine = get_engine(str(self.db_path))

    def initialize(self) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS consent_audit_log (
                        id TEXT PRIMARY KEY,
                        organization_id TEXT NOT NULL,
                        assessment_id TEXT NOT NULL,
                        scan_job_id TEXT NOT NULL,
                        agent_type TEXT NOT NULL,
                        target TEXT NOT NULL,
                        confirmed_by TEXT NOT NULL,
                        confirmed_at TEXT NOT NULL
                    )
                    """
                )
            )

    def record(self, entry: ConsentAuditEntry) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO consent_audit_log
                        (id, organization_id, assessment_id, scan_job_id, agent_type, target, confirmed_by, confirmed_at)
                    VALUES (:id, :organization_id, :assessment_id, :scan_job_id, :agent_type, :target, :confirmed_by, :confirmed_at)
                    """
                ),
                {
                    "id": str(entry.id),
                    "organization_id": str(entry.organization_id),
                    "assessment_id": str(entry.assessment_id),
                    "scan_job_id": str(entry.scan_job_id),
                    "agent_type": entry.agent_type,
                    "target": entry.target,
                    "confirmed_by": entry.confirmed_by,
                    "confirmed_at": entry.confirmed_at.isoformat(),
                },
            )

    def list(self, organization_id: UUID, limit: int = 200) -> list[ConsentAuditEntry]:
        with self._engine.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT * FROM consent_audit_log WHERE organization_id = :organization_id "
                    "ORDER BY confirmed_at DESC LIMIT :limit"
                ),
                {"organization_id": str(organization_id), "limit": limit},
            ).mappings().all()
        return [self._row_to_entry(row) for row in rows]

    @staticmethod
    def _row_to_entry(row) -> ConsentAuditEntry:
        return ConsentAuditEntry(
            id=UUID(row["id"]),
            organization_id=UUID(row["organization_id"]),
            assessment_id=UUID(row["assessment_id"]),
            scan_job_id=UUID(row["scan_job_id"]),
            agent_type=row["agent_type"],
            target=row["target"],
            confirmed_by=row["confirmed_by"],
            confirmed_at=datetime.fromisoformat(row["confirmed_at"]),
        )

    def close(self) -> None:
        self._engine.dispose()

