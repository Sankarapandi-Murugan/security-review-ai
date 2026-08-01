from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from uuid import UUID

from security_review.domain.assessment.models import Assessment


class SqliteAssessmentRepository:
    def __init__(self, db_path: str | Path = "data/security_review.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

    def initialize(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS assessments (
                id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        # Backfill the organization_id column for databases created before multi-tenancy.
        try:
            self._conn.execute(
                "ALTER TABLE assessments ADD COLUMN organization_id TEXT NOT NULL "
                "DEFAULT '00000000-0000-0000-0000-000000000000'"
            )
        except sqlite3.OperationalError:
            pass  # Column already exists.
        self._conn.commit()

    def save(self, assessment: Assessment) -> None:
        payload = json.dumps(assessment.to_dict())
        self._conn.execute(
            """
            INSERT INTO assessments (id, organization_id, payload, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at
            """,
            [
                str(assessment.id),
                str(assessment.organization_id),
                payload,
                assessment.created_at.isoformat(),
                assessment.updated_at.isoformat(),
            ],
        )
        self._conn.commit()

    def get(self, assessment_id: UUID, organization_id: UUID | None = None) -> Assessment:
        row = self._conn.execute(
            "SELECT payload FROM assessments WHERE id = ?",
            [str(assessment_id)],
        ).fetchone()
        if row is None:
            raise KeyError(assessment_id)

        assessment = Assessment.from_dict(json.loads(row["payload"]))
        if organization_id is not None and assessment.organization_id != organization_id:
            raise KeyError(assessment_id)

        return assessment

    def list(
        self,
        organization_id: UUID | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[Assessment]:
        query = "SELECT payload FROM assessments"
        params: list[str] = []
        if organization_id is not None:
            query += " WHERE organization_id = ?"
            params.append(str(organization_id))
        query += " ORDER BY created_at DESC, id DESC"
        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            params.extend([str(limit), str(offset)])
        rows = self._conn.execute(query, params).fetchall()
        return [Assessment.from_dict(json.loads(row["payload"])) for row in rows]

    def count(self, organization_id: UUID | None = None) -> int:
        if organization_id is not None:
            row = self._conn.execute(
                "SELECT COUNT(*) AS total FROM assessments WHERE organization_id = ?",
                [str(organization_id)],
            ).fetchone()
        else:
            row = self._conn.execute("SELECT COUNT(*) AS total FROM assessments").fetchone()
        return int(row["total"])

    def delete(self, assessment_id: UUID, organization_id: UUID | None = None) -> Assessment:
        """Delete an assessment and return the deleted record (for cleanup of on-disk state)."""
        assessment = self.get(assessment_id, organization_id)
        self._conn.execute("DELETE FROM assessments WHERE id = ?", [str(assessment_id)])
        self._conn.commit()
        return assessment

    def close(self) -> None:
        self._conn.close()

