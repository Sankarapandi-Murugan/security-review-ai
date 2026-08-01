from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

from sqlalchemy import inspect, text

from security_review.domain.assessment.models import Assessment
from security_review.infrastructure.persistence.database import get_engine


class SqliteAssessmentRepository:
    """Assessment persistence, backed by SQLite (local/dev/test) or Postgres in
    production (set ``DATABASE_URL``) via the shared SQLAlchemy engine. The class
    name is kept for backward compatibility with existing imports/call sites.
    """

    def __init__(self, db_path: str | Path = "data/security_review.db") -> None:
        self.db_path = Path(db_path)
        self._engine = get_engine(str(self.db_path))

    def initialize(self) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                text(
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
            )

        # Separate, already-committed transaction: Postgres can't see the table
        # created above until that transaction commits, so inspecting it must happen
        # in a fresh connection/transaction afterward.
        with self._engine.begin() as conn:
            columns = {col["name"] for col in inspect(self._engine).get_columns("assessments")}
            if "organization_id" not in columns:
                conn.execute(
                    text(
                        "ALTER TABLE assessments ADD COLUMN organization_id TEXT NOT NULL "
                        "DEFAULT '00000000-0000-0000-0000-000000000000'"
                    )
                )

    def save(self, assessment: Assessment) -> None:
        payload = json.dumps(assessment.to_dict())
        with self._engine.begin() as conn:
            dialect = self._engine.dialect.name
            if dialect == "postgresql":
                upsert = """
                    INSERT INTO assessments (id, organization_id, payload, created_at, updated_at)
                    VALUES (:id, :organization_id, :payload, :created_at, :updated_at)
                    ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload, updated_at = EXCLUDED.updated_at
                """
            else:
                upsert = """
                    INSERT INTO assessments (id, organization_id, payload, created_at, updated_at)
                    VALUES (:id, :organization_id, :payload, :created_at, :updated_at)
                    ON CONFLICT(id) DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at
                """
            conn.execute(
                text(upsert),
                {
                    "id": str(assessment.id),
                    "organization_id": str(assessment.organization_id),
                    "payload": payload,
                    "created_at": assessment.created_at.isoformat(),
                    "updated_at": assessment.updated_at.isoformat(),
                },
            )

    def get(self, assessment_id: UUID, organization_id: UUID | None = None) -> Assessment:
        with self._engine.connect() as conn:
            row = conn.execute(
                text("SELECT payload FROM assessments WHERE id = :id"),
                {"id": str(assessment_id)},
            ).mappings().first()
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
        params: dict[str, object] = {}
        if organization_id is not None:
            query += " WHERE organization_id = :organization_id"
            params["organization_id"] = str(organization_id)
        query += " ORDER BY created_at DESC, id DESC"
        if limit is not None:
            query += " LIMIT :limit OFFSET :offset"
            params["limit"] = limit
            params["offset"] = offset

        with self._engine.connect() as conn:
            rows = conn.execute(text(query), params).mappings().all()
        return [Assessment.from_dict(json.loads(row["payload"])) for row in rows]

    def count(self, organization_id: UUID | None = None) -> int:
        query = "SELECT COUNT(*) AS total FROM assessments"
        params: dict[str, object] = {}
        if organization_id is not None:
            query += " WHERE organization_id = :organization_id"
            params["organization_id"] = str(organization_id)

        with self._engine.connect() as conn:
            row = conn.execute(text(query), params).mappings().first()
        return int(row["total"])

    def delete(self, assessment_id: UUID, organization_id: UUID | None = None) -> Assessment:
        """Delete an assessment and return the deleted record (for cleanup of on-disk state)."""
        assessment = self.get(assessment_id, organization_id)
        with self._engine.begin() as conn:
            conn.execute(text("DELETE FROM assessments WHERE id = :id"), {"id": str(assessment_id)})
        return assessment

    def close(self) -> None:
        self._engine.dispose()


