from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path
from uuid import UUID

from security_review.domain.auth.models import Organization, User, UserRole


class SqliteUserRepository:
    def __init__(self, db_path: str | Path = "data/security_review.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

    def initialize(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS organizations (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                hashed_password TEXT NOT NULL,
                organization_id TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def create_organization(self, organization: Organization) -> None:
        self._conn.execute(
            "INSERT INTO organizations (id, name, created_at) VALUES (?, ?, ?)",
            [str(organization.id), organization.name, organization.created_at.isoformat()],
        )
        self._conn.commit()

    def create_user(self, user: User) -> None:
        self._conn.execute(
            """
            INSERT INTO users (id, email, hashed_password, organization_id, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                str(user.id),
                user.email.lower(),
                user.hashed_password,
                str(user.organization_id),
                user.role.value,
                user.created_at.isoformat(),
            ],
        )
        self._conn.commit()

    def get_user_by_email(self, email: str) -> User | None:
        row = self._conn.execute(
            "SELECT * FROM users WHERE email = ?", [email.lower()]
        ).fetchone()
        return self._row_to_user(row) if row else None

    def get_user_by_id(self, user_id: UUID) -> User | None:
        row = self._conn.execute(
            "SELECT * FROM users WHERE id = ?", [str(user_id)]
        ).fetchone()
        return self._row_to_user(row) if row else None

    def email_exists(self, email: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM users WHERE email = ?", [email.lower()]
        ).fetchone()
        return row is not None

    @staticmethod
    def _row_to_user(row: sqlite3.Row) -> User:
        return User(
            id=UUID(row["id"]),
            email=row["email"],
            hashed_password=row["hashed_password"],
            organization_id=UUID(row["organization_id"]),
            role=UserRole(row["role"]),
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    def close(self) -> None:
        self._conn.close()
