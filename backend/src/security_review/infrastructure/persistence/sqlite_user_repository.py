from __future__ import annotations

from datetime import datetime
from pathlib import Path
from uuid import UUID

from sqlalchemy import inspect, text

from security_review.domain.auth.models import Organization, User, UserRole
from security_review.domain.billing.models import PlanTier
from security_review.infrastructure.persistence.database import get_engine


class SqliteUserRepository:
    """Organization/user persistence, backed by SQLite (local/dev/test) or Postgres
    in production (set ``DATABASE_URL``) via the shared SQLAlchemy engine. The class
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
                    CREATE TABLE IF NOT EXISTS organizations (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        plan TEXT NOT NULL DEFAULT 'free',
                        created_at TEXT NOT NULL
                    )
                    """
                )
            )
            conn.execute(
                text(
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
            )

        # Separate, already-committed transaction: Postgres can't see the tables
        # created above until that transaction commits, so inspecting them must
        # happen in a fresh connection/transaction afterward.
        with self._engine.begin() as conn:
            columns = {col["name"] for col in inspect(self._engine).get_columns("organizations")}
            if "plan" not in columns:
                conn.execute(text("ALTER TABLE organizations ADD COLUMN plan TEXT NOT NULL DEFAULT 'free'"))
            if "stripe_customer_id" not in columns:
                conn.execute(text("ALTER TABLE organizations ADD COLUMN stripe_customer_id TEXT"))
            if "stripe_subscription_id" not in columns:
                conn.execute(text("ALTER TABLE organizations ADD COLUMN stripe_subscription_id TEXT"))

    def create_organization(self, organization: Organization) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO organizations (id, name, plan, stripe_customer_id, stripe_subscription_id, created_at) "
                    "VALUES (:id, :name, :plan, :stripe_customer_id, :stripe_subscription_id, :created_at)"
                ),
                {
                    "id": str(organization.id),
                    "name": organization.name,
                    "plan": organization.plan.value,
                    "stripe_customer_id": organization.stripe_customer_id,
                    "stripe_subscription_id": organization.stripe_subscription_id,
                    "created_at": organization.created_at.isoformat(),
                },
            )

    def get_organization(self, organization_id: UUID) -> Organization | None:
        with self._engine.connect() as conn:
            row = conn.execute(
                text("SELECT * FROM organizations WHERE id = :id"), {"id": str(organization_id)}
            ).mappings().first()
        return self._row_to_organization(row) if row else None

    def get_organization_id_by_stripe_customer_id(self, stripe_customer_id: str) -> UUID | None:
        with self._engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT id FROM organizations WHERE stripe_customer_id = :customer_id "
                    "ORDER BY created_at DESC LIMIT 1"
                ),
                {"customer_id": stripe_customer_id},
            ).mappings().first()
        return UUID(row["id"]) if row else None

    def update_organization_plan(self, organization_id: UUID, plan: PlanTier) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                text("UPDATE organizations SET plan = :plan WHERE id = :id"),
                {"plan": plan.value, "id": str(organization_id)},
            )

    def update_organization_stripe_ids(
        self,
        organization_id: UUID,
        *,
        stripe_customer_id: str | None,
        stripe_subscription_id: str | None,
    ) -> None:
        with self._engine.begin() as conn:
            if stripe_customer_id is not None:
                conn.execute(
                    text(
                        "UPDATE organizations SET stripe_customer_id = NULL WHERE "
                        "stripe_customer_id = :customer_id AND id != :id"
                    ),
                    {"customer_id": stripe_customer_id, "id": str(organization_id)},
                )

            conn.execute(
                text(
                    "UPDATE organizations SET stripe_customer_id = :customer_id, "
                    "stripe_subscription_id = :subscription_id WHERE id = :id"
                ),
                {
                    "customer_id": stripe_customer_id,
                    "subscription_id": stripe_subscription_id,
                    "id": str(organization_id),
                },
            )

    def create_user(self, user: User) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO users (id, email, hashed_password, organization_id, role, created_at)
                    VALUES (:id, :email, :hashed_password, :organization_id, :role, :created_at)
                    """
                ),
                {
                    "id": str(user.id),
                    "email": user.email.lower(),
                    "hashed_password": user.hashed_password,
                    "organization_id": str(user.organization_id),
                    "role": user.role.value,
                    "created_at": user.created_at.isoformat(),
                },
            )

    def get_user_by_email(self, email: str) -> User | None:
        with self._engine.connect() as conn:
            row = conn.execute(
                text("SELECT * FROM users WHERE email = :email"), {"email": email.lower()}
            ).mappings().first()
        return self._row_to_user(row) if row else None

    def get_user_by_id(self, user_id: UUID) -> User | None:
        with self._engine.connect() as conn:
            row = conn.execute(
                text("SELECT * FROM users WHERE id = :id"), {"id": str(user_id)}
            ).mappings().first()
        return self._row_to_user(row) if row else None

    def email_exists(self, email: str) -> bool:
        with self._engine.connect() as conn:
            row = conn.execute(
                text("SELECT 1 AS found FROM users WHERE email = :email"), {"email": email.lower()}
            ).mappings().first()
        return row is not None

    def update_user_password(self, user_id: UUID, hashed_password: str) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                text("UPDATE users SET hashed_password = :hashed_password WHERE id = :id"),
                {"hashed_password": hashed_password, "id": str(user_id)},
            )

    def list_users_by_organization(self, organization_id: UUID) -> list[User]:
        with self._engine.connect() as conn:
            rows = (
                conn.execute(
                    text(
                        "SELECT * FROM users WHERE organization_id = :organization_id "
                        "ORDER BY created_at ASC"
                    ),
                    {"organization_id": str(organization_id)},
                )
                .mappings()
                .all()
            )
        return [self._row_to_user(row) for row in rows]

    def update_user_role(self, user_id: UUID, role: UserRole) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                text("UPDATE users SET role = :role WHERE id = :id"),
                {"role": role.value, "id": str(user_id)},
            )

    def delete_user(self, user_id: UUID) -> None:
        with self._engine.begin() as conn:
            conn.execute(text("DELETE FROM users WHERE id = :id"), {"id": str(user_id)})

    @staticmethod
    def _row_to_organization(row) -> Organization:
        return Organization(
            id=UUID(row["id"]),
            name=row["name"],
            plan=PlanTier(row["plan"]),
            stripe_customer_id=row["stripe_customer_id"],
            stripe_subscription_id=row["stripe_subscription_id"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    @staticmethod
    def _row_to_user(row) -> User:
        return User(
            id=UUID(row["id"]),
            email=row["email"],
            hashed_password=row["hashed_password"],
            organization_id=UUID(row["organization_id"]),
            role=UserRole(row["role"]),
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    def close(self) -> None:
        self._engine.dispose()

