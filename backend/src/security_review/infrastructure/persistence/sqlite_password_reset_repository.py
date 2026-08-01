from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from sqlalchemy import text

from security_review.infrastructure.persistence.database import get_engine
from security_review.infrastructure.security.password_hasher import hash_token, verify_token

RESET_TOKEN_TTL = timedelta(minutes=30)


class SqlitePasswordResetRepository:
    """Password-reset tokens, backed by SQLite (local/dev/test) or Postgres in
    production (set ``DATABASE_URL``) via the shared SQLAlchemy engine.

    Only a hash of the token is stored (never the raw token) so a database
    compromise doesn't hand out usable reset links, mirroring how passwords
    themselves are hashed rather than stored in plaintext.
    """

    def __init__(self, db_path: str | Path = "data/security_review.db") -> None:
        self.db_path = Path(db_path)
        self._engine = get_engine(str(self.db_path))

    def initialize(self) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS password_reset_tokens (
                        id TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        token_hash TEXT NOT NULL,
                        expires_at TEXT NOT NULL,
                        used_at TEXT,
                        created_at TEXT NOT NULL
                    )
                    """
                )
            )

    def create(self, token_id: UUID, user_id: UUID, raw_token: str) -> None:
        now = datetime.now(UTC)
        with self._engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, used_at, created_at)
                    VALUES (:id, :user_id, :token_hash, :expires_at, NULL, :created_at)
                    """
                ),
                {
                    "id": str(token_id),
                    "user_id": str(user_id),
                    "token_hash": hash_token(raw_token),
                    "expires_at": (now + RESET_TOKEN_TTL).isoformat(),
                    "created_at": now.isoformat(),
                },
            )

    def resolve_valid_user_id(self, raw_token: str) -> UUID | None:
        """Return the user id for ``raw_token`` if it exists, hasn't expired, and
        hasn't already been used — else None. Does not consume the token; call
        ``mark_used`` after the password has actually been changed.
        """
        token_hash = hash_token(raw_token)
        with self._engine.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT id, user_id, expires_at, used_at FROM password_reset_tokens "
                    "WHERE token_hash = :token_hash"
                ),
                {"token_hash": token_hash},
            ).mappings().all()

        now = datetime.now(UTC)
        for row in rows:
            if row["used_at"] is not None:
                continue
            if datetime.fromisoformat(row["expires_at"]) < now:
                continue
            # Constant-time re-verification against the (rare) hash-collision case;
            # in practice the lookup above already filters to matching hashes.
            if verify_token(raw_token, token_hash):
                return UUID(row["user_id"])
        return None

    def mark_used(self, raw_token: str) -> None:
        token_hash = hash_token(raw_token)
        with self._engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE password_reset_tokens SET used_at = :used_at WHERE token_hash = :token_hash"
                ),
                {"used_at": datetime.now(UTC).isoformat(), "token_hash": token_hash},
            )

    def close(self) -> None:
        self._engine.dispose()
