from security_review.infrastructure.persistence.database import resolve_database_url


def test_resolve_database_url_defaults_to_sqlite(monkeypatch, tmp_path):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    db_path = tmp_path / "test.db"

    url = resolve_database_url(str(db_path))

    assert url == f"sqlite:///{db_path}"
    assert db_path.parent.exists()


def test_resolve_database_url_prefers_env_var(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://user:pass@host/db")

    url = resolve_database_url(str(tmp_path / "unused.db"))

    assert url == "postgresql+psycopg://user:pass@host/db"
