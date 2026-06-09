from collections.abc import Generator

from sqlalchemy import inspect, text
from sqlmodel import Session, SQLModel, create_engine

from .config import settings

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, echo=False, connect_args=connect_args)

# Columns added after the first release. create_all() does not ALTER existing
# tables, so we add any missing ones on startup (SQLite-friendly, no Alembic).
_ADDED_COLUMNS = {
    "server": {"tls_cert": "TEXT"},
}


def _ensure_columns() -> None:
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    with engine.begin() as conn:
        for table, columns in _ADDED_COLUMNS.items():
            if table not in existing_tables:
                continue
            have = {c["name"] for c in inspector.get_columns(table)}
            for col, coltype in columns.items():
                if col not in have:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {coltype}"))


def init_db() -> None:
    # Import models so SQLModel registers the tables before create_all.
    from . import models  # noqa: F401

    SQLModel.metadata.create_all(engine)
    _ensure_columns()


def get_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session
