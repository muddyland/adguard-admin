from collections.abc import Generator

from sqlalchemy import inspect, text
from sqlmodel import Session, SQLModel, create_engine

from .config import settings

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, echo=False, connect_args=connect_args)

# Columns added after the first release. create_all() does not ALTER existing
# tables, so we add any missing ones on startup (SQLite-friendly, no Alembic).
_ADDED_COLUMNS = {
    "server": {"tls_cert": "TEXT", "manage_upstreams": "BOOLEAN DEFAULT 0"},
    "dnsrecord": {"zone_ids": "TEXT DEFAULT '[]'"},
    "upstream": {"zone_ids": "TEXT DEFAULT '[]'"},
    "forwardzone": {"zone_ids": "TEXT DEFAULT '[]'"},
}

# Tables whose old single zone_id should be folded into the new zone_ids list.
_ZONE_ID_BACKFILL = ["dnsrecord", "upstream", "forwardzone"]


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


def _backfill_zone_ids() -> None:
    """Migrate legacy single zone_id -> zone_ids list (e.g. 3 -> '[3]')."""
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    with engine.begin() as conn:
        for table in _ZONE_ID_BACKFILL:
            if table not in existing_tables:
                continue
            cols = {c["name"] for c in inspector.get_columns(table)}
            if "zone_id" not in cols or "zone_ids" not in cols:
                continue
            conn.execute(text(
                f"UPDATE {table} SET zone_ids = '[' || zone_id || ']' "
                f"WHERE zone_id IS NOT NULL AND (zone_ids IS NULL OR zone_ids = '[]' OR zone_ids = '')"
            ))


def init_db() -> None:
    # Import models so SQLModel registers the tables before create_all.
    from . import models  # noqa: F401

    SQLModel.metadata.create_all(engine)
    _ensure_columns()
    _backfill_zone_ids()


def get_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session
