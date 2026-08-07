"""Shared fixtures.

Environment has to be set before `app.config` is imported, because Settings is
constructed at import time and cached — so this module configures os.environ at
the very top, ahead of any app import.
"""
from __future__ import annotations

import os
import tempfile

from cryptography.fernet import Fernet

# --- must precede any `app.*` import ---------------------------------------
_TMP_DB = tempfile.mkdtemp(prefix="agh-admin-tests-")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_TMP_DB}/test.db")
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-definitely-long-enough-0123456789")
os.environ.setdefault("FERNET_KEY", Fernet.generate_key().decode())
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "not-the-default-password")
os.environ.setdefault("PUBLIC_BASE_URL", "http://testserver")
os.environ.setdefault("FRONTEND_URL", "http://testserver")
os.environ.setdefault("CORS_ORIGINS", "http://testserver")
# Keep the reconcile loop from firing during tests; each test drives it directly.
os.environ.setdefault("SYNC_INTERVAL_SECONDS", "3600")
# ---------------------------------------------------------------------------

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, SQLModel, delete  # noqa: E402

from app import models  # noqa: E402,F401  (registers tables)
from app.database import engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Role, Server, User, Zone  # noqa: E402
from app.routers.auth import login_limiter  # noqa: E402
from app.security import hash_password  # noqa: E402
from app.sync import sync_manager  # noqa: E402

ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]


@pytest.fixture
def anyio_backend():
    """Pin async tests to asyncio.

    anyio's plugin would otherwise also run them under trio, but the app is an
    asyncio application (uvicorn, asyncio.to_thread, asyncio.Semaphore), so a
    trio run tests a configuration that never happens in production.
    """
    return "asyncio"


@pytest.fixture(scope="session", autouse=True)
def _schema():
    init_db()
    yield
    SQLModel.metadata.drop_all(engine)


@pytest.fixture(autouse=True)
def clean_db():
    """Truncate every table between tests so ordering never matters."""
    with Session(engine) as session:
        for table in reversed(SQLModel.metadata.sorted_tables):
            session.exec(delete(table))
        session.commit()
    login_limiter.reset()
    sync_manager.last_results = []
    sync_manager.last_run = None
    yield


@pytest.fixture
def session():
    with Session(engine) as s:
        yield s


@pytest.fixture
def client():
    """A TestClient that does NOT run the lifespan.

    Used without a context manager on purpose: init_db has already run, and the
    background reconcile loop must stay dormant. Startup behaviour has its own
    tests in test_startup.py, which enter the lifespan explicitly.
    """
    return TestClient(app, base_url="http://testserver")


def make_user(
    session: Session,
    username: str = "someone",
    role: Role = Role.admin,
    password: str | None = "pw-for-tests-123",
    is_active: bool = True,
    oidc_sub: str | None = None,
) -> User:
    user = User(
        username=username,
        role=role,
        is_active=is_active,
        hashed_password=hash_password(password) if password else None,
        oidc_sub=oidc_sub,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def auth_headers(client: TestClient, username: str, password: str) -> dict[str, str]:
    resp = client.post("/api/auth/token", data={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


@pytest.fixture
def admin_user(session):
    return make_user(session, "admin-user", Role.admin)


@pytest.fixture
def editor_user(session):
    return make_user(session, "editor-user", Role.editor)


@pytest.fixture
def viewer_user(session):
    return make_user(session, "viewer-user", Role.viewer)


@pytest.fixture
def admin_headers(client, admin_user):
    return auth_headers(client, admin_user.username, "pw-for-tests-123")


@pytest.fixture
def editor_headers(client, editor_user):
    return auth_headers(client, editor_user.username, "pw-for-tests-123")


@pytest.fixture
def viewer_headers(client, viewer_user):
    return auth_headers(client, viewer_user.username, "pw-for-tests-123")


@pytest.fixture
def zone(session):
    z = Zone(name="Test Zone", slug="test-zone")
    session.add(z)
    session.commit()
    session.refresh(z)
    return z


@pytest.fixture
def server_row(session):
    from app.security import encrypt_secret

    s = Server(
        name="agh-1",
        url="http://10.0.0.2:3000",
        username="admin",
        password_enc=encrypt_secret("upstream-secret"),
    )
    session.add(s)
    session.commit()
    session.refresh(s)
    return s
