"""S7/S8/S12/S13 and T4: startup refuses insecure defaults, cookies and headers
are hardened, and SQLite runs in a mode that survives concurrent writes."""
from __future__ import annotations

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text

from app.config import Settings, config_problems
from app.database import engine
from app.main import InsecureConfiguration, check_configuration

GOOD_FERNET = Fernet.generate_key().decode()


def _settings(**overrides) -> Settings:
    base = dict(
        secret_key="a-perfectly-fine-secret-key-of-sufficient-length",
        fernet_key=GOOD_FERNET,
        admin_password="not-the-default",
        cors_origins="https://admin.example.com",
        oidc_default_role="viewer",
    )
    base.update(overrides)
    return Settings(**base)


def test_good_config_has_no_problems():
    assert config_problems(_settings()) == []


def test_placeholder_secret_key_is_fatal():
    problems = config_problems(
        _settings(secret_key="change-me-please-generate-a-long-random-string")
    )
    assert any("SECRET_KEY" in p for p in problems)


def test_empty_secret_key_is_fatal():
    assert any("SECRET_KEY" in p for p in config_problems(_settings(secret_key="")))


def test_short_secret_key_is_fatal():
    problems = config_problems(_settings(secret_key="tooshort"))
    assert any("at least 32" in p for p in problems)


def test_missing_fernet_key_is_fatal():
    assert any("FERNET_KEY" in p for p in config_problems(_settings(fernet_key="")))


def test_malformed_fernet_key_is_caught_at_startup():
    """Otherwise it surfaces as an opaque per-server error inside the sync loop."""
    problems = config_problems(_settings(fernet_key="obviously-not-a-fernet-key"))
    assert any("not a valid Fernet key" in p for p in problems)


def test_default_admin_password_is_fatal():
    assert any("ADMIN_PASSWORD" in p for p in config_problems(_settings(admin_password="admin")))


def test_wildcard_cors_is_fatal():
    problems = config_problems(_settings(cors_origins="*"))
    assert any("CORS_ORIGINS" in p for p in problems)


def test_invalid_oidc_role_is_fatal():
    problems = config_problems(_settings(oidc_default_role="superuser"))
    assert any("OIDC_DEFAULT_ROLE" in p for p in problems)


def test_incomplete_oidc_config_is_fatal():
    problems = config_problems(_settings(oidc_enabled=True, oidc_issuer="https://idp.test"))
    assert any("OIDC_CLIENT_ID" in p for p in problems)


def test_check_configuration_raises_on_bad_config(monkeypatch):
    from app import main as main_mod

    monkeypatch.setattr(main_mod, "settings", _settings(secret_key="short"))
    monkeypatch.setattr(
        main_mod, "config_problems", lambda s: ["SECRET_KEY is too short"]
    )
    with pytest.raises(InsecureConfiguration) as exc:
        check_configuration()
    assert "SECRET_KEY" in str(exc.value)


def test_allow_insecure_config_downgrades_to_warnings(monkeypatch, caplog):
    from app import main as main_mod

    monkeypatch.setattr(main_mod.settings, "allow_insecure_config", True)
    monkeypatch.setattr(main_mod, "config_problems", lambda s: ["something insecure"])
    with caplog.at_level("WARNING"):
        check_configuration()  # must not raise
    assert any("INSECURE CONFIG" in r.message for r in caplog.records)


# --------------------------------------------------------------------------- #
# Cookie / header hardening
# --------------------------------------------------------------------------- #
def test_secure_cookies_follow_the_public_scheme():
    assert _settings(public_base_url="https://admin.example.com").secure_cookies is True
    assert _settings(public_base_url="http://localhost:8000").secure_cookies is False


def test_cors_origin_list_is_parsed_and_trimmed():
    s = _settings(cors_origins=" https://a.test , https://b.test ,, ")
    assert s.cors_origin_list == ["https://a.test", "https://b.test"]


def test_hsts_only_when_https(client, monkeypatch):
    from app import main as main_mod

    assert "strict-transport-security" not in client.get("/api/health").headers

    monkeypatch.setattr(
        type(main_mod.settings), "secure_cookies", property(lambda self: True)
    )
    assert "strict-transport-security" in client.get("/api/health").headers


# --------------------------------------------------------------------------- #
# T4 — SQLite durability settings
# --------------------------------------------------------------------------- #
def test_sqlite_runs_in_wal_mode():
    with engine.connect() as conn:
        assert conn.execute(text("PRAGMA journal_mode")).scalar().lower() == "wal"


def test_sqlite_has_a_busy_timeout():
    with engine.connect() as conn:
        assert conn.execute(text("PRAGMA busy_timeout")).scalar() >= 1000


def test_concurrent_writes_do_not_deadlock():
    """Without WAL + busy_timeout this is where 'database is locked' shows up."""
    import threading

    from sqlmodel import Session

    from app.models import Zone

    errors: list[Exception] = []

    def writer(n: int):
        try:
            with Session(engine) as s:
                for i in range(10):
                    s.add(Zone(name=f"z-{n}-{i}", slug=f"z-{n}-{i}"))
                    s.commit()
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert not errors, f"concurrent writes failed: {errors}"
