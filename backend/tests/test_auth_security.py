"""S5 / S6: login brute-force protection and OIDC account-linking safety."""
from __future__ import annotations

import pytest

from app.config import settings
from app.models import Role, User
from app.routers.auth import (
    _claim_groups,
    _in_admin_group,
    _resolve_oidc_user,
    login_limiter,
)
from app.ratelimit import RateLimiter
from tests.conftest import make_user


# --------------------------------------------------------------------------- #
# S6 — login rate limiting
# --------------------------------------------------------------------------- #
def test_repeated_bad_passwords_get_locked_out(client, admin_user):
    last = None
    for _ in range(settings.login_max_attempts):
        last = client.post(
            "/api/auth/token",
            data={"username": admin_user.username, "password": "wrong"},
        )
        assert last.status_code == 401

    blocked = client.post(
        "/api/auth/token", data={"username": admin_user.username, "password": "wrong"}
    )
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers
    assert int(blocked.headers["Retry-After"]) > 0


def test_lockout_also_blocks_the_correct_password(client, admin_user):
    """Otherwise the limiter is trivially bypassed by the attempt that matters."""
    for _ in range(settings.login_max_attempts):
        client.post(
            "/api/auth/token", data={"username": admin_user.username, "password": "wrong"}
        )
    resp = client.post(
        "/api/auth/token",
        data={"username": admin_user.username, "password": "pw-for-tests-123"},
    )
    assert resp.status_code == 429


def test_successful_login_clears_the_failure_counter(client, admin_user):
    for _ in range(settings.login_max_attempts - 1):
        client.post(
            "/api/auth/token", data={"username": admin_user.username, "password": "wrong"}
        )
    ok = client.post(
        "/api/auth/token",
        data={"username": admin_user.username, "password": "pw-for-tests-123"},
    )
    assert ok.status_code == 200

    # Counter reset: a fresh run of failures is needed to trip the lockout again.
    for _ in range(settings.login_max_attempts - 1):
        resp = client.post(
            "/api/auth/token", data={"username": admin_user.username, "password": "wrong"}
        )
        assert resp.status_code == 401


def test_disabled_account_is_not_an_unlimited_password_oracle(client, session):
    user = make_user(session, "disabled-user", Role.viewer, is_active=False)
    for _ in range(settings.login_max_attempts):
        resp = client.post(
            "/api/auth/token",
            data={"username": user.username, "password": "pw-for-tests-123"},
        )
        assert resp.status_code == 403

    resp = client.post(
        "/api/auth/token",
        data={"username": user.username, "password": "pw-for-tests-123"},
    )
    assert resp.status_code == 429


def test_unknown_username_is_still_rate_limited(client):
    for _ in range(settings.login_max_attempts):
        client.post("/api/auth/token", data={"username": "nobody", "password": "x"})
    resp = client.post("/api/auth/token", data={"username": "nobody", "password": "x"})
    assert resp.status_code == 429


def test_limiter_lockout_expires():
    limiter = RateLimiter(max_attempts=2, window_seconds=60, lockout_seconds=1)
    limiter.record_failure("k")
    limiter.record_failure("k")
    assert limiter.retry_after("k") > 0

    # Advance the clock rather than sleeping.
    limiter._locked_until["k"] = limiter._now() - 0.01
    assert limiter.retry_after("k") == 0


def test_limiter_window_slides():
    """Failures spread beyond the window must not accumulate into a lockout."""
    limiter = RateLimiter(max_attempts=3, window_seconds=10, lockout_seconds=60)
    limiter.record_failure("k")
    limiter.record_failure("k")
    # Age the recorded failures out of the window.
    limiter._failures["k"] = type(limiter._failures["k"])(
        [t - 3600 for t in limiter._failures["k"]]
    )
    limiter.record_failure("k")
    assert limiter.retry_after("k") == 0


def test_limiter_is_keyed_independently(client, session):
    a = make_user(session, "user-a", Role.viewer)
    make_user(session, "user-b", Role.viewer)
    for _ in range(settings.login_max_attempts):
        client.post("/api/auth/token", data={"username": a.username, "password": "wrong"})

    # Same client IP, so the ip: key is also locked — that is intended. Verify
    # the username key alone locks by clearing only the ip key.
    login_limiter.record_success("ip:testclient")
    assert login_limiter.retry_after(f"user:{a.username}") > 0
    assert login_limiter.retry_after("user:user-b") == 0


# --------------------------------------------------------------------------- #
# S5 — OIDC account linking
# --------------------------------------------------------------------------- #
def test_oidc_does_not_adopt_local_account_by_username(session, monkeypatch):
    """The core takeover case: an IdP user names themselves 'admin'."""
    monkeypatch.setattr(settings, "oidc_allow_username_linking", True)
    local_admin = make_user(session, "admin", Role.admin, password="local-admin-pw")

    resolved = _resolve_oidc_user(session, sub="attacker-sub", username="admin", email=None)
    assert resolved is None, "must not adopt an account that has a local password"

    session.refresh(local_admin)
    assert local_admin.oidc_sub is None


def test_oidc_username_linking_is_off_by_default(session, monkeypatch):
    monkeypatch.setattr(settings, "oidc_allow_username_linking", False)
    make_user(session, "passwordless", Role.editor, password=None)
    assert _resolve_oidc_user(session, "sub-1", "passwordless", None) is None


def test_oidc_links_passwordless_account_when_enabled(session, monkeypatch):
    monkeypatch.setattr(settings, "oidc_allow_username_linking", True)
    user = make_user(session, "passwordless", Role.editor, password=None)
    resolved = _resolve_oidc_user(session, "sub-1", "passwordless", None)
    assert resolved is not None and resolved.id == user.id


def test_oidc_will_not_steal_account_bound_to_another_subject(session, monkeypatch):
    monkeypatch.setattr(settings, "oidc_allow_username_linking", True)
    make_user(session, "taken", Role.editor, password=None, oidc_sub="original-sub")
    assert _resolve_oidc_user(session, "other-sub", "taken", None) is None


def test_oidc_matches_on_subject_regardless_of_username_change(session):
    user = make_user(session, "old-name", Role.editor, password=None, oidc_sub="stable-sub")
    resolved = _resolve_oidc_user(session, "stable-sub", "brand-new-name", None)
    assert resolved is not None and resolved.id == user.id


@pytest.mark.parametrize("claims,expected_email", [
    ({"email": "a@example.com", "email_verified": True}, "a@example.com"),
    ({"email": "a@example.com", "email_verified": False}, None),
    ({"email": "a@example.com"}, None),
])
def test_unverified_email_is_not_trusted(claims, expected_email):
    """Mirrors the extraction in oidc_callback: self-asserted email is dropped."""
    email = claims.get("email") if claims.get("email_verified") else None
    assert email == expected_email


# --------------------------------------------------------------------------- #
# Existing authz guarantees that must keep holding
# --------------------------------------------------------------------------- #
def test_deleted_user_token_stops_working(client, session, admin_headers, admin_user):
    assert client.get("/api/auth/me", headers=admin_headers).status_code == 200
    session.delete(session.get(User, admin_user.id))
    session.commit()
    assert client.get("/api/auth/me", headers=admin_headers).status_code == 401


def test_disabled_user_token_stops_working(client, session, admin_headers, admin_user):
    user = session.get(User, admin_user.id)
    user.is_active = False
    session.add(user)
    session.commit()
    assert client.get("/api/auth/me", headers=admin_headers).status_code == 401


def test_role_demotion_takes_effect_immediately(client, session, admin_headers, admin_user):
    """The JWT carries a stale role claim; authorization must read the database."""
    user = session.get(User, admin_user.id)
    user.role = Role.viewer
    session.add(user)
    session.commit()
    assert client.get("/api/users", headers=admin_headers).status_code == 403


def test_token_signed_with_wrong_key_is_rejected(client):
    import jwt

    forged = jwt.encode({"sub": "1"}, "some-other-key-entirely", algorithm="HS256")
    resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 401


def test_alg_none_token_is_rejected(client, admin_user):
    """decode_access_token pins algorithms; an unsigned token must not pass."""
    import jwt

    forged = jwt.encode({"sub": str(admin_user.id)}, key="", algorithm="none")
    resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 401


# --------------------------------------------------------------------------- #
# OIDC group -> role mapping (provider-agnostic; Kanidm sends SPNs)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("raw,expected", [
    (None, []),
    ([], []),
    (["a", "b"], ["a", "b"]),
    (["  a  ", "", "b"], ["a", "b"]),
    # Some providers send one delimited string rather than an array.
    ("a,b", ["a", "b"]),
    ("a b", ["a", "b"]),
    ("a, b", ["a", "b"]),
    # Anything that isn't a name is dropped rather than stringified.
    ([{"name": "a"}, 7, "b"], ["b"]),
    (42, []),
])
def test_claim_groups_normalisation(raw, expected):
    assert _claim_groups(raw) == expected


@pytest.mark.parametrize("configured,groups,expected", [
    # Bare name, bare claim — the Authentik shape.
    ("adguard-admins", ["adguard-admins"], True),
    # Bare name against Kanidm's SPNs (plus the UUIDs it also sends).
    ("adguard-admins", ["adguard-admins@idm.example.com", "e3a1-..."], True),
    # A configured SPN is matched whole: same name, different realm must not pass.
    ("adguard-admins@idm.example.com", ["adguard-admins@idm.example.com"], True),
    ("adguard-admins@idm.example.com", ["adguard-admins@evil.example.com"], False),
    ("adguard-admins@idm.example.com", ["adguard-admins"], False),
    # Unset means nobody is promoted, whatever the IdP sends.
    ("", ["adguard-admins"], False),
    ("adguard-admins", [], False),
])
def test_admin_group_matching(monkeypatch, configured, groups, expected):
    monkeypatch.setattr(settings, "oidc_admin_group", configured)
    assert _in_admin_group(groups) is expected


@pytest.mark.parametrize("groups", [
    ["not-adguard-admins"],
    ["adguard-admins-readonly"],
    "not-adguard-admins",
    ["adguard-admins-x@idm.example.com"],
])
def test_admin_group_is_never_a_substring_match(monkeypatch, groups):
    """A substring test would make 'adguard-admins' match 'not-adguard-admins'."""
    monkeypatch.setattr(settings, "oidc_admin_group", "adguard-admins")
    assert _in_admin_group(_claim_groups(groups)) is False


# --------------------------------------------------------------------------- #
# The SSO button's name is operator-configurable
# --------------------------------------------------------------------------- #
def test_auth_config_reports_the_configured_provider_name(client, monkeypatch):
    monkeypatch.setattr(settings, "oidc_display_name", "Kanidm")
    body = client.get("/api/auth/config").json()
    assert body["oidc_display_name"] == "Kanidm"
    assert body["oidc_label"] == "Sign in with Kanidm"


@pytest.mark.parametrize("name", ["", "   "])
def test_blank_provider_name_falls_back_to_a_generic_label(monkeypatch, name):
    monkeypatch.setattr(settings, "oidc_display_name", name)
    assert settings.oidc_button_label == "Sign in with SSO"
