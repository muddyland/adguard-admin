"""S3 / S4: the UI proxy must re-check the cookie's user on every request and
must hand the SPA a sandbox that denies the proxied app our origin."""
from __future__ import annotations

import pytest

from app.config import settings
from app.models import Role, User
from app.routers.proxy import _sandbox_attr, _to_js_str
from app.security import create_proxy_token


def _open_session(client, headers, server_id):
    resp = client.post(f"/api/servers/{server_id}/ui-session", headers=headers)
    assert resp.status_code == 200, resp.text
    return resp


# --------------------------------------------------------------------------- #
# S3 — origin isolation
# --------------------------------------------------------------------------- #
def test_sandbox_omits_allow_same_origin_over_https(monkeypatch):
    """This single token is what keeps a hostile AdGuard box out of localStorage.

    Only achievable over HTTPS: the opaque-origin frame needs a SameSite=None
    cookie, which browsers reject without Secure.
    """
    monkeypatch.setattr(settings, "public_base_url", "https://admin.example.com")
    tokens = _sandbox_attr().split()
    assert "allow-same-origin" not in tokens
    assert "allow-scripts" in tokens


def test_sandbox_falls_back_over_plain_http(monkeypatch):
    """Documented trade-off: over HTTP the cookie could never be sent, so a
    strict sandbox would just break the feature."""
    monkeypatch.setattr(settings, "public_base_url", "http://admin.example.com")
    assert "allow-same-origin" in _sandbox_attr().split()


def test_ui_session_advertises_the_sandbox(client, editor_headers, server_row, monkeypatch):
    monkeypatch.setattr(settings, "public_base_url", "https://admin.example.com")
    body = _open_session(client, editor_headers, server_row.id).json()
    assert "allow-same-origin" not in body["sandbox"]
    assert body["src"] == f"/api/servers/{server_row.id}/ui/"


def test_same_origin_escape_hatch_is_explicit(monkeypatch):
    monkeypatch.setattr(settings, "ui_proxy_allow_same_origin", True)
    assert "allow-same-origin" in _sandbox_attr()


def test_same_origin_escape_hatch_is_flagged_as_insecure_config(monkeypatch):
    from app.config import Settings, config_problems

    s = Settings(
        secret_key="x" * 40,
        fernet_key=settings.fernet_key,
        admin_password="not-admin",
        ui_proxy_enabled=True,
        ui_proxy_allow_same_origin=True,
    )
    assert any("UI_PROXY_ALLOW_SAME_ORIGIN" in p for p in config_problems(s))


def test_shim_cannot_break_out_of_its_script_tag():
    """The prefix is interpolated into an inline <script>."""
    assert "</script>" not in _to_js_str("</script><script>alert(1)</script>")
    assert "\\x3c" in _to_js_str("<")


def test_strict_csp_on_api_but_not_on_proxy(client, admin_headers, server_row):
    api = client.get("/api/health")
    assert "frame-ancestors 'none'" in api.headers["content-security-policy"]
    assert api.headers["x-frame-options"] == "DENY"

    # The proxy path must stay frameable by us; a 401 still goes through the
    # middleware, which is what we're asserting on.
    proxied = client.get(f"/api/servers/{server_row.id}/ui/")
    assert proxied.status_code == 401
    assert "content-security-policy" not in proxied.headers
    assert "x-frame-options" not in proxied.headers


def test_security_headers_present(client):
    resp = client.get("/api/health")
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["referrer-policy"] == "no-referrer"
    assert resp.headers["cross-origin-opener-policy"] == "same-origin"


def test_preflight_from_sandboxed_frame_is_answered(client, server_row):
    """A sandboxed iframe sends Origin: null and preflights carry no cookies."""
    resp = client.options(
        f"/api/servers/{server_row.id}/ui/control/status",
        headers={
            "Origin": "null",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert resp.status_code == 204
    assert resp.headers["access-control-allow-origin"] == "null"
    assert resp.headers["access-control-allow-credentials"] == "true"


def test_proxy_cors_does_not_leak_to_arbitrary_origins(client, server_row):
    resp = client.options(
        f"/api/servers/{server_row.id}/ui/control/status",
        headers={"Origin": "http://evil.test", "Access-Control-Request-Method": "GET"},
    )
    assert resp.headers.get("access-control-allow-origin") != "http://evil.test"


def test_other_api_routes_are_not_reachable_from_a_null_origin(client, admin_headers):
    """The sandboxed frame must not be able to read the real API."""
    resp = client.get("/api/servers", headers={**admin_headers, "Origin": "null"})
    assert resp.headers.get("access-control-allow-origin") != "null"


# --------------------------------------------------------------------------- #
# S4 — the cookie is not proof of current authorization
# --------------------------------------------------------------------------- #
def test_proxy_requires_a_cookie(client, server_row):
    assert client.get(f"/api/servers/{server_row.id}/ui/").status_code == 401


def test_proxy_rejects_cookie_minted_for_another_server(client, session, editor_user, server_row):
    from app.models import Server

    other = Server(name="agh-2", url="http://10.0.0.3:3000")
    session.add(other)
    session.commit()
    session.refresh(other)

    token = create_proxy_token(other.id, editor_user.id)
    client.cookies.set(f"aghproxy_{server_row.id}", token)
    resp = client.get(f"/api/servers/{server_row.id}/ui/")
    assert resp.status_code == 401


def test_proxy_rejects_disabled_user(client, session, editor_user, server_row):
    token = create_proxy_token(server_row.id, editor_user.id)
    user = session.get(User, editor_user.id)
    user.is_active = False
    session.add(user)
    session.commit()

    client.cookies.set(f"aghproxy_{server_row.id}", token)
    resp = client.get(f"/api/servers/{server_row.id}/ui/")
    assert resp.status_code == 403


def test_proxy_rejects_demoted_user(client, session, editor_user, server_row):
    """A cookie minted while the user was an editor must stop working on demotion."""
    token = create_proxy_token(server_row.id, editor_user.id)
    user = session.get(User, editor_user.id)
    user.role = Role.viewer
    session.add(user)
    session.commit()

    client.cookies.set(f"aghproxy_{server_row.id}", token)
    resp = client.get(f"/api/servers/{server_row.id}/ui/")
    assert resp.status_code == 403


def test_proxy_rejects_deleted_user(client, session, editor_user, server_row):
    token = create_proxy_token(server_row.id, editor_user.id)
    session.delete(session.get(User, editor_user.id))
    session.commit()

    client.cookies.set(f"aghproxy_{server_row.id}", token)
    resp = client.get(f"/api/servers/{server_row.id}/ui/")
    assert resp.status_code == 403


def test_proxy_rejects_a_normal_access_token_as_a_proxy_cookie(client, session, editor_user, server_row):
    """Typ confusion: a login JWT must not authorize the proxy."""
    from app.security import create_access_token

    client.cookies.set(f"aghproxy_{server_row.id}", create_access_token(str(editor_user.id)))
    assert client.get(f"/api/servers/{server_row.id}/ui/").status_code == 401


def test_ui_session_requires_editor(client, viewer_headers, server_row):
    resp = client.post(f"/api/servers/{server_row.id}/ui-session", headers=viewer_headers)
    assert resp.status_code == 403


def test_ui_session_cookie_is_httponly_and_path_scoped(client, editor_headers, server_row):
    resp = _open_session(client, editor_headers, server_row.id)
    raw = resp.headers["set-cookie"]
    assert "HttpOnly" in raw
    assert f"Path=/api/servers/{server_row.id}/ui" in raw


def test_proxy_can_be_disabled_entirely(client, editor_headers, server_row, monkeypatch):
    monkeypatch.setattr(settings, "ui_proxy_enabled", False)
    assert client.post(
        f"/api/servers/{server_row.id}/ui-session", headers=editor_headers
    ).status_code == 404


@pytest.mark.parametrize("bad_token", ["", "not-a-jwt", "a.b.c"])
def test_proxy_rejects_malformed_cookies(client, server_row, bad_token):
    client.cookies.set(f"aghproxy_{server_row.id}", bad_token)
    assert client.get(f"/api/servers/{server_row.id}/ui/").status_code == 401


def test_decode_proxy_token_returns_user_id():
    from app.security import decode_proxy_token

    token = create_proxy_token(7, 42)
    assert decode_proxy_token(token, 7) == 42
    assert decode_proxy_token(token, 8) is None
