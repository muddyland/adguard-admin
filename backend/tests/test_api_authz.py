"""S10 plus the role matrix: who may read, write and extract credentials."""
from __future__ import annotations

import pytest

from app.models import Role, Server
from tests.conftest import make_user


# --------------------------------------------------------------------------- #
# S10 — credential reveal
# --------------------------------------------------------------------------- #
def test_credentials_endpoint_is_post_only(client, admin_headers, server_row):
    """GET would record the read in history and access logs."""
    assert client.get(f"/api/servers/{server_row.id}/credentials",
                      headers=admin_headers).status_code == 405


def test_admin_can_reveal_credentials(client, admin_headers, server_row):
    resp = client.post(f"/api/servers/{server_row.id}/credentials", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["password"] == "upstream-secret"
    assert body["has_password"] is True


def test_editor_cannot_reveal_credentials(client, editor_headers, server_row):
    resp = client.post(f"/api/servers/{server_row.id}/credentials", headers=editor_headers)
    assert resp.status_code == 403


def test_viewer_cannot_reveal_credentials(client, viewer_headers, server_row):
    assert client.post(
        f"/api/servers/{server_row.id}/credentials", headers=viewer_headers
    ).status_code == 403


def test_credential_reveal_is_audit_logged(client, admin_headers, server_row, caplog):
    with caplog.at_level("WARNING", logger="adguard_admin.servers"):
        client.post(f"/api/servers/{server_row.id}/credentials", headers=admin_headers)
    messages = [r.getMessage() for r in caplog.records]
    assert any("Credential reveal" in m for m in messages)
    # The log line must identify who did it and which server.
    assert any("admin-user" in m and server_row.name in m for m in messages)


def test_credentials_404_for_unknown_server(client, admin_headers):
    assert client.post("/api/servers/9999/credentials", headers=admin_headers).status_code == 404


# --------------------------------------------------------------------------- #
# Role matrix
# --------------------------------------------------------------------------- #
WRITE_ENDPOINTS = [
    ("post", "/api/zones", {"name": "Z", "slug": "z"}),
    ("post", "/api/records", {"domain": "a.test", "answer": "10.0.0.1"}),
    ("post", "/api/servers", {"name": "s", "url": "http://10.0.0.9:3000"}),
    ("post", "/api/sync/run", None),
]


@pytest.mark.parametrize("method,path,body", WRITE_ENDPOINTS)
def test_viewer_cannot_write(client, viewer_headers, method, path, body):
    resp = getattr(client, method)(path, json=body, headers=viewer_headers)
    assert resp.status_code == 403, f"{path} allowed a viewer: {resp.status_code}"


@pytest.mark.parametrize("method,path,body", WRITE_ENDPOINTS)
def test_unauthenticated_cannot_write(client, method, path, body):
    resp = getattr(client, method)(path, json=body)
    assert resp.status_code == 401


@pytest.mark.parametrize("path", [
    "/api/zones", "/api/records", "/api/servers", "/api/users", "/api/stats",
    "/api/sync/status", "/api/upstreams", "/api/filters",
])
def test_reads_require_authentication(client, path):
    assert client.get(path).status_code == 401


def test_user_management_is_admin_only(client, editor_headers):
    assert client.get("/api/users", headers=editor_headers).status_code == 403
    assert client.post(
        "/api/users", json={"username": "x", "password": "y"}, headers=editor_headers
    ).status_code == 403


def test_admin_cannot_demote_self(client, admin_headers, admin_user):
    resp = client.patch(
        f"/api/users/{admin_user.id}", json={"role": "viewer"}, headers=admin_headers
    )
    assert resp.status_code == 400


def test_admin_cannot_delete_self(client, admin_headers, admin_user):
    assert client.delete(
        f"/api/users/{admin_user.id}", headers=admin_headers
    ).status_code == 400


def test_admin_cannot_disable_self(client, admin_headers, admin_user):
    resp = client.patch(
        f"/api/users/{admin_user.id}", json={"is_active": False}, headers=admin_headers
    )
    assert resp.status_code == 400


def test_admin_can_manage_other_users(client, admin_headers, session):
    other = make_user(session, "other", Role.viewer)
    resp = client.patch(
        f"/api/users/{other.id}", json={"role": "editor"}, headers=admin_headers
    )
    assert resp.status_code == 200 and resp.json()["role"] == "editor"


def test_password_is_never_returned_by_the_users_api(client, admin_headers, session):
    make_user(session, "someone-else", Role.viewer)
    body = client.get("/api/users", headers=admin_headers).json()
    for user in body:
        assert "hashed_password" not in user
        assert "password" not in user


def test_server_read_never_includes_the_password(client, admin_headers, server_row):
    body = client.get("/api/servers", headers=admin_headers).json()
    assert body
    for s in body:
        assert "password" not in s
        assert "password_enc" not in s


# --------------------------------------------------------------------------- #
# Server URL validation (SSRF-adjacent hardening)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "ftp://10.0.0.1", "not-a-url", "http://ex ample.com",
])
def test_server_url_must_be_http(client, editor_headers, url):
    resp = client.post(
        "/api/servers", json={"name": "s", "url": url}, headers=editor_headers
    )
    assert resp.status_code == 422


def test_server_name_with_control_chars_rejected(client, editor_headers):
    resp = client.post(
        "/api/servers",
        json={"name": "bad\nname", "url": "http://10.0.0.9:3000"},
        headers=editor_headers,
    )
    assert resp.status_code == 422


def test_server_update_validates_url(client, editor_headers, server_row):
    resp = client.patch(
        f"/api/servers/{server_row.id}", json={"url": "file:///etc/passwd"},
        headers=editor_headers,
    )
    assert resp.status_code == 422


def test_server_create_normalises_url(client, editor_headers, session):
    resp = client.post(
        "/api/servers", json={"name": "s2", "url": "http://10.0.0.9:3000/"},
        headers=editor_headers,
    )
    assert resp.status_code == 201
    assert session.get(Server, resp.json()["id"]).url == "http://10.0.0.9:3000"
