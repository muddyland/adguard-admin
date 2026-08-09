"""End-to-end UI proxy tests against a real HTTP upstream.

The unit tests only covered authorization and header policy, which is how a
broken proxy shipped: nothing actually pushed bytes through it. These stand up a
miniature AdGuard Home and drive the proxy the way a browser does.
"""
from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.models import Server
from app.security import encrypt_secret

UPSTREAM_USER = "admin"
UPSTREAM_PASS = "upstream-pw"

INDEX_HTML = (
    "<!DOCTYPE html><html><head><title>AdGuard Home</title>"
    '<link rel="stylesheet" href="/static/main.css">'
    '</head><body><div id="root"></div>'
    '<script src="/static/main.js"></script></body></html>'
)


class FakeAdGuardHandler(BaseHTTPRequestHandler):
    """Enough of AdGuard Home's control API to exercise the proxy."""

    protocol_version = "HTTP/1.1"
    received: list[dict] = []

    def log_message(self, *a):  # silence
        pass

    def _authed(self) -> bool:
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        raw = base64.b64decode(header[6:]).decode()
        return raw == f"{UPSTREAM_USER}:{UPSTREAM_PASS}"

    def _record(self):
        type(self).received.append({
            "method": self.command,
            "path": self.path,
            "transfer_encoding": self.headers.get("Transfer-Encoding"),
            "content_length": self.headers.get("Content-Length"),
            "authorization": bool(self.headers.get("Authorization")),
        })

    def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # AdGuard sends these; the proxy must strip them for embedding.
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "frame-ancestors 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _handle(self):
        self._record()
        if not self._authed():
            self._send(401, b"unauthorized", "text/plain")
            return

        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            self._send(200, INDEX_HTML.encode(), "text/html; charset=utf-8")
        elif path == "/control/status":
            self._send(200, json.dumps({"version": "0.107.60", "running": True}).encode(),
                       "application/json")
        elif path == "/static/main.js":
            self._send(200, b"console.log('adguard');", "application/javascript")
        elif path == "/big":
            self._send(200, b"x" * (2 * 1024 * 1024), "application/octet-stream")
        elif path == "/control/login":
            self._send(302, b"", "text/plain",
                       {"Location": self.headers.get("X-Test-Base", "") + "/control/dashboard"})
        elif path == "/echo":
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            self._send(200, body or b"(empty)", "application/octet-stream")
        else:
            self._send(404, b"not found", "text/plain")

    do_GET = _handle
    do_POST = _handle
    do_HEAD = _handle


@pytest.fixture(scope="module")
def upstream():
    FakeAdGuardHandler.received = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeAdGuardHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


@pytest.fixture
def proxied_server(session, upstream):
    FakeAdGuardHandler.received = []
    s = Server(
        name="fake-agh",
        url=upstream,
        username=UPSTREAM_USER,
        password_enc=encrypt_secret(UPSTREAM_PASS),
    )
    session.add(s)
    session.commit()
    session.refresh(s)
    return s


@pytest.fixture
def ui_client(client, editor_headers, proxied_server):
    """A client holding a valid UI-session cookie, like the browser would."""
    resp = client.post(
        f"/api/servers/{proxied_server.id}/ui-session", headers=editor_headers
    )
    assert resp.status_code == 200, resp.text
    return client


# --------------------------------------------------------------------------- #
# The basics that were never covered
# --------------------------------------------------------------------------- #
def test_proxy_serves_the_upstream_html(ui_client, proxied_server):
    resp = ui_client.get(f"/api/servers/{proxied_server.id}/ui/")
    assert resp.status_code == 200, resp.text
    assert "AdGuard Home" in resp.text


def test_proxy_injects_basic_auth(ui_client, proxied_server):
    ui_client.get(f"/api/servers/{proxied_server.id}/ui/")
    assert FakeAdGuardHandler.received, "upstream was never reached"
    assert all(r["authorization"] for r in FakeAdGuardHandler.received)


def test_proxy_passes_json_endpoints_through(ui_client, proxied_server):
    resp = ui_client.get(f"/api/servers/{proxied_server.id}/ui/control/status")
    assert resp.status_code == 200, resp.text
    assert resp.json()["version"] == "0.107.60"


def test_proxy_strips_framing_headers(ui_client, proxied_server):
    resp = ui_client.get(f"/api/servers/{proxied_server.id}/ui/")
    assert "x-frame-options" not in resp.headers
    assert "content-security-policy" not in resp.headers


def test_absolute_paths_are_rewritten_to_the_prefix(ui_client, proxied_server):
    resp = ui_client.get(f"/api/servers/{proxied_server.id}/ui/")
    prefix = f"/api/servers/{proxied_server.id}/ui"
    assert f'href="{prefix}/static/main.css"' in resp.text
    assert f'src="{prefix}/static/main.js"' in resp.text


def test_static_assets_proxy_through(ui_client, proxied_server):
    resp = ui_client.get(f"/api/servers/{proxied_server.id}/ui/static/main.js")
    assert resp.status_code == 200
    assert b"adguard" in resp.content


def test_shim_is_injected_once(ui_client, proxied_server):
    resp = ui_client.get(f"/api/servers/{proxied_server.id}/ui/")
    assert resp.text.count("<script>(function(){var P=") == 1


def test_shim_uses_relative_paths_not_public_base_url(ui_client, proxied_server, monkeypatch):
    """Pinning rewritten URLs to PUBLIC_BASE_URL broke the proxy for anyone
    reaching the app on a different hostname."""
    from app.config import settings

    monkeypatch.setattr(settings, "public_base_url", "http://not-the-host-you-used:9999")
    resp = ui_client.get(f"/api/servers/{proxied_server.id}/ui/")
    assert "not-the-host-you-used" not in resp.text


def test_redirects_are_rewritten(ui_client, proxied_server):
    resp = ui_client.get(
        f"/api/servers/{proxied_server.id}/ui/control/login",
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["location"].startswith(f"/api/servers/{proxied_server.id}/ui/")


# --------------------------------------------------------------------------- #
# Regression guards for the streaming rewrite
# --------------------------------------------------------------------------- #
def test_bodyless_requests_are_not_sent_chunked(ui_client, proxied_server):
    """Streaming request bodies made httpx use chunked encoding even for GETs,
    which many servers reject outright."""
    ui_client.get(f"/api/servers/{proxied_server.id}/ui/control/status")
    got = [r for r in FakeAdGuardHandler.received if r["path"].endswith("/control/status")]
    assert got, "upstream never saw the request"
    assert got[-1]["transfer_encoding"] != "chunked", (
        "a GET was forwarded with Transfer-Encoding: chunked"
    )


def test_request_bodies_still_reach_the_upstream(ui_client, proxied_server):
    resp = ui_client.post(
        f"/api/servers/{proxied_server.id}/ui/echo", content=b"hello-upstream"
    )
    assert resp.status_code == 200, resp.text
    assert resp.content == b"hello-upstream"


def test_large_responses_stream_intact(ui_client, proxied_server):
    resp = ui_client.get(f"/api/servers/{proxied_server.id}/ui/big")
    assert resp.status_code == 200
    assert len(resp.content) == 2 * 1024 * 1024


def test_upstream_404_is_passed_through(ui_client, proxied_server):
    resp = ui_client.get(f"/api/servers/{proxied_server.id}/ui/nope")
    assert resp.status_code == 404


def test_unreachable_upstream_reports_502(client, editor_headers, session):
    s = Server(name="dead", url="http://127.0.0.1:1", username="u",
               password_enc=encrypt_secret("p"))
    session.add(s)
    session.commit()
    session.refresh(s)
    client.post(f"/api/servers/{s.id}/ui-session", headers=editor_headers)
    resp = client.get(f"/api/servers/{s.id}/ui/")
    assert resp.status_code == 502


# --------------------------------------------------------------------------- #
# Sandbox / cookie coherence. AdGuard's UI needs same-origin, so the cookie is
# Lax and the frame keeps allow-same-origin. These lock in that pairing.
# --------------------------------------------------------------------------- #
def test_frame_is_same_origin_with_a_lax_cookie(client, editor_headers, proxied_server):
    resp = client.post(f"/api/servers/{proxied_server.id}/ui-session", headers=editor_headers)
    body = resp.json()
    raw = resp.headers["set-cookie"].lower()

    assert body["isolation"] == "same-origin"
    assert "allow-same-origin" in body["sandbox"]
    assert "samesite=lax" in raw, raw
    assert "httponly" in raw


def test_cookie_is_secure_only_over_https(client, editor_headers, proxied_server, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "public_base_url", "https://admin.example.com")
    raw = client.post(
        f"/api/servers/{proxied_server.id}/ui-session", headers=editor_headers
    ).headers["set-cookie"].lower()
    assert "secure" in raw


def test_cors_allows_our_own_host_not_public_base_url(ui_client, proxied_server, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "public_base_url", "http://elsewhere.example:1234")
    resp = ui_client.options(
        f"/api/servers/{proxied_server.id}/ui/control/status",
        headers={"Origin": "http://testserver", "Access-Control-Request-Method": "GET"},
    )
    assert resp.status_code == 204
    assert resp.headers["access-control-allow-origin"] == "http://testserver"


def test_cors_still_refuses_foreign_origins(ui_client, proxied_server):
    resp = ui_client.options(
        f"/api/servers/{proxied_server.id}/ui/control/status",
        headers={"Origin": "http://evil.test", "Access-Control-Request-Method": "GET"},
    )
    assert resp.headers.get("access-control-allow-origin") != "http://evil.test"
