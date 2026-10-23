"""End to end over a real socket: the control plane's client talks to a server
that demands a certificate from our CA, exactly as the agent does."""
from __future__ import annotations

import json
import ssl
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app import pki
from app.agent_client import AgentClient, AgentError


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # quiet
        pass

    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        peer = self.connection.getpeercert()
        cn = dict(x[0] for x in peer["subject"])["commonName"]
        if self.path == "/v1/info":
            self._send(200, {"agent_version": "test", "client_cn": cn, "desired_hashes": {}})
        elif self.path == "/v1/health":
            self._send(200, {"load": [0, 0, 0]})
        else:
            self._send(404, {"error": "no such path"})

    def do_PUT(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        self._send(202, {"accepted": True, "hash": pki.spec_hash(body)})


def _agent_server(material: pki.Pki, *, address: str = "127.0.0.1", signer: pki.Pki | None = None):
    """Start an HTTPS server with an agent cert for `address`, requiring client certs."""
    signer = signer or material
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "host")]))
        .sign(key, hashes.SHA256())
    )
    cert_pem = pki.sign_agent_csr(
        signer.ca_cert_pem, signer.ca_key_pem,
        csr.public_bytes(serialization.Encoding.PEM).decode(), name="host", address=address,
    )
    d = tempfile.mkdtemp()
    cert_file, key_file, ca_file = f"{d}/s.crt", f"{d}/s.key", f"{d}/ca.crt"
    open(cert_file, "w").write(cert_pem)
    open(key_file, "w").write(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption()).decode()
    )
    open(ca_file, "w").write(material.ca_cert_pem)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert_file, key_file)
    ctx.load_verify_locations(cafile=ca_file)
    ctx.verify_mode = ssl.CERT_REQUIRED
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, f"https://127.0.0.1:{srv.server_address[1]}"


@pytest.fixture
def material(session):
    return pki.load_pki(session)


@pytest.mark.anyio
async def test_client_authenticates_with_our_client_cert(material):
    srv, url = _agent_server(material)
    try:
        async with AgentClient(url) as client:
            info = await client.info()
            assert info["client_cn"] == "adguard-admin"
            # A PUT round-trips and the agent's hash equals ours.
            spec = {"enabled": True, "dns_port": 53, "dns_bind": ["0.0.0.0"]}
            reply = await client.put_role("adguard", spec)
            assert reply["hash"] == pki.spec_hash(spec)
    finally:
        srv.shutdown()


@pytest.mark.anyio
async def test_server_without_client_cert_is_rejected(material):
    """A caller that trusts our CA but has no client certificate gets no data."""
    srv, url = _agent_server(material)
    try:
        ca_file = pki.materialize(material)[0]
        async with httpx.AsyncClient(verify=str(ca_file)) as plain:
            # TLS 1.3 sends the server's "certificate required" alert after the
            # client already considers the handshake done, so it races the
            # request: caught while connecting it arrives wrapped in an httpx
            # error, caught on the response read httpcore lets the raw
            # ssl.SSLError through. Either way the caller gets no data.
            with pytest.raises((httpx.HTTPError, ssl.SSLError)) as exc:
                await plain.get(url + "/v1/info")
            if isinstance(exc.value, ssl.SSLError):
                assert "CERTIFICATE_REQUIRED" in str(exc.value).upper(), exc.value
    finally:
        srv.shutdown()


@pytest.mark.anyio
async def test_agent_cert_from_another_ca_is_rejected(material):
    other_cert, other_key = pki.generate_ca()
    other_client = pki.issue_client_cert(other_cert, other_key)
    rogue = pki.Pki(ca_cert_pem=other_cert, ca_key_pem=other_key,
                    client_cert_pem=other_client[0], client_key_pem=other_client[1])
    srv, url = _agent_server(material, signer=rogue)
    try:
        async with AgentClient(url) as client:
            with pytest.raises(AgentError) as exc:
                await client.info()
            assert "failed" in str(exc.value)
    finally:
        srv.shutdown()


@pytest.mark.anyio
async def test_san_mismatch_is_rejected(material):
    """The cert was issued for another address: hostname verification must fail."""
    srv, url = _agent_server(material, address="10.9.9.9")
    try:
        async with AgentClient(url) as client:
            with pytest.raises(AgentError):
                await client.info()
    finally:
        srv.shutdown()


@pytest.mark.anyio
async def test_agent_error_carries_status_and_message(material):
    srv, url = _agent_server(material)
    try:
        async with AgentClient(url) as client:
            with pytest.raises(AgentError) as exc:
                await client.get_role("nothing")
            assert exc.value.status_code == 404
            assert "no such path" in str(exc.value)
    finally:
        srv.shutdown()
