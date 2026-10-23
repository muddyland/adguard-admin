"""The agent CA: what it signs, what it refuses, and the hash the agent must match."""
from __future__ import annotations

import ssl
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app import pki
from app.certs import AGENT_MTLS_MARKER, verify_for
from app.models import AgentCA


def make_csr(cn: str = "host-a") -> tuple[str, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        # An agent might ask for any SAN it likes; the CA must ignore it.
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("evil.example")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    from cryptography.hazmat.primitives import serialization

    return csr.public_bytes(serialization.Encoding.PEM).decode(), key


def test_ca_is_created_once_and_cached(session):
    first = pki.ensure_ca(session)
    second = pki.ensure_ca(session)
    assert first.id == second.id
    assert session.query(AgentCA).count() == 1
    assert pki.get_pki().ca_cert_pem == first.ca_cert_pem


def test_client_cert_has_client_auth_only(session):
    material = pki.load_pki(session)
    cert = x509.load_pem_x509_certificate(material.client_cert_pem.encode())
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.CLIENT_AUTH]
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "adguard-admin"
    assert cert.issuer == x509.load_pem_x509_certificate(material.ca_cert_pem.encode()).subject


@pytest.mark.parametrize("address, expected", [
    ("10.0.0.11", x509.IPAddress),
    ("dns-a.lan", x509.DNSName),
    ("fd00::11", x509.IPAddress),
])
def test_agent_cert_takes_san_from_control_plane_not_csr(session, address, expected):
    material = pki.load_pki(session)
    csr_pem, _ = make_csr()
    cert_pem = pki.sign_agent_csr(material.ca_cert_pem, material.ca_key_pem, csr_pem, name="host-a", address=address)
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    entries = list(san)
    assert len(entries) == 1 and isinstance(entries[0], expected)
    assert "evil.example" not in [str(getattr(e, "value", "")) for e in entries]
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.SERVER_AUTH]
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is False
    # Signed by our CA.
    ca = x509.load_pem_x509_certificate(material.ca_cert_pem.encode())
    ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))


def test_garbage_csr_is_refused(session):
    material = pki.load_pki(session)
    with pytest.raises(pki.PkiError):
        pki.sign_agent_csr(material.ca_cert_pem, material.ca_key_pem, "not a csr", name="x", address="10.0.0.1")


def test_tampered_csr_signature_is_refused(session):
    material = pki.load_pki(session)
    csr_pem, _ = make_csr()
    # Flip a byte inside the base64 body (not the header/footer lines).
    lines = csr_pem.splitlines()
    body = lines[2]
    flipped = ("A" if body[5] != "A" else "B") + body[6:]
    lines[2] = body[:5] + flipped
    with pytest.raises(pki.PkiError):
        pki.sign_agent_csr(material.ca_cert_pem, material.ca_key_pem, "\n".join(lines), name="x", address="10.0.0.1")


def test_canonical_hash_matches_contract_vector():
    spec = {"b": [1, 2, {"z": True, "a": "é"}], "a": "x", "n": 3}
    assert pki.canonical_json(spec) == '{"a":"x","b":[1,2,{"a":"é","z":true}],"n":3}'
    # sha256 of the UTF-8 bytes of that string, computed independently.
    import hashlib

    assert pki.spec_hash(spec) == hashlib.sha256(
        '{"a":"x","b":[1,2,{"a":"é","z":true}],"n":3}'.encode("utf-8")
    ).hexdigest()


def test_needs_renewal_threshold():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert pki.needs_renewal(now + timedelta(days=30), now)
    assert not pki.needs_renewal(now + timedelta(days=300), now)
    assert not pki.needs_renewal(None, now)
    # Naive timestamps (SQLite) are treated as UTC rather than crashing.
    assert pki.needs_renewal((now + timedelta(days=1)).replace(tzinfo=None), now)


def test_verify_for_marker_returns_mutual_tls_context(session):
    pki.load_pki(session)
    ctx = verify_for(AGENT_MTLS_MARKER)
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.check_hostname is True
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3
    # The client chain is loaded: the context can report its cert store stats
    # and the material is on disk with a private mode.
    ca_file, cert_file, key_file = pki.materialize(pki.get_pki())
    import os

    assert oct(os.stat(key_file).st_mode & 0o777) == "0o600"
    # The ordinary pinned path still works as before.
    assert verify_for(None) is True
