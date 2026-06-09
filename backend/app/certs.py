"""Self-signed TLS certificate generation for provisioned servers.

When a server is provisioned with SSL, the admin app generates a cert/key pair
server-side (SAN = the address the admin app will use to reach the box). The
install script downloads them and configures AdGuard Home's TLS. The admin app
stores the cert and pins it when connecting, so it can verify the self-signed
certificate without a public CA.
"""
from __future__ import annotations

import ipaddress
import ssl
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_self_signed(address: str, valid_days: int = 3650) -> tuple[str, str]:
    """Return (cert_pem, key_pem) for the given hostname or IP."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, address)])

    try:
        san_entry = x509.IPAddress(ipaddress.ip_address(address))
    except ValueError:
        san_entry = x509.DNSName(address)

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(x509.SubjectAlternativeName([san_entry]), critical=False)
        # CA:TRUE so the cert can act as its own trust anchor when pinned.
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


def ssl_context_for(cert_pem: str) -> ssl.SSLContext:
    """Build an SSL context that trusts (only) the given pinned certificate."""
    ctx = ssl.create_default_context(cadata=cert_pem)
    return ctx


def verify_for(tls_cert: str | None):
    """httpx `verify` value: a pinned context if we have a cert, else default TLS."""
    return ssl_context_for(tls_cert) if tls_cert else True
