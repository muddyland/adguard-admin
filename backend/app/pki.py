"""The control plane's private CA for agent mutual TLS.

One CA per deployment, generated on first use and stored in the database with
its key Fernet-encrypted, like every other secret here. It signs two kinds of
certificate:

* **agent certificates** (EKU serverAuth only, SAN = the agent's connect
  address), issued against a CSR the agent generated on the box, so the private
  key never crosses the network;
* **one client certificate** for this app (EKU clientAuth, CN "adguard-admin"),
  which every agent requires before serving anything.

The EKU split is what stops a compromised host from using its own certificate
to talk to other agents as if it were the control plane.

httpx needs the client chain as files, so the material is written under
PKI_DIR (mode 0600) on demand; see `materialize`.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import ssl
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlmodel import Session, select

from .config import settings
from .models import AgentCA
from .security import decrypt_secret, encrypt_secret

logger = logging.getLogger("adguard_admin.pki")

CA_COMMON_NAME = "AdGuard Admin Agent CA"
CLIENT_COMMON_NAME = "adguard-admin"
CA_DAYS = 365 * 20
CLIENT_DAYS = 365 * 5
AGENT_DAYS = 365
# Renew an agent certificate once fewer than this many days remain.
RENEW_BEFORE_DAYS = 120


class PkiError(ValueError):
    """A certificate request that must not be signed."""


# --------------------------------------------------------------------------- #
# Primitives
# --------------------------------------------------------------------------- #
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _key_pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _cert_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _load_cert(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode())


def _load_key(pem: str):
    return serialization.load_pem_private_key(pem.encode(), password=None)


def generate_ca() -> tuple[str, str]:
    """Return (cert_pem, key_pem) for a fresh CA."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME)])
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return _cert_pem(cert), _key_pem(key)


def _issue(
    ca_cert_pem: str,
    ca_key_pem: str,
    public_key,
    *,
    common_name: str,
    days: int,
    eku: x509.ObjectIdentifier,
    san: list[x509.GeneralName] | None = None,
) -> str:
    ca_cert = _load_cert(ca_cert_pem)
    ca_key = _load_key(ca_key_pem)
    now = _now()
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=False, content_commitment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
    )
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
    return _cert_pem(builder.sign(ca_key, hashes.SHA256()))


def san_for(address: str) -> x509.GeneralName:
    try:
        return x509.IPAddress(ipaddress.ip_address(address))
    except ValueError:
        return x509.DNSName(address)


def sign_agent_csr(ca_cert_pem: str, ca_key_pem: str, csr_pem: str, *, name: str, address: str) -> str:
    """Sign an agent's CSR. Only the public key is taken from the CSR.

    The subject, SAN and extensions come from the control plane: the agent
    proves possession of a key, not a right to any particular name.
    """
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
    except Exception as exc:  # noqa: BLE001 - any parse failure is a bad request
        raise PkiError(f"invalid CSR: {exc}") from exc
    if not csr.is_signature_valid:
        raise PkiError("CSR signature does not verify")
    return _issue(
        ca_cert_pem, ca_key_pem, csr.public_key(),
        common_name=name[:64], days=AGENT_DAYS,
        eku=ExtendedKeyUsageOID.SERVER_AUTH, san=[san_for(address)],
    )


def issue_client_cert(ca_cert_pem: str, ca_key_pem: str) -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _issue(
        ca_cert_pem, ca_key_pem, key.public_key(),
        common_name=CLIENT_COMMON_NAME, days=CLIENT_DAYS,
        eku=ExtendedKeyUsageOID.CLIENT_AUTH,
    )
    return cert, _key_pem(key)


def cert_not_after(pem: str) -> datetime:
    cert = _load_cert(pem)
    try:
        return cert.not_valid_after_utc
    except AttributeError:  # pragma: no cover - older cryptography
        return cert.not_valid_after.replace(tzinfo=timezone.utc)


def fingerprint(pem: str) -> str:
    """SHA-256 of the DER certificate, hex, lowercase."""
    return _load_cert(pem).fingerprint(hashes.SHA256()).hex()


def canonical_json(spec) -> str:
    """The canonical form the agent hashes too; see docs/design/agent-api.md."""
    return json.dumps(spec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def spec_hash(spec) -> str:
    return hashlib.sha256(canonical_json(spec).encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# The deployment's CA
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Pki:
    ca_cert_pem: str
    ca_key_pem: str
    client_cert_pem: str
    client_key_pem: str

    @property
    def ca_fingerprint(self) -> str:
        return fingerprint(self.ca_cert_pem)


_lock = threading.Lock()
_cached: Pki | None = None
_materialized_for: str | None = None
_ssl_context: ssl.SSLContext | None = None


def ensure_ca(session: Session) -> AgentCA:
    """Return the CA row, creating it on first use."""
    row = session.exec(select(AgentCA)).first()
    if row is not None:
        return row
    ca_cert, ca_key = generate_ca()
    client_cert, client_key = issue_client_cert(ca_cert, ca_key)
    row = AgentCA(
        ca_cert_pem=ca_cert,
        ca_key_enc=encrypt_secret(ca_key),
        client_cert_pem=client_cert,
        client_key_enc=encrypt_secret(client_key),
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    logger.info("Generated the agent CA (fingerprint %s)", fingerprint(ca_cert))
    return row


def load_pki(session: Session) -> Pki:
    row = ensure_ca(session)
    return Pki(
        ca_cert_pem=row.ca_cert_pem,
        ca_key_pem=decrypt_secret(row.ca_key_enc) or "",
        client_cert_pem=row.client_cert_pem,
        client_key_pem=decrypt_secret(row.client_key_enc) or "",
    )


def pki_dir() -> Path:
    return Path(settings.resolved_pki_dir)


def materialize(pki: Pki) -> tuple[Path, Path, Path]:
    """Write (ca.crt, client.crt, client.key) under PKI_DIR, mode 0600.

    Idempotent and cheap after the first call for a given CA.
    """
    global _materialized_for, _ssl_context
    d = pki_dir()
    with _lock:
        key = pki.client_cert_pem
        paths = (d / "ca.crt", d / "client.crt", d / "client.key")
        if _materialized_for == key and all(p.is_file() for p in paths):
            return paths
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:  # pragma: no cover - e.g. a mount that ignores modes
            pass
        for path, content in zip(paths, (pki.ca_cert_pem, pki.client_cert_pem, pki.client_key_pem)):
            tmp = path.with_suffix(path.suffix + ".tmp")
            with open(tmp, "w", opener=lambda p, f: os.open(p, f, 0o600)) as fh:
                fh.write(content)
            os.replace(tmp, path)
        _materialized_for = key
        _ssl_context = None
        return paths


def client_ssl_context(pki: Pki) -> ssl.SSLContext:
    """An SSL context that trusts only our CA and presents our client cert."""
    global _ssl_context
    ca_file, cert_file, key_file = materialize(pki)
    with _lock:
        if _ssl_context is None:
            ctx = ssl.create_default_context(cafile=str(ca_file))
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.load_cert_chain(str(cert_file), str(key_file))
            ctx.check_hostname = True
            _ssl_context = ctx
        return _ssl_context


def get_pki() -> Pki:
    """Process-wide cached PKI (the CA never changes once created)."""
    global _cached
    if _cached is None:
        from .database import engine

        with _lock:
            if _cached is None:
                with Session(engine) as session:
                    _cached = load_pki(session)
    return _cached


def reset_cache() -> None:
    """Forget the cached CA (tests truncate the table between cases)."""
    global _cached, _materialized_for, _ssl_context
    with _lock:
        _cached = None
        _materialized_for = None
        _ssl_context = None


def needs_renewal(not_after: datetime | None, now: datetime | None = None) -> bool:
    if not_after is None:
        return False
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    now = now or _now()
    return not_after - now < timedelta(days=RENEW_BEFORE_DAYS)
