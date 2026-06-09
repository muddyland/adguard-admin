"""Token-based server provisioning.

Flow:
  1. An editor requests a new server (name, zone, method, SSL) -> a ProvisioningToken
     is created. If SSL is requested we generate a self-signed cert (SAN = the
     address the admin app will use) and return a one-line install command.
  2. On the target box the operator runs the one-liner, which pipes a generated
     install.sh into bash. That script (authenticated only by the token in the URL):
       - fetches its config,
       - installs AdGuard Home (Docker or bare-metal),
       - configures the admin account, and TLS if requested,
       - calls back to /complete, which creates the Server record so reconciliation
         takes over automatically.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from sqlmodel import select

from ..config import settings
from ..deps import RequireEditor, SessionDep
from ..certs import generate_self_signed
from ..models import (
    ProvisioningToken,
    ProvisionStatus,
    Server,
    SyncStatus,
    Zone,
)
from ..schemas import ProvisionComplete, ProvisionRequest, ProvisionTokenRead
from ..security import decrypt_secret, encrypt_secret, generate_token

router = APIRouter(prefix="/api/provision", tags=["provision"])


def _command(token: str) -> str:
    base = settings.public_base_url.rstrip("/")
    return f'curl -fsSL "{base}/api/provision/{token}/install.sh" | sudo bash'


def _to_read(t: ProvisioningToken) -> ProvisionTokenRead:
    return ProvisionTokenRead(
        id=t.id, name=t.name, zone_id=t.zone_id, method=t.method,
        ssl_enabled=t.ssl_enabled, connect_address=t.connect_address,
        http_port=t.http_port, https_port=t.https_port, status=t.status,
        token=t.token, command=_command(t.token), created_at=t.created_at,
        expires_at=t.expires_at, completed_at=t.completed_at, server_id=t.server_id,
    )


def _valid_pending(session: SessionDep, token: str) -> ProvisioningToken:
    t = session.exec(select(ProvisioningToken).where(ProvisioningToken.token == token)).first()
    if not t:
        raise HTTPException(status_code=404, detail="Unknown token")
    if t.status == ProvisionStatus.revoked:
        raise HTTPException(status_code=410, detail="Token revoked")
    if t.status == ProvisionStatus.completed:
        raise HTTPException(status_code=409, detail="Token already used")
    # SQLite returns naive datetimes; treat stored timestamps as UTC.
    expires_at = t.expires_at if t.expires_at.tzinfo else t.expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=410, detail="Token expired")
    return t


# --------------------------------------------------------------------------- #
# Admin (JWT) endpoints
# --------------------------------------------------------------------------- #
@router.post("/tokens", response_model=ProvisionTokenRead)
def create_token(payload: ProvisionRequest, _: RequireEditor, session: SessionDep):
    if payload.zone_id is not None and not session.get(Zone, payload.zone_id):
        raise HTTPException(status_code=400, detail="zone_id does not exist")
    if payload.ssl_enabled and not payload.connect_address:
        raise HTTPException(status_code=400, detail="connect_address (FQDN or IP) is required for SSL")

    http_port = payload.http_port or settings.adguard_default_http_port
    https_port = payload.https_port or settings.adguard_default_https_port

    tls_cert = tls_key_enc = None
    if payload.ssl_enabled:
        cert_pem, key_pem = generate_self_signed(payload.connect_address)
        tls_cert, tls_key_enc = cert_pem, encrypt_secret(key_pem)

    t = ProvisioningToken(
        token=generate_token(),
        name=payload.name,
        zone_id=payload.zone_id,
        method=payload.method,
        prune=payload.prune,
        ssl_enabled=payload.ssl_enabled,
        connect_address=payload.connect_address,
        http_port=http_port,
        https_port=https_port,
        dns_port=settings.adguard_dns_port,
        admin_username="admin",
        admin_password_enc=encrypt_secret(generate_token(18)),
        tls_cert=tls_cert,
        tls_key_enc=tls_key_enc,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=settings.provision_token_ttl_hours),
    )
    session.add(t)
    session.commit()
    session.refresh(t)
    return _to_read(t)


@router.get("/tokens", response_model=list[ProvisionTokenRead])
def list_tokens(_: RequireEditor, session: SessionDep):
    rows = session.exec(select(ProvisioningToken).order_by(ProvisioningToken.created_at.desc())).all()
    return [_to_read(t) for t in rows]


@router.delete("/tokens/{token_id}", status_code=204)
def revoke_token(token_id: int, _: RequireEditor, session: SessionDep):
    t = session.get(ProvisioningToken, token_id)
    if not t:
        raise HTTPException(status_code=404, detail="Token not found")
    if t.status == ProvisionStatus.pending:
        t.status = ProvisionStatus.revoked
        session.add(t)
        session.commit()


# --------------------------------------------------------------------------- #
# Token-authenticated endpoints (consumed by install.sh on the target box)
# --------------------------------------------------------------------------- #
@router.get("/{token}/config", response_class=PlainTextResponse)
def get_config(token: str, session: SessionDep):
    """Shell-sourceable config (avoids a jq dependency on the target)."""
    t = _valid_pending(session, token)
    password = decrypt_secret(t.admin_password_enc) or ""
    lines = [
        f"METHOD={t.method.value}",
        f"SSL={'true' if t.ssl_enabled else 'false'}",
        f"HTTP_PORT={t.http_port}",
        f"HTTPS_PORT={t.https_port}",
        f"DNS_PORT={t.dns_port}",
        f"ADMIN_USER='{t.admin_username}'",
        f"ADMIN_PASSWORD='{password}'",
        f"CONNECT_ADDRESS='{t.connect_address or ''}'",
        f"SERVER_NAME='{t.name}'",
    ]
    return "\n".join(lines) + "\n"


@router.get("/{token}/cert.pem", response_class=PlainTextResponse)
def get_cert(token: str, session: SessionDep):
    t = _valid_pending(session, token)
    if not t.ssl_enabled or not t.tls_cert:
        raise HTTPException(status_code=404, detail="No certificate for this token")
    return t.tls_cert


@router.get("/{token}/key.pem", response_class=PlainTextResponse)
def get_key(token: str, session: SessionDep):
    t = _valid_pending(session, token)
    key = decrypt_secret(t.tls_key_enc) if t.ssl_enabled else None
    if not key:
        raise HTTPException(status_code=404, detail="No private key for this token")
    return key


@router.get("/{token}/install.sh", response_class=PlainTextResponse)
def install_script(token: str, session: SessionDep):
    t = _valid_pending(session, token)
    return PlainTextResponse(
        _render_install_script(t),
        media_type="text/x-shellscript",
    )


@router.post("/{token}/complete")
def complete(token: str, payload: ProvisionComplete, session: SessionDep):
    t = _valid_pending(session, token)
    address = payload.address or t.connect_address
    if not address:
        raise HTTPException(status_code=400, detail="No address provided and none preconfigured")

    http_port = payload.http_port or t.http_port
    https_port = payload.https_port or t.https_port
    if t.ssl_enabled:
        url = f"https://{address}:{https_port}"
    else:
        url = f"http://{address}:{http_port}"

    server = Server(
        name=t.name,
        url=url,
        username=t.admin_username,
        password_enc=t.admin_password_enc,  # already encrypted on the token
        zone_id=t.zone_id,
        enabled=True,
        prune=t.prune,
        tls_cert=t.tls_cert if t.ssl_enabled else None,
        status=SyncStatus.unknown,
    )
    session.add(server)
    session.commit()
    session.refresh(server)

    t.status = ProvisionStatus.completed
    t.completed_at = datetime.now(timezone.utc)
    t.server_id = server.id
    session.add(t)
    session.commit()
    return {"ok": True, "server_id": server.id, "url": url}


# --------------------------------------------------------------------------- #
# install.sh template
# --------------------------------------------------------------------------- #
def _render_install_script(t: ProvisioningToken) -> str:
    base = settings.public_base_url.rstrip("/")
    return f"""#!/usr/bin/env bash
# AdGuard Admin — automated provisioning for "{t.name}"
# This script is generated for a single token and installs + registers a server.
set -euo pipefail

BASE_URL="{base}"
TOKEN="{t.token}"

green(){{ printf '\\033[0;32m[adguard-admin]\\033[0m %s\\n' "$*"; }}
red(){{ printf '\\033[0;31m[adguard-admin]\\033[0m %s\\n' "$*" >&2; }}

[ "$(id -u)" -eq 0 ] || {{ red "Please run as root (the one-liner uses sudo)."; exit 1; }}
command -v curl >/dev/null 2>&1 || {{ red "curl is required."; exit 1; }}

green "Fetching configuration..."
CONFIG="$(curl -fsSL "$BASE_URL/api/provision/$TOKEN/config")" || {{ red "Invalid or expired token."; exit 1; }}
# shellcheck disable=SC1090
eval "$CONFIG"

CERT_DIR="/opt/adguard-provision"
CERT_PATH="$CERT_DIR/cert.pem"
KEY_PATH="$CERT_DIR/key.pem"

if [ "$SSL" = "true" ]; then
  green "Installing TLS certificate (provisioned by the admin server)..."
  mkdir -p "$CERT_DIR"; chmod 700 "$CERT_DIR"
  curl -fsSL "$BASE_URL/api/provision/$TOKEN/cert.pem" -o "$CERT_PATH"
  curl -fsSL "$BASE_URL/api/provision/$TOKEN/key.pem" -o "$KEY_PATH"
  chmod 600 "$CERT_PATH" "$KEY_PATH"
fi

install_docker() {{
  if ! command -v docker >/dev/null 2>&1; then
    green "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
  fi
  green "Starting AdGuard Home container..."
  docker rm -f adguardhome >/dev/null 2>&1 || true
  EXTRA=()
  if [ "$SSL" = "true" ]; then EXTRA+=(-v "$CERT_DIR:/certs:ro" -p "$HTTPS_PORT:443/tcp"); fi
  docker run -d --name adguardhome --restart unless-stopped \\
    -v adguardhome-work:/opt/adguardhome/work \\
    -v adguardhome-conf:/opt/adguardhome/conf \\
    -p "$DNS_PORT:53/tcp" -p "$DNS_PORT:53/udp" \\
    -p "$HTTP_PORT:3000/tcp" \\
    "${{EXTRA[@]}}" \\
    adguard/adguardhome >/dev/null
  SETUP_PORT="$HTTP_PORT"          # host port mapped to the container's 3000
  WEB_PORT=3000                    # keep the container's web port at 3000
  MGMT_PORT="$HTTP_PORT"           # reachable on the host
  CERT_FILE="/certs/cert.pem"; KEY_FILE="/certs/key.pem"
}}

install_bare() {{
  if [ ! -d /opt/AdGuardHome ]; then
    green "Installing AdGuard Home (bare-metal)..."
    curl -fsSL https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v
  fi
  SETUP_PORT=3000                  # first-run wizard listens on 3000
  WEB_PORT="$HTTP_PORT"            # move the admin UI to the desired port
  MGMT_PORT="$HTTP_PORT"
  CERT_FILE="$CERT_PATH"; KEY_FILE="$KEY_PATH"
}}

if [ "$METHOD" = "docker" ]; then install_docker; else install_bare; fi

green "Waiting for AdGuard Home to come up..."
for _ in $(seq 1 30); do
  curl -fsS "http://127.0.0.1:$SETUP_PORT/control/install/get_addresses" >/dev/null 2>&1 && break
  sleep 2
done

green "Configuring admin account..."
curl -fsS -X POST "http://127.0.0.1:$SETUP_PORT/control/install/configure" \\
  -H 'Content-Type: application/json' \\
  -d "{{\\"web\\":{{\\"ip\\":\\"0.0.0.0\\",\\"port\\":$WEB_PORT}},\\"dns\\":{{\\"ip\\":\\"0.0.0.0\\",\\"port\\":$DNS_PORT}},\\"username\\":\\"$ADMIN_USER\\",\\"password\\":\\"$ADMIN_PASSWORD\\"}}" >/dev/null || true
sleep 3

if [ "$SSL" = "true" ]; then
  green "Enabling TLS on the server..."
  curl -fsS -u "$ADMIN_USER:$ADMIN_PASSWORD" -X POST "http://127.0.0.1:$MGMT_PORT/control/tls/configure" \\
    -H 'Content-Type: application/json' \\
    -d "{{\\"enabled\\":true,\\"server_name\\":\\"$CONNECT_ADDRESS\\",\\"force_https\\":false,\\"port_https\\":$HTTPS_PORT,\\"port_dns_over_tls\\":853,\\"port_dns_over_quic\\":0,\\"certificate_path\\":\\"$CERT_FILE\\",\\"private_key_path\\":\\"$KEY_FILE\\",\\"certificate_chain\\":\\"\\",\\"private_key\\":\\"\\",\\"private_key_saved\\":false}}" >/dev/null \\
    || red "TLS configure failed — verify cert paths and that port $HTTPS_PORT is free."
fi

if [ -n "${{CONNECT_ADDRESS:-}}" ]; then ADDR="$CONNECT_ADDRESS"; else ADDR="$(hostname -I 2>/dev/null | awk '{{print $1}}')"; fi

green "Registering with AdGuard Admin..."
curl -fsS -X POST "$BASE_URL/api/provision/$TOKEN/complete" \\
  -H 'Content-Type: application/json' \\
  -d "{{\\"address\\":\\"$ADDR\\",\\"http_port\\":$HTTP_PORT,\\"https_port\\":$HTTPS_PORT}}" >/dev/null

if [ "$SSL" = "true" ]; then
  green "Done. '$SERVER_NAME' is up at https://$ADDR:$HTTPS_PORT and registered."
else
  green "Done. '$SERVER_NAME' is up at http://$ADDR:$HTTP_PORT and registered."
fi
"""
