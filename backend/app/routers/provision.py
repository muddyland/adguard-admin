"""Token-based host provisioning.

Flow:
  1. An editor requests a new host (name, zone, roles) -> a ProvisioningToken is
     created and a one-line install command is shown.
  2. On the target box the operator runs the one-liner, which pipes a generated
     install.sh into bash. That script (authenticated only by the token in the
     URL) downloads the agent binary, verifies its checksum, and runs
     `adguard-admin-agent enroll`.
  3. The agent generates a key on the box and POSTs a CSR to /enroll. We sign it,
     create the Agent row and the Server / LoadBalancer rows the token asked
     for, and the token is consumed.
  4. The agent starts serving over mutual TLS. Reconciliation pushes the AdGuard
     and dnsdist specs to it and the host converges; nothing else is fetched or
     executed from a token URL.

Compared with the previous flow, no shell-sourced config is eval'd on the box,
the AdGuard admin password travels only over mTLS, and the private key never
leaves the host.
"""
from __future__ import annotations

import asyncio
import logging
import re
import shlex
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from sqlmodel import select

from ..certs import AGENT_MTLS_MARKER
from ..config import settings
from ..deps import RequireEditor, SessionDep
from ..hosts import adguard_url_via_agent, agent_url, reconcile_agent, reconcile_load_balancer
from ..models import (
    Agent,
    AgentRole,
    LbMode,
    LoadBalancer,
    ProvisioningToken,
    ProvisionStatus,
    Server,
    SyncStatus,
    Zone,
)
from ..pki import PkiError, cert_not_after, load_pki, sign_agent_csr
from ..schemas import EnrollRequest, EnrollResponse, ProvisionRequest, ProvisionTokenRead
from ..security import encrypt_secret, generate_token
from ..validators import MAX_NAME_LENGTH, ValidationError, validate_host

router = APIRouter(prefix="/api/provision", tags=["provision"])

logger = logging.getLogger("adguard_admin.provision")

# How long after enrollment to give the agent's service time to start before
# the first push. The periodic loop would get there anyway; this is for the
# operator watching the Servers page.
FIRST_RECONCILE_DELAY_SECONDS = 5.0


def _command(token: str) -> str:
    base = settings.public_base_url.rstrip("/")
    return f'curl -fsSL "{base}/api/provision/{token}/install.sh" | sudo bash'


def _to_read(t: ProvisioningToken) -> ProvisionTokenRead:
    return ProvisionTokenRead(
        id=t.id, name=t.name, zone_id=t.zone_id, roles=list(t.roles or ["adguard"]),
        method=t.method, auto_update=t.auto_update, connect_address=t.connect_address,
        agent_port=t.agent_port, vrrp_priority=t.vrrp_priority, expose_web_ui=t.expose_web_ui,
        lb_mode=t.lb_mode or LbMode.dnsdist,
        status=t.status, token=t.token, command=_command(t.token), created_at=t.created_at,
        expires_at=t.expires_at, completed_at=t.completed_at, server_id=t.server_id,
        agent_id=t.agent_id, load_balancer_id=t.load_balancer_id,
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
    roles = [r.value for r in payload.roles]
    if AgentRole.dnsdist.value in roles:
        if payload.zone_id is None:
            raise HTTPException(
                status_code=400,
                detail="A balancer needs a zone: its backends are the zone's AdGuard servers",
            )
        from .loadbalancers import validate_zone_mode

        validate_zone_mode(session, session.get(Zone, payload.zone_id), payload.lb_mode)

    t = ProvisioningToken(
        token=generate_token(),
        name=payload.name,
        zone_id=payload.zone_id,
        method=payload.method,
        prune=payload.prune,
        auto_update=(
            settings.auto_update_default if payload.auto_update is None else payload.auto_update
        ),
        connect_address=payload.connect_address,
        roles=roles,
        agent_port=payload.agent_port or settings.agent_default_port,
        vrrp_priority=payload.vrrp_priority,
        expose_web_ui=payload.expose_web_ui,
        lb_mode=payload.lb_mode,
        http_port=3000,
        https_port=443,
        dns_port=settings.adguard_dns_port,
        admin_username="admin",
        admin_password_enc=encrypt_secret(generate_token(18)),
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


@router.post("/tokens/{token_id}/revoke", response_model=ProvisionTokenRead)
def revoke_token(token_id: int, _: RequireEditor, session: SessionDep):
    """Invalidate a pending token (the one-liner stops working) but keep the record."""
    t = session.get(ProvisioningToken, token_id)
    if not t:
        raise HTTPException(status_code=404, detail="Token not found")
    if t.status == ProvisionStatus.pending:
        t.status = ProvisionStatus.revoked
        session.add(t)
        session.commit()
        session.refresh(t)
    return _to_read(t)


@router.delete("/tokens/{token_id}", status_code=204)
def delete_token(token_id: int, _: RequireEditor, session: SessionDep):
    """Permanently remove a token record of any status from the list."""
    t = session.get(ProvisioningToken, token_id)
    if not t:
        raise HTTPException(status_code=404, detail="Token not found")
    session.delete(t)
    session.commit()


# --------------------------------------------------------------------------- #
# Token-authenticated endpoints (consumed on the target box)
# --------------------------------------------------------------------------- #
@router.get("/{token}/install.sh", response_class=PlainTextResponse)
def install_script(token: str, session: SessionDep):
    t = _valid_pending(session, token)
    return PlainTextResponse(
        _render_install_script(t),
        media_type="text/x-shellscript",
    )


async def _first_reconcile(agent_id: int, lb_id: int | None) -> None:
    await asyncio.sleep(FIRST_RECONCILE_DELAY_SECONDS)
    try:
        await reconcile_agent(agent_id)
        if lb_id is not None:
            await reconcile_load_balancer(lb_id)
    except Exception:  # noqa: BLE001 - the periodic loop retries
        logger.exception("first reconcile of agent id=%s failed", agent_id)


@router.post("/{token}/enroll", response_model=EnrollResponse)
async def enroll(token: str, payload: EnrollRequest, session: SessionDep):
    """Sign the agent's CSR and create the rows the token asked for.

    Single use: the token flips to completed in the same transaction, so a
    replayed request (the URL is log-visible) gets 409 and no certificate.
    """
    t = _valid_pending(session, token)
    address = t.connect_address or payload.address
    if not address:
        raise HTTPException(status_code=400, detail="No address reported and none preconfigured")
    try:
        address = validate_host(address, field="address")
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    port = payload.port or t.agent_port or settings.agent_default_port

    pki = load_pki(session)
    try:
        cert = sign_agent_csr(pki.ca_cert_pem, pki.ca_key_pem, payload.csr_pem, name=t.name, address=address)
    except PkiError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    agent = Agent(
        name=t.name,
        url=agent_url(address, port),
        address=address,
        port=port,
        zone_id=t.zone_id,
        hostname=payload.hostname,
        os=payload.os,
        arch=payload.arch,
        version=payload.agent_version,
        cert_pem=cert,
        cert_not_after=cert_not_after(cert),
        status=SyncStatus.unknown,
    )
    session.add(agent)
    session.commit()
    session.refresh(agent)

    roles = set(t.roles or ["adguard"])
    server = lb = None
    if AgentRole.adguard.value in roles:
        server = Server(
            name=t.name,
            url=adguard_url_via_agent(agent),
            username=t.admin_username,
            password_enc=t.admin_password_enc,  # already encrypted on the token
            zone_id=t.zone_id,
            enabled=True,
            prune=t.prune,
            auto_update=t.auto_update,
            install_method=t.method,
            tls_cert=AGENT_MTLS_MARKER,
            agent_id=agent.id,
            dns_port=settings.adguard_dns_port,
            expose_web_ui=t.expose_web_ui,
            status=SyncStatus.provisioning,
        )
        session.add(server)
    if AgentRole.dnsdist.value in roles:
        lb = LoadBalancer(
            name=t.name,
            zone_id=t.zone_id,
            agent_id=agent.id,
            image=settings.dnsdist_image,
            vrrp_priority=t.vrrp_priority,
            mode=t.lb_mode or LbMode.dnsdist,
        )
        session.add(lb)
    session.commit()

    t.status = ProvisionStatus.completed
    t.completed_at = datetime.now(timezone.utc)
    t.agent_id = agent.id
    t.server_id = server.id if server else None
    t.load_balancer_id = lb.id if lb else None
    session.add(t)
    session.commit()
    logger.info(
        "enrolled agent %r (id=%s) at %s with roles %s", agent.name, agent.id, agent.url, sorted(roles)
    )

    asyncio.get_running_loop().create_task(_first_reconcile(agent.id, lb.id if lb else None))
    return EnrollResponse(
        agent_id=agent.id, name=agent.name, cert_pem=cert, ca_pem=pki.ca_cert_pem,
        not_after=cert_not_after(cert),
    )


# --------------------------------------------------------------------------- #
# install.sh template
# --------------------------------------------------------------------------- #
def _comment_safe(value: str) -> str:
    """Collapse anything that could terminate a shell comment line.

    Names are validated on creation, but tokens issued before that validation
    existed are still in the database, and this string is rendered into a script
    that runs as root.
    """
    return re.sub(r"[\x00-\x1f\x7f]", " ", value or "")[:MAX_NAME_LENGTH]


def _render_install_script(t: ProvisioningToken) -> str:
    base = settings.public_base_url.rstrip("/")
    listen = f"0.0.0.0:{int(t.agent_port or settings.agent_default_port)}"
    return f"""#!/usr/bin/env bash
# AdGuard Admin — installs and enrolls the host agent for {_comment_safe(t.name)}
# Generated for a single-use token. The agent is the only thing this script
# installs; AdGuard Home / dnsdist are set up by the control plane afterwards.
set -euo pipefail

BASE_URL={shlex.quote(base)}
TOKEN={shlex.quote(t.token)}
LISTEN={shlex.quote(listen)}
ADDRESS={shlex.quote(t.connect_address or "")}
BIN=/usr/local/bin/adguard-admin-agent
UNIT=/etc/systemd/system/adguard-admin-agent.service

green(){{ printf '\\033[0;32m[adguard-admin]\\033[0m %s\\n' "$*"; }}
red(){{ printf '\\033[0;31m[adguard-admin]\\033[0m %s\\n' "$*" >&2; }}

[ "$(id -u)" -eq 0 ] || {{ red "Please run as root (the one-liner uses sudo)."; exit 1; }}
command -v curl >/dev/null 2>&1 || {{ red "curl is required."; exit 1; }}
command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] || {{ red "systemd is required to run the agent as a service."; exit 1; }}
case "$BASE_URL" in
  https://*) ;;
  *) red "Warning: the control plane is reached over plain HTTP; the enrollment token and the issued certificate are visible on the network. Put it behind HTTPS." ;;
esac

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  armv7l|armv6l|armhf) ARCH=arm ;;
  *) red "Unsupported architecture: $(uname -m)"; exit 1 ;;
esac

green "Downloading the agent for linux/$ARCH ..."
MANIFEST="$(curl -fsSL "$BASE_URL/api/agents/download/manifest")" || {{ red "Could not fetch the agent manifest from $BASE_URL — is the admin app reachable from this host?"; exit 1; }}
# The manifest is small JSON; pull the checksum for our arch without needing jq.
WANT_SHA="$(printf '%s' "$MANIFEST" | tr -d '\\n ' | sed -n 's/.*"linux\\/'"$ARCH"'":{{"sha256":"\\([0-9a-f]*\\)".*/\\1/p')"
[ -n "$WANT_SHA" ] || {{ red "The control plane has no agent build for linux/$ARCH."; exit 1; }}
TMP="$(mktemp)"
curl -fsSL "$BASE_URL/api/agents/download/linux/$ARCH" -o "$TMP"
GOT_SHA="$(sha256sum "$TMP" | awk '{{print $1}}')"
[ "$GOT_SHA" = "$WANT_SHA" ] || {{ red "Checksum mismatch for the downloaded agent (got $GOT_SHA, want $WANT_SHA)."; rm -f "$TMP"; exit 1; }}
install -m 0755 "$TMP" "$BIN"
rm -f "$TMP"
green "Installed $("$BIN" version)"

green "Enrolling with the control plane ..."
ENROLL_ARGS=(--url "$BASE_URL" --token "$TOKEN" --listen "$LISTEN")
if [ -n "$ADDRESS" ]; then ENROLL_ARGS+=(--address "$ADDRESS"); fi
"$BIN" enroll "${{ENROLL_ARGS[@]}}"

green "Installing the systemd service ..."
cat > "$UNIT" <<'UNIT_EOF'
[Unit]
Description=AdGuard Admin host agent
After=network-online.target docker.service
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/adguard-admin-agent serve
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT_EOF
systemctl daemon-reload
systemctl enable --now adguard-admin-agent
sleep 1
systemctl is-active --quiet adguard-admin-agent && green "Agent is running on $LISTEN." || {{ red "The agent did not start; see: journalctl -u adguard-admin-agent"; exit 1; }}
green "Done. The control plane will now install and configure this host's roles; watch the Hosts page."
"""
