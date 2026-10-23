"""Hosts: the agents enrolled through provisioning, and the agent binaries.

`/download/*` is deliberately unauthenticated: the binary and its checksum
manifest are public artefacts the install one-liner needs before the host has
any credential for this app, exactly like the old `docker-agent.sh`.
"""
from __future__ import annotations

import logging
import os

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse
from sqlmodel import select

from ..agent_client import SERVICES, AgentClient, AgentError
from ..config import settings
from ..deps import CurrentUser, RequireAdmin, RequireEditor, SessionDep
from .. import agent_bin
from ..hosts import reconcile_agent, release_references, update_agent_now
from ..models import Agent, LbMode, LoadBalancer, Server, SyncStatus, Zone
from ..pki import cert_not_after, get_pki, sign_agent_csr
from ..schemas import AgentLogs, AgentRead, AgentServiceResult, AgentUpdate

router = APIRouter(prefix="/api/agents", tags=["agents"])

logger = logging.getLogger("adguard_admin.agents")

ARCHES = agent_bin.ARCHES


def to_read(session, agent: Agent) -> AgentRead:
    server_ids = list(session.exec(select(Server.id).where(Server.agent_id == agent.id)).all())
    lbs = list(session.exec(select(LoadBalancer).where(LoadBalancer.agent_id == agent.id)).all())
    lb_ids = [lb.id for lb in lbs]
    roles = []
    if server_ids:
        roles.append("adguard")
    # The balancer role is named after what actually runs on the host: dnsdist
    # in dnsdist mode, keepalived (VRRP + IPVS) in ipvs mode.
    if any(lb.mode == LbMode.dnsdist for lb in lbs):
        roles.append("dnsdist")
    if any(lb.mode == LbMode.ipvs for lb in lbs):
        roles.append("keepalived")
    item = AgentRead.model_validate(agent, from_attributes=True)
    item.roles = roles
    item.server_ids = server_ids
    item.load_balancer_ids = lb_ids
    shipped = agent_bin.shipped_version()
    item.update_available = bool(shipped and (agent.version or "").strip() != shipped)
    return item


def _get(session, agent_id: int) -> Agent:
    agent = session.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Host not found")
    return agent


# --------------------------------------------------------------------------- #
# Downloads (public)
# --------------------------------------------------------------------------- #
def build_manifest() -> dict:
    return agent_bin.build_manifest()


@router.get("/download/manifest")
def download_manifest():
    manifest = build_manifest()
    if not manifest["files"]:
        raise HTTPException(
            status_code=404,
            detail="No agent binaries are available on this control plane (AGENT_BIN_DIR is empty).",
        )
    return manifest


@router.get("/download/linux/{arch}")
def download_binary(arch: str):
    if arch not in ARCHES:
        raise HTTPException(status_code=404, detail="Unknown architecture")
    p = agent_bin.binary_path(arch)
    if not p.is_file():
        raise HTTPException(status_code=404, detail=f"No agent build for linux/{arch}")
    return FileResponse(
        p, media_type="application/octet-stream", filename="adguard-admin-agent",
    )


# --------------------------------------------------------------------------- #
# Hosts (JWT)
# --------------------------------------------------------------------------- #
@router.get("", response_model=list[AgentRead])
def list_agents(_: CurrentUser, session: SessionDep):
    return [to_read(session, a) for a in session.exec(select(Agent).order_by(Agent.name)).all()]


@router.get("/{agent_id}", response_model=AgentRead)
def get_agent(agent_id: int, _: CurrentUser, session: SessionDep):
    return to_read(session, _get(session, agent_id))


@router.patch("/{agent_id}", response_model=AgentRead)
def update_agent(agent_id: int, payload: AgentUpdate, _: RequireEditor, session: SessionDep):
    agent = _get(session, agent_id)
    data = payload.model_dump(exclude_unset=True)
    if "zone_id" in data and data["zone_id"] is not None and not session.get(Zone, data["zone_id"]):
        raise HTTPException(status_code=400, detail="zone_id does not exist")
    for key, value in data.items():
        setattr(agent, key, value)
    session.add(agent)
    session.commit()
    session.refresh(agent)
    return to_read(session, agent)


@router.post("/{agent_id}/refresh", response_model=AgentRead)
async def refresh_agent(agent_id: int, _: CurrentUser, session: SessionDep):
    _get(session, agent_id)
    session.commit()  # release the connection before the network round-trip
    await reconcile_agent(agent_id)
    session.expire_all()
    return to_read(session, _get(session, agent_id))


@router.get("/{agent_id}/logs", response_model=AgentLogs)
async def agent_logs(
    agent_id: int, _: RequireEditor, session: SessionDep,
    service: str = Query("agent"), lines: int = Query(200, ge=1, le=2000),
):
    if service not in SERVICES:
        raise HTTPException(status_code=400, detail=f"service must be one of {', '.join(SERVICES)}")
    agent = _get(session, agent_id)
    url = agent.url
    session.commit()
    try:
        async with AgentClient(url) as client:
            return AgentLogs(lines=await client.logs(service, lines))
    except AgentError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@router.post("/{agent_id}/services/{service}/restart", response_model=AgentServiceResult)
async def restart_service(agent_id: int, service: str, _: RequireEditor, session: SessionDep):
    if service not in ("adguard", "dnsdist", "keepalived"):
        raise HTTPException(status_code=400, detail="service must be adguard, dnsdist or keepalived")
    agent = _get(session, agent_id)
    url, name = agent.url, agent.name
    session.commit()
    logger.warning("restart of %s requested on host %r", service, name)
    try:
        async with AgentClient(url) as client:
            data = await client.restart(service)
    except AgentError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return AgentServiceResult(ok=bool((data or {}).get("ok", True)), message=(data or {}).get("message") or "")


@router.post("/{agent_id}/update", response_model=AgentRead)
async def update_agent_binary(agent_id: int, _: RequireEditor, session: SessionDep):
    """Push the agent build shipped with this control plane to the host now.

    The agent verifies the checksum and restarts itself; the row's
    `update_error` says why if it refused (same version, no build for its arch).
    """
    _get(session, agent_id)
    session.commit()
    outcome = await update_agent_now(agent_id)
    session.expire_all()
    agent = _get(session, agent_id)
    if outcome is not None and outcome.error:
        raise HTTPException(status_code=502, detail=outcome.error)
    return to_read(session, agent)


@router.post("/{agent_id}/renew-cert", response_model=AgentRead)
async def renew_cert(agent_id: int, _: RequireEditor, session: SessionDep):
    agent = _get(session, agent_id)
    url, name, address = agent.url, agent.name, agent.address
    session.commit()
    pki = get_pki()
    try:
        async with AgentClient(url) as client:
            csr = await client.renew_csr()
            cert = sign_agent_csr(pki.ca_cert_pem, pki.ca_key_pem, csr, name=name, address=address)
            await client.install_cert(cert, pki.ca_cert_pem)
    except AgentError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    agent = _get(session, agent_id)
    agent.cert_pem = cert
    agent.cert_not_after = cert_not_after(cert)
    session.add(agent)
    session.commit()
    session.refresh(agent)
    return to_read(session, agent)


@router.delete("/{agent_id}", status_code=204)
def delete_agent(agent_id: int, _: RequireAdmin, session: SessionDep, force: bool = False):
    """Forget a host. Its servers and balancers block the delete unless ?force=true,
    which removes the balancers and detaches the servers (they become unreachable
    direct entries the operator can delete or re-point)."""
    agent = _get(session, agent_id)
    servers = session.exec(select(Server).where(Server.agent_id == agent_id)).all()
    lbs = session.exec(select(LoadBalancer).where(LoadBalancer.agent_id == agent_id)).all()
    if (servers or lbs) and not force:
        raise HTTPException(
            status_code=409,
            detail="This host still has servers or load balancers; delete them first or use force=true",
        )
    # Detach first and commit, then delete: the flush order between unrelated
    # mappers is not guaranteed and SQLite enforces the foreign keys.
    for s in servers:
        s.agent_id = None
        s.tls_cert = None
        s.status = SyncStatus.unknown
        s.agent_state = None
        s.last_error = "Host agent removed; this server is no longer managed"
        session.add(s)
    release_references(session, agent_id=agent_id)
    for lb in lbs:
        release_references(session, lb_id=lb.id)
        session.delete(lb)
    session.commit()
    name = agent.name
    session.delete(agent)
    session.commit()
    logger.warning("host %r (id=%s) deleted (force=%s)", name, agent_id, force)


def agent_bin_dir_exists() -> bool:
    return os.path.isdir(settings.agent_bin_dir)
