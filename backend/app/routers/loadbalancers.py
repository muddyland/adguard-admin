"""dnsdist load balancers: declared here, converged on the host by the agent.

A balancer belongs to one zone and one host. Its backends are derived (the
zone's enabled AdGuard servers) with optional per-backend overrides; see
app.hosts for the spec it turns into.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, status
from sqlmodel import select

from ..agent_client import AgentClient, AgentError
from ..deps import CurrentUser, RequireEditor, SessionDep
from ..hosts import (
    DISABLED_DNSDIST,
    DISABLED_KEEPALIVED,
    desired_backends,
    live_backends,
    reconcile_load_balancer,
    release_references,
)
from ..models import Agent, LbMode, LoadBalancer, LoadBalancerBackend, Server, Zone
from ..schemas import (
    LbBackendLive,
    LbBackendRead,
    LbBackendUpdate,
    LoadBalancerCreate,
    LoadBalancerRead,
    LoadBalancerState,
    LoadBalancerUpdate,
)
from ..validators import backend_name_for

router = APIRouter(prefix="/api/load-balancers", tags=["load-balancers"])

logger = logging.getLogger("adguard_admin.loadbalancers")


def _get(session, lb_id: int) -> LoadBalancer:
    lb = session.get(LoadBalancer, lb_id)
    if not lb:
        raise HTTPException(status_code=404, detail="Load balancer not found")
    return lb


def _num(value):
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def to_read(session, lb: LoadBalancer) -> LoadBalancerRead:
    live = {
        b.get("name"): b
        for b in live_backends(lb.state, lb.keepalived_state)
        if isinstance(b, dict)
    }
    backends = []
    for t in desired_backends(session, lb):
        entry = live.get(t.name)
        backends.append(LbBackendRead(
            server_id=t.server_id, server_name=t.server_name, address=t.address, port=t.port,
            enabled=t.enabled, weight=t.weight, order=t.order,
            live=LbBackendLive(
                state=entry.get("state"), drained=bool(entry.get("drained")),
                qps=_num(entry.get("qps")), queries=_num(entry.get("queries")),
                latency_ms=_num(entry.get("latency_ms")), outstanding=_num(entry.get("outstanding")),
                drop_rate=_num(entry.get("drop_rate")),
                conns=_num(entry.get("conns")), active_conns=_num(entry.get("active_conns")),
                inactive_conns=_num(entry.get("inactive_conns")),
            ) if entry else None,
        ))
    zone = session.get(Zone, lb.zone_id) if lb.zone_id is not None else None
    data = {c: getattr(lb, c) for c in LoadBalancer.model_fields}
    data["vip"] = zone.vip if zone else None
    data["backends"] = backends
    return LoadBalancerRead(**data)


def _validate_refs(session, zone_id, agent_id, mode: LbMode, *, exclude_lb_id: int | None = None) -> None:
    if zone_id is None:
        raise HTTPException(status_code=400, detail="A load balancer needs a zone: its backends are the zone's servers")
    zone = session.get(Zone, zone_id)
    if not zone:
        raise HTTPException(status_code=400, detail="zone_id does not exist")
    if not session.get(Agent, agent_id):
        raise HTTPException(status_code=400, detail="agent_id does not exist")
    stmt = select(LoadBalancer).where(LoadBalancer.agent_id == agent_id)
    if exclude_lb_id is not None:
        stmt = stmt.where(LoadBalancer.id != exclude_lb_id)
    if session.exec(stmt).first():
        raise HTTPException(status_code=409, detail="That host already runs a load balancer")
    validate_zone_mode(session, zone, mode, exclude_lb_id=exclude_lb_id)


def validate_zone_mode(session, zone: Zone, mode: LbMode, *, exclude_lb_id: int | None = None) -> None:
    """One mode per zone, and ipvs needs the zone VIP (it is the virtual service)."""
    if mode == LbMode.ipvs and not zone.vip:
        raise HTTPException(status_code=400, detail="IPVS direct routing needs a VIP on the zone")
    stmt = select(LoadBalancer).where(LoadBalancer.zone_id == zone.id, LoadBalancer.mode != mode)
    if exclude_lb_id is not None:
        stmt = stmt.where(LoadBalancer.id != exclude_lb_id)
    other = session.exec(stmt).first()
    if other:
        raise HTTPException(
            status_code=409,
            detail=f"Zone {zone.name!r} already balances in {other.mode.value} mode; all balancers in a zone share one mode",
        )


@router.get("", response_model=list[LoadBalancerRead])
def list_load_balancers(_: CurrentUser, session: SessionDep):
    return [to_read(session, lb) for lb in session.exec(select(LoadBalancer).order_by(LoadBalancer.name)).all()]


@router.post("", response_model=LoadBalancerRead, status_code=status.HTTP_201_CREATED)
def create_load_balancer(payload: LoadBalancerCreate, _: RequireEditor, session: SessionDep):
    _validate_refs(session, payload.zone_id, payload.agent_id, payload.mode or LbMode.dnsdist)
    data = payload.model_dump(exclude_unset=True, exclude_none=True)
    lb = LoadBalancer(**data)
    session.add(lb)
    session.commit()
    session.refresh(lb)
    return to_read(session, lb)


@router.get("/{lb_id}", response_model=LoadBalancerRead)
def get_load_balancer(lb_id: int, _: CurrentUser, session: SessionDep):
    return to_read(session, _get(session, lb_id))


@router.patch("/{lb_id}", response_model=LoadBalancerRead)
def update_load_balancer(lb_id: int, payload: LoadBalancerUpdate, _: RequireEditor, session: SessionDep):
    lb = _get(session, lb_id)
    data = payload.model_dump(exclude_unset=True)
    zone_id = data.get("zone_id", lb.zone_id)
    agent_id = data.get("agent_id", lb.agent_id)
    mode = data.get("mode") or lb.mode
    if "zone_id" in data or "agent_id" in data or "mode" in data:
        _validate_refs(session, zone_id, agent_id, mode, exclude_lb_id=lb.id)
    for key, value in data.items():
        if value is None and key not in ("zone_id",):
            continue
        setattr(lb, key, value)
    lb.in_sync = False
    session.add(lb)
    session.commit()
    session.refresh(lb)
    return to_read(session, lb)


@router.delete("/{lb_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_load_balancer(lb_id: int, _: RequireEditor, session: SessionDep):
    lb = _get(session, lb_id)
    agent = session.get(Agent, lb.agent_id)
    url, name, mode = (agent.url if agent else None), lb.name, lb.mode
    release_references(session, lb_id=lb.id)
    session.delete(lb)
    session.commit()
    # Best effort: tell the host to stop balancing. The row is gone either way;
    # a host that is down keeps serving its last config until it next reconciles.
    if url:
        try:
            async with AgentClient(url) as client:
                if mode == LbMode.ipvs:
                    await client.put_role("keepalived", DISABLED_KEEPALIVED)
                else:
                    await client.put_role("dnsdist", DISABLED_DNSDIST)
        except AgentError as exc:
            logger.warning("could not disable balancing on the host of deleted balancer %r: %s", name, exc)


@router.get("/{lb_id}/state", response_model=LoadBalancerState)
async def live_state(lb_id: int, _: CurrentUser, session: SessionDep):
    """Fresh dnsdist/keepalived status straight from the agent (the list view
    shows the last reconcile's snapshot)."""
    lb = _get(session, lb_id)
    agent = session.get(Agent, lb.agent_id)
    if not agent:
        raise HTTPException(status_code=409, detail="This balancer's host no longer exists")
    url = agent.url
    session.commit()
    out = LoadBalancerState()
    # In ipvs mode the host runs no dnsdist, so keepalived is the required
    # read and dnsdist is skipped; in dnsdist mode it is the other way round
    # (keepalived only exists when the zone has a VIP).
    try:
        async with AgentClient(url) as client:
            if lb.mode == LbMode.ipvs:
                out.keepalived = await client.get_role("keepalived")
            else:
                out.dnsdist = await client.get_role("dnsdist")
                try:
                    out.keepalived = await client.get_role("keepalived")
                except AgentError:
                    out.keepalived = None
    except AgentError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return out


@router.post("/{lb_id}/sync", response_model=LoadBalancerRead)
async def sync_now(lb_id: int, _: RequireEditor, session: SessionDep):
    _get(session, lb_id)
    session.commit()
    await reconcile_load_balancer(lb_id)
    session.expire_all()
    return to_read(session, _get(session, lb_id))


@router.post("/{lb_id}/restart")
async def restart(lb_id: int, _: RequireEditor, session: SessionDep):
    lb = _get(session, lb_id)
    agent = session.get(Agent, lb.agent_id)
    if not agent:
        raise HTTPException(status_code=409, detail="This balancer's host no longer exists")
    url, service = agent.url, ("keepalived" if lb.mode == LbMode.ipvs else "dnsdist")
    session.commit()
    try:
        async with AgentClient(url) as client:
            data = await client.restart(service)
    except AgentError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return {"ok": bool((data or {}).get("ok", True)), "message": (data or {}).get("message") or ""}


def _backend_server(session, lb: LoadBalancer, server_id: int) -> Server:
    server = session.get(Server, server_id)
    if not server or server.zone_id != lb.zone_id:
        raise HTTPException(status_code=404, detail="That server is not a backend of this balancer")
    return server


@router.put("/{lb_id}/backends/{server_id}", response_model=LoadBalancerRead)
def update_backend(lb_id: int, server_id: int, payload: LbBackendUpdate, _: RequireEditor, session: SessionDep):
    lb = _get(session, lb_id)
    _backend_server(session, lb, server_id)
    row = session.exec(
        select(LoadBalancerBackend).where(
            LoadBalancerBackend.load_balancer_id == lb.id, LoadBalancerBackend.server_id == server_id
        )
    ).first()
    if row is None:
        row = LoadBalancerBackend(load_balancer_id=lb.id, server_id=server_id)
    for key, value in payload.model_dump(exclude_unset=True).items():
        if value is not None:
            setattr(row, key, value)
    session.add(row)
    lb.in_sync = False
    session.add(lb)
    session.commit()
    session.refresh(lb)
    return to_read(session, lb)


async def _drain(lb_id: int, server_id: int, session, *, undrain: bool) -> dict:
    lb = _get(session, lb_id)
    server = _backend_server(session, lb, server_id)
    agent = session.get(Agent, lb.agent_id)
    if not agent:
        raise HTTPException(status_code=409, detail="This balancer's host no longer exists")
    url, backend = agent.url, backend_name_for(server.name, server.id)
    role = "keepalived" if lb.mode == LbMode.ipvs else "dnsdist"
    session.commit()
    try:
        async with AgentClient(url) as client:
            await client.drain(backend, undrain=undrain, role=role)
    except AgentError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return {"ok": True}


@router.post("/{lb_id}/backends/{server_id}/drain")
async def drain_backend(lb_id: int, server_id: int, _: RequireEditor, session: SessionDep):
    return await _drain(lb_id, server_id, session, undrain=False)


@router.post("/{lb_id}/backends/{server_id}/undrain")
async def undrain_backend(lb_id: int, server_id: int, _: RequireEditor, session: SessionDep):
    return await _drain(lb_id, server_id, session, undrain=True)
