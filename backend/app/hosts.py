"""Agent-managed hosts: desired state for each role, and the reconcile passes
that push it and read it back.

Three things live here:

* **spec builders** — pure functions from database rows to the JSON specs in
  docs/design/agent-api.md. They are what makes this app the authority: a host's
  AdGuard, dnsdist and keepalived configuration is derived from zones, servers
  and balancers, never typed on the box.
* **reconcile_agent** — refresh a host (info + health), push the AdGuard spec
  when its hash moved, record the role status on the Server row, and renew the
  agent's certificate when it is close to expiry.
* **reconcile_load_balancer** — push the dnsdist (and keepalived) spec when the
  hash moved, read the live state back, and fan the per-backend view out to the
  Server rows so the Servers page can show what the balancer thinks.

Like sync.py, each pass reads what it needs in one short transaction, does its
network I/O with no connection checked out, then writes back in another.
"""
from __future__ import annotations

import asyncio
import logging
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlmodel import Session, select

from .agent_client import AgentClient, AgentError
from .config import settings
from .database import engine
from .models import (
    Agent,
    HealthCheckMode,
    InstallMethod,
    IpvsAlgo,
    LbMode,
    LbPolicy,
    LoadBalancer,
    LoadBalancerBackend,
    ProvisioningToken,
    Server,
    SyncStatus,
    Zone,
)
from .pki import cert_not_after, get_pki, needs_renewal, sign_agent_csr, spec_hash
from .security import decrypt_secret, encrypt_secret, generate_token
from .validators import backend_name_for

logger = logging.getLogger("adguard_admin.hosts")

AGENT_API_SUFFIX = "/v1/adguard/api"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def agent_url(address: str, port: int) -> str:
    from .validators import format_host_port

    return f"https://{format_host_port(address, port)}"


def adguard_url_via_agent(agent: Agent) -> str:
    return agent.url.rstrip("/") + AGENT_API_SUFFIX


def host_of_url(url: str) -> str | None:
    try:
        return urllib.parse.urlsplit(url).hostname
    except ValueError:
        return None


def release_references(
    session: Session, *, agent_id: int | None = None, server_id: int | None = None, lb_id: int | None = None
) -> None:
    """Null out the foreign keys that would block deleting a host, server or
    balancer, and commit.

    SQLite enforces foreign keys here, and SQLAlchemy only orders a flush by
    declared relationships, so the referencing rows must be updated and
    committed before the owning row is deleted.
    """
    tokens = select(ProvisioningToken)
    if agent_id is not None:
        for t in session.exec(tokens.where(ProvisioningToken.agent_id == agent_id)).all():
            t.agent_id = None
            session.add(t)
    if server_id is not None:
        for t in session.exec(tokens.where(ProvisioningToken.server_id == server_id)).all():
            t.server_id = None
            session.add(t)
        for o in session.exec(select(LoadBalancerBackend).where(LoadBalancerBackend.server_id == server_id)).all():
            session.delete(o)
    if lb_id is not None:
        for t in session.exec(tokens.where(ProvisioningToken.load_balancer_id == lb_id)).all():
            t.load_balancer_id = None
            session.add(t)
        for o in session.exec(select(LoadBalancerBackend).where(LoadBalancerBackend.load_balancer_id == lb_id)).all():
            session.delete(o)
    session.commit()


# --------------------------------------------------------------------------- #
# Spec builders
# --------------------------------------------------------------------------- #
def zone_has_balancer_on_agent(session: Session, agent_id: int) -> bool:
    """True when this host runs a *dnsdist* balancer, which owns :53 and pushes
    the co-located AdGuard to loopback:5335. An IPVS director does not: in
    direct routing the backends, directors included, serve :53 themselves."""
    stmt = select(LoadBalancer.id).where(
        LoadBalancer.agent_id == agent_id, LoadBalancer.enabled == True,  # noqa: E712
        LoadBalancer.mode == LbMode.dnsdist,
    )
    return session.exec(stmt).first() is not None


def zone_mode(session: Session, zone_id: int | None) -> LbMode | None:
    """The balancing mode of a zone (None when it has no balancer)."""
    if zone_id is None:
        return None
    lb = session.exec(select(LoadBalancer).where(LoadBalancer.zone_id == zone_id)).first()
    return lb.mode if lb else None


def zone_vip_address(zone: Zone | None) -> str | None:
    """The VIP without its prefix, e.g. 10.0.0.53 from 10.0.0.53/24."""
    if zone is None or not zone.vip:
        return None
    return zone.vip.split("/", 1)[0]


def adguard_spec(server: Server, *, colocated: bool, password: str | None, ipvs: bool = False) -> dict:
    """The AdGuard role spec for a server that lives on an agent.

    `colocated`: a dnsdist balancer shares the host, so AdGuard moves to
    loopback:5335. `ipvs`: the zone balances with IPVS direct routing, so
    AdGuard must answer on :53 for the VIP's packets, whatever its own setting.
    """
    if ipvs:
        dns_bind = ["0.0.0.0"]
        dns_port = 53
    elif colocated:
        dns_bind = ["127.0.0.1"]
        dns_port = settings.adguard_colocated_dns_port
    else:
        dns_bind = ["0.0.0.0"]
        dns_port = int(server.dns_port or 53)
    return {
        "enabled": bool(server.enabled),
        "install_method": (server.install_method or InstallMethod.docker).value,
        "image": settings.adguard_image,
        "web_bind": "0.0.0.0" if server.expose_web_ui else "127.0.0.1",
        "web_port": 3000,
        "dns_bind": dns_bind,
        "dns_port": dns_port,
        "admin_username": server.username or "admin",
        "admin_password": password or "",
    }


@dataclass
class BackendTarget:
    server_id: int
    server_name: str
    name: str
    address: str
    port: int
    enabled: bool = True
    weight: int = 1
    order: int = 1


def ipvs_backend_spec(zone: Zone | None, *, enabled: bool) -> dict:
    return {"enabled": bool(enabled and zone_vip_address(zone)), "vip": zone_vip_address(zone) or ""}


def desired_backends(session: Session, lb: LoadBalancer) -> list[BackendTarget]:
    """Enabled AdGuard servers in the balancer's zone, with overrides applied.

    dnsdist mode: a backend on the balancer's own host is loopback:5335; one on
    another dnsdist host is that host's address:5335; anything else is its
    address and DNS port. IPVS mode: always the host address and port 53, the
    director included, because direct routing delivers the client's packet to
    the backend unchanged.
    """
    if lb.zone_id is None:
        return []
    ipvs = lb.mode == LbMode.ipvs
    overrides = {
        o.server_id: o
        for o in session.exec(
            select(LoadBalancerBackend).where(LoadBalancerBackend.load_balancer_id == lb.id)
        ).all()
    }
    servers = session.exec(
        select(Server).where(Server.zone_id == lb.zone_id, Server.enabled == True)  # noqa: E712
        .order_by(Server.name)
    ).all()
    out: list[BackendTarget] = []
    for s in servers:
        if s.agent_id is not None:
            agent = session.get(Agent, s.agent_id)
            if agent is None:
                continue
            if ipvs:
                address, port = agent.address, 53
            elif s.agent_id == lb.agent_id:
                address, port = "127.0.0.1", settings.adguard_colocated_dns_port
            else:
                address = agent.address
                port = (
                    settings.adguard_colocated_dns_port
                    if zone_has_balancer_on_agent(session, agent.id)
                    else int(s.dns_port or 53)
                )
        else:
            address = host_of_url(s.url) or ""
            port = 53 if ipvs else int(s.dns_port or 53)
        if not address:
            continue
        o = overrides.get(s.id)
        out.append(BackendTarget(
            server_id=s.id, server_name=s.name, name=backend_name_for(s.name, s.id),
            address=address, port=port,
            enabled=o.enabled if o else True,
            weight=o.weight if o else 1,
            order=o.order if o else 1,
        ))
    return out


def dnsdist_spec(lb: LoadBalancer, backends: list[BackendTarget]) -> dict:
    return {
        "enabled": bool(lb.enabled),
        "install_method": (lb.install_method or InstallMethod.docker).value,
        "image": lb.image or settings.dnsdist_image,
        "listen": list(lb.listen_addresses or ["0.0.0.0:53"]),
        "policy": (lb.policy or LbPolicy.leastOutstanding).value,
        "ecs": bool(lb.ecs),
        "cache": {"enabled": bool(lb.cache_enabled), "max_entries": int(lb.cache_max_entries or 100000)},
        "healthcheck": {
            "name": lb.hc_name or "a.root-servers.net.",
            "interval_s": int(lb.hc_interval_s or 1),
            "max_failures": int(lb.hc_max_failures or 3),
            "rise": int(lb.hc_rise or 2),
            "mode": (lb.hc_mode or HealthCheckMode.auto).value,
        },
        "acl": list(lb.acl or []),
        "backends": [
            {"name": b.name, "address": b.address, "port": int(b.port),
             "weight": int(b.weight), "order": int(b.order)}
            for b in backends if b.enabled
        ],
    }


def ensure_zone_vrrp(session: Session, zone: Zone) -> None:
    """A zone with a VIP needs a router id and an auth password; fill them in once."""
    changed = False
    if zone.vrrp_router_id is None:
        zone.vrrp_router_id = 50 + (zone.id % 200)
        changed = True
    if not zone.vrrp_auth_enc:
        zone.vrrp_auth_enc = encrypt_secret(generate_token(6)[:8])
        changed = True
    if changed:
        session.add(zone)
        session.commit()


def keepalived_spec(
    lb: LoadBalancer, zone: Zone, agent: Agent, peers: list[str],
    backends: list[BackendTarget] | None = None,
) -> dict | None:
    if not zone.vip:
        return None
    ipvs = lb.mode == LbMode.ipvs
    spec = {
        "enabled": bool(lb.enabled),
        "vip": zone.vip,
        "interface": lb.vip_interface or "",
        "router_id": int(zone.vrrp_router_id or 53),
        "priority": int(lb.vrrp_priority or 100),
        "auth_pass": (decrypt_secret(zone.vrrp_auth_enc) or "")[:8],
        "peers": sorted(p for p in peers if p and p != agent.address),
        "src_ip": agent.address,
        # In ipvs mode the local AdGuard is a backend like any other and is
        # health-checked as such; tracking it from VRRP would be double counting.
        "check_dns": "" if ipvs else "127.0.0.1:53",
    }
    if ipvs:
        spec["ipvs"] = {
            "enabled": bool(lb.enabled),
            "vip": zone_vip_address(zone) or "",
            "ports": [53],
            "protocols": ["udp", "tcp"],
            "algo": (lb.ipvs_algo or IpvsAlgo.wlc).value,
            "backends": [
                {"name": b.name, "address": b.address, "port": int(b.port), "weight": int(b.weight)}
                for b in (backends or []) if b.enabled
            ],
            "check": {
                "interval_s": int(lb.hc_interval_s or 2),
                "timeout_s": 2,
                "retry": int(lb.hc_max_failures or 2),
            },
        }
    return spec


DISABLED_DNSDIST = {"enabled": False, "backends": [], "listen": ["0.0.0.0:53"]}
DISABLED_KEEPALIVED = {"enabled": False, "vip": "", "interface": "", "router_id": 1, "priority": 1,
                       "auth_pass": "x", "peers": [], "src_ip": "", "check_dns": ""}
DISABLED_IPVS_BACKEND = {"enabled": False, "vip": ""}


# --------------------------------------------------------------------------- #
# Reconcile: agents
# --------------------------------------------------------------------------- #
@dataclass
class AgentPlan:
    agent_id: int
    name: str
    url: str
    cert_pem: str
    cert_not_after: datetime | None
    # servers on this host: (server_id, spec)
    adguard: list[tuple[int, dict]] = field(default_factory=list)
    # ipvs_backend spec when this host's AdGuard is a direct-routing backend
    ipvs_backend: dict | None = None


@dataclass
class AgentOutcome:
    agent_id: int
    name: str
    status: SyncStatus
    error: str | None = None
    info: dict | None = None
    health: dict | None = None
    adguard_status: dict[int, dict] = field(default_factory=dict)
    ipvs_backend_status: dict | None = None
    renewed_cert: str | None = None


def _agent_plan(session: Session, agent_id: int) -> AgentPlan | None:
    agent = session.get(Agent, agent_id)
    if agent is None:
        return None
    plan = AgentPlan(
        agent_id=agent.id, name=agent.name, url=agent.url,
        cert_pem=agent.cert_pem, cert_not_after=agent.cert_not_after,
    )
    colocated = zone_has_balancer_on_agent(session, agent.id)
    for s in session.exec(select(Server).where(Server.agent_id == agent.id)).all():
        zone = session.get(Zone, s.zone_id) if s.zone_id is not None else None
        ipvs = zone_mode(session, s.zone_id) == LbMode.ipvs and bool(zone_vip_address(zone))
        plan.adguard.append((
            s.id,
            adguard_spec(s, colocated=colocated, password=decrypt_secret(s.password_enc), ipvs=ipvs),
        ))
        if ipvs and s.enabled:
            plan.ipvs_backend = ipvs_backend_spec(zone, enabled=True)
    return plan


async def _renew_if_due(client: AgentClient, plan: AgentPlan, outcome: AgentOutcome) -> None:
    if not needs_renewal(plan.cert_not_after):
        return
    pki = get_pki()
    with Session(engine) as session:
        agent = session.get(Agent, plan.agent_id)
        if agent is None:
            return
        address = agent.address
    csr = await client.renew_csr()
    cert = await asyncio.to_thread(
        sign_agent_csr, pki.ca_cert_pem, pki.ca_key_pem, csr, name=plan.name, address=address
    )
    await client.install_cert(cert, pki.ca_cert_pem)
    outcome.renewed_cert = cert
    logger.info("renewed the certificate of agent %s", plan.name)


async def _run_agent_plan(plan: AgentPlan) -> AgentOutcome:
    outcome = AgentOutcome(agent_id=plan.agent_id, name=plan.name, status=SyncStatus.unknown)
    try:
        client = AgentClient(plan.url)
    except Exception as exc:  # noqa: BLE001 - PKI material unusable
        logger.exception("could not build an agent client for %s", plan.name)
        outcome.status = SyncStatus.error
        outcome.error = f"PKI error: {exc}"
        return outcome
    try:
        outcome.info = await client.info()
        outcome.health = await client.health()
        desired = (outcome.info or {}).get("desired_hashes") or {}
        for server_id, spec in plan.adguard:
            want = spec_hash(spec)
            if desired.get("adguard") != want:
                await client.put_role("adguard", spec)
            try:
                outcome.adguard_status[server_id] = await client.get_role("adguard")
            except AgentError as exc:
                outcome.adguard_status[server_id] = {"state": "error", "message": str(exc)}
        # Direct-routing backend prep: VIP on loopback plus ARP sysctls. Stood
        # down when the zone is no longer in ipvs mode.
        if plan.ipvs_backend is not None:
            if desired.get("ipvs_backend") != spec_hash(plan.ipvs_backend):
                await client.put_role("ipvs-backend", plan.ipvs_backend)
            try:
                outcome.ipvs_backend_status = await client.get_role("ipvs-backend")
            except AgentError as exc:
                outcome.ipvs_backend_status = {"state": "error", "message": str(exc)}
        elif desired.get("ipvs_backend"):
            await client.put_role("ipvs-backend", DISABLED_IPVS_BACKEND)
        try:
            await _renew_if_due(client, plan, outcome)
        except AgentError as exc:
            logger.warning("certificate renewal for %s failed: %s", plan.name, exc)
        outcome.status = SyncStatus.online
    except AgentError as exc:
        outcome.status = SyncStatus.error if exc.status_code else SyncStatus.offline
        outcome.error = str(exc)
    except Exception as exc:  # noqa: BLE001 - one host must never kill the pass
        logger.exception("agent reconcile of %s failed", plan.name)
        outcome.status = SyncStatus.error
        outcome.error = str(exc)
    finally:
        await client.aclose()
    return outcome


def _record_agent(outcome: AgentOutcome) -> None:
    with Session(engine) as session:
        agent = session.get(Agent, outcome.agent_id)
        if agent is None:
            return
        agent.status = outcome.status
        agent.last_error = outcome.error
        if outcome.info is not None:
            agent.info = outcome.info
            agent.version = str(outcome.info.get("agent_version") or agent.version or "")[:50] or None
            agent.hostname = str(outcome.info.get("hostname") or agent.hostname or "")[:100] or None
            agent.os = str(outcome.info.get("os") or agent.os or "")[:50] or None
            agent.arch = str(outcome.info.get("arch") or agent.arch or "")[:50] or None
        if outcome.health is not None:
            agent.health = outcome.health
        if outcome.status == SyncStatus.online:
            agent.last_seen = _now()
        if outcome.renewed_cert:
            agent.cert_pem = outcome.renewed_cert
            agent.cert_not_after = cert_not_after(outcome.renewed_cert)
        session.add(agent)
        for server_id, status in outcome.adguard_status.items():
            server = session.get(Server, server_id)
            if server is None:
                continue
            if outcome.ipvs_backend_status is not None:
                status = dict(status)
                status["ipvs_backend"] = outcome.ipvs_backend_status
            server.agent_state = status
            if status.get("state") != "ready":
                server.status = SyncStatus.provisioning
                server.in_sync = False
                msg = status.get("message") or status.get("state") or "not ready"
                server.last_error = f"AdGuard role: {msg}"
            session.add(server)
        if outcome.status != SyncStatus.online:
            # The host is unreachable: say so on its servers too, instead of
            # leaving a stale "online" from the last good pass.
            for server in session.exec(select(Server).where(Server.agent_id == outcome.agent_id)).all():
                server.status = SyncStatus.offline if outcome.status == SyncStatus.offline else SyncStatus.error
                server.in_sync = False
                server.last_error = f"Agent unreachable: {outcome.error}"
                session.add(server)
        session.commit()


async def reconcile_agent(agent_id: int) -> AgentOutcome | None:
    plan = await asyncio.to_thread(lambda: _plan_in_session(_agent_plan, agent_id))
    if plan is None:
        return None
    outcome = await _run_agent_plan(plan)
    await asyncio.to_thread(_record_agent, outcome)
    return outcome


def _plan_in_session(fn, *args):
    with Session(engine) as session:
        return fn(session, *args)


def agent_ids(*, zone_id: int | None = None) -> list[int]:
    with Session(engine) as session:
        stmt = select(Agent.id)
        if zone_id is not None:
            stmt = stmt.where(Agent.zone_id == zone_id)
        return list(session.exec(stmt).all())


def server_ready_via_agent(session: Session, server: Server) -> bool:
    """False when the host's AdGuard role is not `ready` yet (skip AdGuard sync)."""
    if server.agent_id is None:
        return True
    state = (server.agent_state or {}).get("state")
    return state == "ready"


# --------------------------------------------------------------------------- #
# Reconcile: load balancers
# --------------------------------------------------------------------------- #
@dataclass
class LbPlan:
    lb_id: int
    name: str
    agent_url: str
    agent_name: str
    enabled: bool
    mode: LbMode
    dnsdist: dict | None
    keepalived: dict | None
    backends: list[BackendTarget]


@dataclass
class LbOutcome:
    lb_id: int
    name: str
    status: SyncStatus
    error: str | None = None
    desired_hash: str | None = None
    applied_hash: str | None = None
    in_sync: bool = False
    state: dict | None = None
    keepalived_state: dict | None = None
    backends: list[BackendTarget] = field(default_factory=list)


def _lb_plan(session: Session, lb_id: int) -> LbPlan | None:
    lb = session.get(LoadBalancer, lb_id)
    if lb is None:
        return None
    agent = session.get(Agent, lb.agent_id)
    if agent is None:
        return None
    backends = desired_backends(session, lb)
    ka = None
    if lb.zone_id is not None:
        zone = session.get(Zone, lb.zone_id)
        if zone is not None and zone.vip:
            ensure_zone_vrrp(session, zone)
            peers = []
            for other in session.exec(
                select(LoadBalancer).where(
                    LoadBalancer.zone_id == zone.id, LoadBalancer.enabled == True,  # noqa: E712
                    LoadBalancer.id != lb.id,
                )
            ).all():
                other_agent = session.get(Agent, other.agent_id)
                if other_agent is not None:
                    peers.append(other_agent.address)
            ka = keepalived_spec(lb, zone, agent, peers, backends)
    ipvs = lb.mode == LbMode.ipvs
    return LbPlan(
        lb_id=lb.id, name=lb.name, agent_url=agent.url, agent_name=agent.name,
        enabled=lb.enabled, mode=lb.mode,
        dnsdist=None if ipvs else dnsdist_spec(lb, backends),
        keepalived=ka, backends=backends,
    )


async def _run_lb_plan(plan: LbPlan) -> LbOutcome:
    outcome = LbOutcome(lb_id=plan.lb_id, name=plan.name, status=SyncStatus.unknown, backends=plan.backends)
    ipvs = plan.mode == LbMode.ipvs
    # What "in sync" is measured against: the dnsdist spec, or in ipvs mode the
    # keepalived spec (which carries the virtual servers).
    outcome.desired_hash = spec_hash(plan.keepalived) if ipvs else spec_hash(plan.dnsdist)
    try:
        client = AgentClient(plan.agent_url)
    except Exception as exc:  # noqa: BLE001
        outcome.status = SyncStatus.error
        outcome.error = f"PKI error: {exc}"
        return outcome
    try:
        info = await client.info()
        desired = (info or {}).get("desired_hashes") or {}
        if plan.dnsdist is not None:
            if desired.get("dnsdist") != outcome.desired_hash:
                await client.put_role("dnsdist", plan.dnsdist)
        elif desired.get("dnsdist"):
            # The zone switched to ipvs: dnsdist must give :53 back.
            await client.put_role("dnsdist", DISABLED_DNSDIST)
        if plan.keepalived is not None:
            ka_hash = spec_hash(plan.keepalived)
            if desired.get("keepalived") != ka_hash:
                await client.put_role("keepalived", plan.keepalived)
            try:
                outcome.keepalived_state = await client.get_role("keepalived")
            except AgentError as exc:
                outcome.keepalived_state = {"state": "error", "message": str(exc)}
        elif desired.get("keepalived"):
            # The zone lost its VIP: tell the host to stand down.
            await client.put_role("keepalived", DISABLED_KEEPALIVED)

        if ipvs:
            ks = outcome.keepalived_state or {}
            if plan.keepalived is None:
                outcome.status = SyncStatus.error
                outcome.error = "ipvs mode needs a VIP on the zone"
            else:
                outcome.applied_hash = ks.get("applied_hash")
                state = ks.get("state")
                outcome.in_sync = outcome.applied_hash == outcome.desired_hash and state in ("ready", "stopped")
                if state == "error":
                    outcome.status = SyncStatus.error
                    outcome.error = f"keepalived role: {ks.get('message') or 'error'}"
                else:
                    outcome.status = SyncStatus.online
        else:
            outcome.state = await client.get_role("dnsdist")
            outcome.applied_hash = (outcome.state or {}).get("applied_hash")
            state = (outcome.state or {}).get("state")
            outcome.in_sync = outcome.applied_hash == outcome.desired_hash and state in ("ready", "stopped")
            if state == "error":
                outcome.status = SyncStatus.error
                outcome.error = f"dnsdist role: {(outcome.state or {}).get('message') or 'error'}"
            else:
                outcome.status = SyncStatus.online
    except AgentError as exc:
        outcome.status = SyncStatus.error if exc.status_code else SyncStatus.offline
        outcome.error = str(exc)
    except Exception as exc:  # noqa: BLE001
        logger.exception("load balancer reconcile of %s failed", plan.name)
        outcome.status = SyncStatus.error
        outcome.error = str(exc)
    finally:
        await client.aclose()
    return outcome


def live_backends(dnsdist_state: dict | None, keepalived_state: dict | None) -> list[dict]:
    """The per-backend live rows, normalised to one shape for both modes.

    dnsdist rows are passed through. IPVS rows map packets-in/s to `qps` and
    packets-in to `queries` so the Servers page and the share bar work the
    same way; the connection counters ride along.
    """
    if dnsdist_state and dnsdist_state.get("backends"):
        return list(dnsdist_state.get("backends") or [])
    ipvs = ((keepalived_state or {}).get("ipvs") or {})
    rows = []
    for b in ipvs.get("backends") or []:
        if not isinstance(b, dict):
            continue
        rows.append({
            "name": b.get("name"), "address": b.get("address"), "state": b.get("state"),
            "drained": bool(b.get("drained")), "qps": b.get("in_pps"), "queries": b.get("in_pkts"),
            "conns": b.get("conns"), "active_conns": b.get("active_conns"),
            "inactive_conns": b.get("inactive_conns"), "weight": b.get("weight"),
        })
    return rows


def _record_lb(outcome: LbOutcome) -> None:
    with Session(engine) as session:
        lb = session.get(LoadBalancer, outcome.lb_id)
        if lb is None:
            return
        lb.status = outcome.status
        lb.last_error = outcome.error
        lb.desired_hash = outcome.desired_hash
        lb.in_sync = outcome.in_sync
        if outcome.applied_hash is not None:
            lb.applied_hash = outcome.applied_hash
        if outcome.state is not None:
            lb.state = outcome.state
        if outcome.keepalived_state is not None:
            lb.keepalived_state = outcome.keepalived_state
        if outcome.status == SyncStatus.online:
            lb.last_synced = _now()
        session.add(lb)

        live = {b.get("name"): b for b in live_backends(outcome.state, outcome.keepalived_state) if isinstance(b, dict)}
        for target in outcome.backends:
            server = session.get(Server, target.server_id)
            if server is None:
                continue
            entry = live.get(target.name)
            view = {
                "id": lb.id, "name": lb.name, "mode": lb.mode.value,
                "state": (entry or {}).get("state") if entry else None,
                "drained": bool((entry or {}).get("drained")) if entry else False,
                "qps": (entry or {}).get("qps") if entry else None,
                "enabled": target.enabled,
            }
            balancers = [b for b in ((server.lb_state or {}).get("balancers") or []) if b.get("id") != lb.id]
            balancers.append(view)
            server.lb_state = {
                "up": sum(1 for b in balancers if b.get("state") == "up" and not b.get("drained")),
                "down": sum(1 for b in balancers if b.get("state") == "down"),
                "drained": sum(1 for b in balancers if b.get("drained")),
                "qps": sum(float(b.get("qps") or 0) for b in balancers),
                "balancers": balancers,
            }
            session.add(server)
        session.commit()


async def reconcile_load_balancer(lb_id: int) -> LbOutcome | None:
    plan = await asyncio.to_thread(lambda: _plan_in_session(_lb_plan, lb_id))
    if plan is None:
        return None
    outcome = await _run_lb_plan(plan)
    await asyncio.to_thread(_record_lb, outcome)
    return outcome


def load_balancer_ids(*, zone_id: int | None = None) -> list[int]:
    with Session(engine) as session:
        stmt = select(LoadBalancer.id)
        if zone_id is not None:
            stmt = stmt.where(LoadBalancer.zone_id == zone_id)
        return list(session.exec(stmt).all())


async def reconcile_hosts(*, limit: int) -> tuple[list[AgentOutcome], list[LbOutcome]]:
    """Agents first (so a freshly ready AdGuard can be synced in the same cycle),
    balancers after the servers (so a new server is already in the pool)."""
    semaphore = asyncio.Semaphore(max(1, limit))

    async def _guard(coro):
        async with semaphore:
            return await coro

    ids = await asyncio.to_thread(agent_ids)
    agent_results = await asyncio.gather(*(_guard(reconcile_agent(i)) for i in ids), return_exceptions=True)
    agents = [r for r in agent_results if isinstance(r, AgentOutcome)]
    for r in agent_results:
        if isinstance(r, BaseException):
            logger.exception("agent reconcile task raised", exc_info=r)
    return agents, []


async def reconcile_balancers(*, limit: int) -> list[LbOutcome]:
    semaphore = asyncio.Semaphore(max(1, limit))

    async def _guard(coro):
        async with semaphore:
            return await coro

    ids = await asyncio.to_thread(load_balancer_ids)
    results = await asyncio.gather(*(_guard(reconcile_load_balancer(i)) for i in ids), return_exceptions=True)
    out = [r for r in results if isinstance(r, LbOutcome)]
    for r in results:
        if isinstance(r, BaseException):
            logger.exception("load balancer reconcile task raised", exc_info=r)
    return out
