"""Spec builders and the host / balancer reconcile passes, against a fake agent."""
from __future__ import annotations

import pytest
from sqlmodel import select

from app import hosts
from app.certs import AGENT_MTLS_MARKER
from app.config import settings
from app.models import Agent, InstallMethod, LoadBalancer, LoadBalancerBackend, Server, SyncStatus, Zone
from app.security import decrypt_secret, encrypt_secret


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
def make_agent(session, name="host-a", address="10.0.0.11", zone=None):
    a = Agent(name=name, url=f"https://{address}:8443", address=address, port=8443,
              zone_id=zone.id if zone else None, cert_pem="-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----")
    session.add(a)
    session.commit()
    session.refresh(a)
    return a


def make_server(session, name, zone, agent=None, url=None, dns_port=53, enabled=True):
    s = Server(
        name=name, zone_id=zone.id, enabled=enabled,
        url=url or (hosts.adguard_url_via_agent(agent) if agent else f"http://{name}.lan:3000"),
        username="admin", password_enc=encrypt_secret("pw-" + name),
        agent_id=agent.id if agent else None, tls_cert=AGENT_MTLS_MARKER if agent else None,
        install_method=InstallMethod.docker, dns_port=dns_port,
        agent_state={"state": "ready"} if agent else None,
    )
    session.add(s)
    session.commit()
    session.refresh(s)
    return s


def make_lb(session, name, zone, agent, **kw):
    lb = LoadBalancer(name=name, zone_id=zone.id, agent_id=agent.id, **kw)
    session.add(lb)
    session.commit()
    session.refresh(lb)
    return lb


class FakeAgent:
    """Stands in for AgentClient; records what the control plane pushes."""

    instances: list["FakeAgent"] = []
    # Scripted replies, shared across instances in a test.
    reply_info: dict = {}
    reply_health: dict = {"load": [0.1, 0.1, 0.1]}
    roles: dict = {}
    fail: Exception | None = None
    puts: list[tuple[str, dict]] = []

    def __init__(self, url, **kw):
        self.url = url
        FakeAgent.instances.append(self)

    async def aclose(self):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        pass

    async def info(self):
        if FakeAgent.fail:
            raise FakeAgent.fail
        return FakeAgent.reply_info

    async def health(self):
        return FakeAgent.reply_health

    async def put_role(self, role, spec):
        FakeAgent.puts.append((role, spec))
        return {"accepted": True, "hash": hosts.spec_hash(spec)}

    async def get_role(self, role):
        from app.agent_client import AgentError

        if role not in FakeAgent.roles:
            raise AgentError(f"GET /v1/{role} -> HTTP 404", status_code=404)
        return FakeAgent.roles[role]

    async def renew_csr(self):
        raise AssertionError("renewal should not run in these tests")


@pytest.fixture
def fake_agent(monkeypatch):
    FakeAgent.instances = []
    FakeAgent.puts = []
    FakeAgent.fail = None
    FakeAgent.reply_info = {"agent_version": "0.1.0", "hostname": "host-a", "os": "linux", "arch": "amd64",
                            "desired_hashes": {"adguard": None, "dnsdist": None, "keepalived": None}}
    FakeAgent.roles = {}
    monkeypatch.setattr(hosts, "AgentClient", FakeAgent)
    return FakeAgent


# --------------------------------------------------------------------------- #
# Spec builders
# --------------------------------------------------------------------------- #
def test_adguard_spec_standalone_and_colocated(session, zone):
    agent = make_agent(session, zone=zone)
    s = make_server(session, "dns-a", zone, agent, dns_port=53)
    s.expose_web_ui = True
    spec = hosts.adguard_spec(s, colocated=False, password="secret")
    assert spec["dns_bind"] == ["0.0.0.0"] and spec["dns_port"] == 53
    assert spec["web_bind"] == "0.0.0.0" and spec["admin_password"] == "secret"
    assert spec["install_method"] == "docker" and spec["image"] == settings.adguard_image

    s.expose_web_ui = False
    spec = hosts.adguard_spec(s, colocated=True, password="secret")
    assert spec["dns_bind"] == ["127.0.0.1"]
    assert spec["dns_port"] == settings.adguard_colocated_dns_port
    assert spec["web_bind"] == "127.0.0.1"
    # Only JSON scalars the agent can hash identically.
    hosts.spec_hash(spec)


def test_backends_come_from_the_zone_with_overrides(session, zone):
    agent_a = make_agent(session, "host-a", "10.0.0.11", zone)
    agent_b = make_agent(session, "host-b", "10.0.0.12", zone)
    sa = make_server(session, "dns-a", zone, agent_a)
    sb = make_server(session, "dns-b", zone, agent_b)
    sc = make_server(session, "legacy", zone, url="http://10.0.0.20:3000", dns_port=5300)
    make_server(session, "off", zone, url="http://10.0.0.21:3000", enabled=False)
    other = Zone(name="Other", slug="other")
    session.add(other)
    session.commit()
    make_server(session, "elsewhere", other, url="http://10.0.0.30:3000")

    lb = make_lb(session, "lb-a", zone, agent_a)
    # host-b also runs a balancer, so its AdGuard listens on the loopback port.
    make_lb(session, "lb-b", zone, agent_b)
    session.add(LoadBalancerBackend(load_balancer_id=lb.id, server_id=sb.id, weight=3, order=2))
    session.commit()

    backends = hosts.desired_backends(session, lb)
    by_name = {b.server_name: b for b in backends}
    assert set(by_name) == {"dns-a", "dns-b", "legacy"}
    assert (by_name["dns-a"].address, by_name["dns-a"].port) == ("127.0.0.1", settings.adguard_colocated_dns_port)
    assert (by_name["dns-b"].address, by_name["dns-b"].port) == ("10.0.0.12", settings.adguard_colocated_dns_port)
    assert (by_name["dns-b"].weight, by_name["dns-b"].order) == (3, 2)
    assert (by_name["legacy"].address, by_name["legacy"].port) == ("10.0.0.20", 5300)
    assert by_name["legacy"].name == f"legacy-{sc.id}"
    assert by_name["dns-a"].name == f"dns-a-{sa.id}"

    spec = hosts.dnsdist_spec(lb, backends)
    assert [b["address"] for b in spec["backends"]] == ["127.0.0.1", "10.0.0.12", "10.0.0.20"]
    assert spec["policy"] == "leastOutstanding" and spec["healthcheck"]["mode"] == "auto"
    assert spec["listen"] == ["0.0.0.0:53"] and spec["ecs"] is True
    hosts.spec_hash(spec)


def test_disabled_backend_override_drops_it_from_the_spec(session, zone):
    agent = make_agent(session, zone=zone)
    make_server(session, "dns-a", zone, agent)
    s2 = make_server(session, "dns-b", zone, url="http://10.0.0.12:3000")
    lb = make_lb(session, "lb", zone, agent)
    session.add(LoadBalancerBackend(load_balancer_id=lb.id, server_id=s2.id, enabled=False))
    session.commit()
    spec = hosts.dnsdist_spec(lb, hosts.desired_backends(session, lb))
    sa_id = session.exec(select(Server.id).where(Server.name == "dns-a")).one()
    assert [b["name"] for b in spec["backends"]] == [f"dns-a-{sa_id}"]


def test_keepalived_spec_uses_zone_vip_and_peers(session, zone):
    zone.vip = "10.0.0.53/24"
    session.add(zone)
    session.commit()
    hosts.ensure_zone_vrrp(session, zone)
    assert 1 <= zone.vrrp_router_id <= 255
    pw = decrypt_secret(zone.vrrp_auth_enc)
    assert pw and len(pw) <= 8
    agent = make_agent(session, "host-a", "10.0.0.11", zone)
    lb = make_lb(session, "lb-a", zone, agent, vrrp_priority=150, vip_interface="eth0")
    spec = hosts.keepalived_spec(lb, zone, agent, peers=["10.0.0.12", "10.0.0.11", "10.0.0.13"])
    assert spec["vip"] == "10.0.0.53/24" and spec["priority"] == 150 and spec["interface"] == "eth0"
    assert spec["peers"] == ["10.0.0.12", "10.0.0.13"]  # self removed, sorted
    assert spec["src_ip"] == "10.0.0.11" and spec["auth_pass"] == pw
    zone.vip = None
    assert hosts.keepalived_spec(lb, zone, agent, []) is None


# --------------------------------------------------------------------------- #
# reconcile_agent
# --------------------------------------------------------------------------- #
@pytest.mark.anyio
async def test_reconcile_agent_pushes_spec_and_marks_server_provisioning(session, zone, fake_agent):
    agent = make_agent(session, zone=zone)
    server = make_server(session, "dns-a", zone, agent)
    server.agent_state = None
    session.add(server)
    session.commit()
    fake_agent.roles["adguard"] = {"state": "installing", "message": "pulling image", "desired_hash": "x"}

    outcome = await hosts.reconcile_agent(agent.id)
    assert outcome.status == SyncStatus.online
    assert [r for r, _ in fake_agent.puts] == ["adguard"]
    pushed = fake_agent.puts[0][1]
    assert pushed["admin_password"] == "pw-dns-a" and pushed["dns_bind"] == ["0.0.0.0"]

    session.expire_all()
    server = session.get(Server, server.id)
    assert server.status == SyncStatus.provisioning
    assert server.agent_state["state"] == "installing"
    assert "pulling image" in server.last_error
    agent = session.get(Agent, agent.id)
    assert agent.status == SyncStatus.online and agent.version == "0.1.0" and agent.health["load"]


@pytest.mark.anyio
async def test_reconcile_agent_skips_push_when_hash_matches(session, zone, fake_agent):
    agent = make_agent(session, zone=zone)
    server = make_server(session, "dns-a", zone, agent)
    spec = hosts.adguard_spec(server, colocated=False, password="pw-dns-a")
    fake_agent.reply_info["desired_hashes"] = {"adguard": hosts.spec_hash(spec)}
    fake_agent.roles["adguard"] = {"state": "ready", "applied_hash": hosts.spec_hash(spec)}

    await hosts.reconcile_agent(agent.id)
    assert fake_agent.puts == []
    session.expire_all()
    assert session.get(Server, server.id).status != SyncStatus.provisioning


@pytest.mark.anyio
async def test_unreachable_agent_marks_host_and_servers_offline(session, zone, fake_agent):
    from app.agent_client import AgentError

    agent = make_agent(session, zone=zone)
    server = make_server(session, "dns-a", zone, agent)
    fake_agent.fail = AgentError("GET /v1/info failed: could not connect")

    outcome = await hosts.reconcile_agent(agent.id)
    assert outcome.status == SyncStatus.offline
    session.expire_all()
    assert session.get(Agent, agent.id).status == SyncStatus.offline
    s = session.get(Server, server.id)
    assert s.status == SyncStatus.offline and "Agent unreachable" in s.last_error


# --------------------------------------------------------------------------- #
# reconcile_load_balancer
# --------------------------------------------------------------------------- #
@pytest.mark.anyio
async def test_reconcile_balancer_pushes_and_fans_out_backend_state(session, zone, fake_agent):
    agent = make_agent(session, zone=zone)
    sa = make_server(session, "dns-a", zone, agent)
    sb = make_server(session, "dns-b", zone, url="http://10.0.0.12:3000")
    lb = make_lb(session, "lb", zone, agent)
    spec = hosts.dnsdist_spec(lb, hosts.desired_backends(session, lb))
    want = hosts.spec_hash(spec)
    fake_agent.roles["dnsdist"] = {
        "state": "ready", "applied_hash": want, "version": "2.0.8",
        "backends": [
            {"name": f"dns-a-{sa.id}", "state": "up", "drained": False, "qps": 4.5},
            {"name": f"dns-b-{sb.id}", "state": "down", "drained": False, "qps": 0},
        ],
    }

    outcome = await hosts.reconcile_load_balancer(lb.id)
    assert outcome.status == SyncStatus.online and outcome.in_sync
    assert fake_agent.puts == [("dnsdist", spec)]  # no VIP -> no keepalived push

    session.expire_all()
    lb = session.get(LoadBalancer, lb.id)
    assert lb.in_sync and lb.applied_hash == want and lb.state["version"] == "2.0.8"
    sa = session.get(Server, sa.id)
    sb = session.get(Server, sb.id)
    assert sa.lb_state["up"] == 1 and sa.lb_state["qps"] == 4.5
    assert sb.lb_state["down"] == 1 and sb.lb_state["balancers"][0]["name"] == "lb"


@pytest.mark.anyio
async def test_reconcile_balancer_with_vip_pushes_keepalived(session, zone, fake_agent):
    zone.vip = "10.0.0.53/24"
    session.add(zone)
    session.commit()
    agent_a = make_agent(session, "host-a", "10.0.0.11", zone)
    agent_b = make_agent(session, "host-b", "10.0.0.12", zone)
    make_server(session, "dns-a", zone, agent_a)
    lb = make_lb(session, "lb-a", zone, agent_a, vrrp_priority=150)
    make_lb(session, "lb-b", zone, agent_b, vrrp_priority=100)
    fake_agent.roles["dnsdist"] = {"state": "ready", "applied_hash": "stale", "backends": []}
    fake_agent.roles["keepalived"] = {"state": "ready", "vip_owner": True}

    outcome = await hosts.reconcile_load_balancer(lb.id)
    roles = [r for r, _ in fake_agent.puts]
    assert roles == ["dnsdist", "keepalived"]
    ka = fake_agent.puts[1][1]
    assert ka["vip"] == "10.0.0.53/24" and ka["peers"] == ["10.0.0.12"] and ka["priority"] == 150
    assert ka["src_ip"] == "10.0.0.11" and ka["check_dns"] == "127.0.0.1:53"
    assert outcome.keepalived_state["vip_owner"] is True
    # Applied hash is stale, so the balancer is online but not in sync yet.
    assert outcome.status == SyncStatus.online and not outcome.in_sync


@pytest.mark.anyio
async def test_reconcile_balancer_error_state_is_surfaced(session, zone, fake_agent):
    agent = make_agent(session, zone=zone)
    make_server(session, "dns-a", zone, agent)
    lb = make_lb(session, "lb", zone, agent)
    fake_agent.roles["dnsdist"] = {"state": "error", "message": "check-config failed", "backends": []}
    outcome = await hosts.reconcile_load_balancer(lb.id)
    assert outcome.status == SyncStatus.error
    assert "check-config failed" in outcome.error


# --------------------------------------------------------------------------- #
# IPVS direct-routing mode
# --------------------------------------------------------------------------- #
def test_ipvs_specs(session, zone):
    zone.vip = "10.0.0.53/24"
    session.add(zone)
    session.commit()
    hosts.ensure_zone_vrrp(session, zone)
    agent_a = make_agent(session, "host-a", "10.0.0.11", zone)
    agent_b = make_agent(session, "host-b", "10.0.0.12", zone)
    sa = make_server(session, "dns-a", zone, agent_a, dns_port=5353)
    sb = make_server(session, "dns-b", zone, agent_b)
    sc = make_server(session, "legacy", zone, url="http://10.0.0.20:3000", dns_port=5300)
    lb = make_lb(session, "lb-a", zone, agent_a, mode="ipvs", ipvs_algo="sh", vrrp_priority=150)
    make_lb(session, "lb-b", zone, agent_b, mode="ipvs")

    backends = hosts.desired_backends(session, lb)
    assert [(b.address, b.port) for b in backends] == [("10.0.0.11", 53), ("10.0.0.12", 53), ("10.0.0.20", 53)]
    # No dnsdist spec in ipvs mode; the keepalived spec carries the virtual servers.
    ka = hosts.keepalived_spec(lb, zone, agent_a, ["10.0.0.12"], backends)
    assert ka["check_dns"] == "" and ka["peers"] == ["10.0.0.12"]
    ipvs = ka["ipvs"]
    assert ipvs["vip"] == "10.0.0.53" and ipvs["algo"] == "sh" and ipvs["protocols"] == ["udp", "tcp"]
    assert [b["name"] for b in ipvs["backends"]] == [f"dns-a-{sa.id}", f"dns-b-{sb.id}", f"legacy-{sc.id}"]
    assert ipvs["check"] == {"interval_s": 1, "timeout_s": 2, "retry": 3}
    hosts.spec_hash(ka)
    # The AdGuard role on an ipvs backend listens on :53 everywhere, whatever dns_port says.
    assert hosts.zone_has_balancer_on_agent(session, agent_a.id) is False  # ipvs directors do not take :53
    spec = hosts.adguard_spec(sa, colocated=False, password="x", ipvs=True)
    assert spec["dns_bind"] == ["0.0.0.0"] and spec["dns_port"] == 53
    assert hosts.ipvs_backend_spec(zone, enabled=True) == {"enabled": True, "vip": "10.0.0.53"}
    zone.vip = None
    assert hosts.ipvs_backend_spec(zone, enabled=True) == {"enabled": False, "vip": ""}


@pytest.mark.anyio
async def test_reconcile_agent_in_ipvs_zone_pushes_backend_prep(session, zone, fake_agent):
    zone.vip = "10.0.0.53/24"
    session.add(zone)
    session.commit()
    agent = make_agent(session, zone=zone)
    server = make_server(session, "dns-a", zone, agent, dns_port=5353)
    make_lb(session, "lb", zone, agent, mode="ipvs")
    fake_agent.roles["adguard"] = {"state": "ready"}
    fake_agent.roles["ipvs-backend"] = {"state": "ready", "vip_present": True, "sysctls_ok": True}

    await hosts.reconcile_agent(agent.id)
    roles = [r for r, _ in fake_agent.puts]
    assert roles == ["adguard", "ipvs-backend"]
    assert fake_agent.puts[0][1]["dns_port"] == 53 and fake_agent.puts[0][1]["dns_bind"] == ["0.0.0.0"]
    assert fake_agent.puts[1][1] == {"enabled": True, "vip": "10.0.0.53"}
    session.expire_all()
    s = session.get(Server, server.id)
    assert s.agent_state["ipvs_backend"]["vip_present"] is True and s.status != SyncStatus.provisioning


@pytest.mark.anyio
async def test_reconcile_agent_stands_down_ipvs_backend_when_zone_leaves_ipvs(session, zone, fake_agent):
    agent = make_agent(session, zone=zone)
    make_server(session, "dns-a", zone, agent)
    fake_agent.reply_info["desired_hashes"] = {"adguard": None, "ipvs_backend": "stale"}
    fake_agent.roles["adguard"] = {"state": "ready"}
    await hosts.reconcile_agent(agent.id)
    assert ("ipvs-backend", {"enabled": False, "vip": ""}) in fake_agent.puts


@pytest.mark.anyio
async def test_reconcile_ipvs_balancer_pushes_keepalived_and_disables_dnsdist(session, zone, fake_agent):
    zone.vip = "10.0.0.53/24"
    session.add(zone)
    session.commit()
    agent = make_agent(session, zone=zone)
    sa = make_server(session, "dns-a", zone, agent)
    lb = make_lb(session, "lb", zone, agent, mode="ipvs")
    fake_agent.reply_info["desired_hashes"] = {"dnsdist": "was-dnsdist", "keepalived": None}
    hosts.ensure_zone_vrrp(session, zone)  # the plan does this too; hash the same inputs
    ka = hosts.keepalived_spec(lb, zone, agent, [], hosts.desired_backends(session, lb))
    want = hosts.spec_hash(ka)
    fake_agent.roles["keepalived"] = {"state": "ready", "applied_hash": want, "vip_owner": True, "ipvs": {
        "present": True, "backends": [{"name": f"dns-a-{sa.id}", "address": "10.0.0.11", "port": 53,
                                       "weight": 1, "state": "up", "drained": False, "in_pps": 3.0, "in_pkts": 30, "conns": 30}],
    }}

    outcome = await hosts.reconcile_load_balancer(lb.id)
    assert outcome.status == SyncStatus.online and outcome.in_sync, outcome.error
    assert fake_agent.puts == [("dnsdist", hosts.DISABLED_DNSDIST), ("keepalived", ka)]
    session.expire_all()
    lb = session.get(LoadBalancer, lb.id)
    assert lb.state is None and lb.keepalived_state["vip_owner"] is True and lb.applied_hash == want
    s = session.get(Server, sa.id)
    assert s.lb_state["up"] == 1 and s.lb_state["qps"] == 3.0 and s.lb_state["balancers"][0]["mode"] == "ipvs"


@pytest.mark.anyio
async def test_reconcile_ipvs_balancer_without_vip_is_an_error(session, zone, fake_agent):
    agent = make_agent(session, zone=zone)
    make_server(session, "dns-a", zone, agent)
    lb = make_lb(session, "lb", zone, agent, mode="ipvs")
    outcome = await hosts.reconcile_load_balancer(lb.id)
    assert outcome.status == SyncStatus.error and "VIP" in outcome.error
