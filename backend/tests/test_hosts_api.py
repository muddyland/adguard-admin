"""The /api/agents and /api/load-balancers surfaces."""
from __future__ import annotations

import hashlib
import os

import pytest

from app.config import settings
from app.models import Agent, LoadBalancer, LoadBalancerBackend, Server
from app.routers import agents as agents_router
from app.routers import loadbalancers as lb_router
from tests.test_hosts import make_agent, make_lb, make_server


class StubClient:
    calls: list[tuple] = []
    roles: dict = {}

    def __init__(self, url, **kw):
        self.url = url

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        pass

    async def aclose(self):
        pass

    async def get_role(self, role):
        from app.agent_client import AgentError

        if role not in StubClient.roles:
            raise AgentError("404", status_code=404)
        return StubClient.roles[role]

    async def put_role(self, role, spec):
        StubClient.calls.append(("put", role, spec))
        return {"accepted": True}

    async def drain(self, backend, *, undrain=False, role="dnsdist"):
        StubClient.calls.append(("undrain" if undrain else "drain", backend, role))
        return {"ok": True}

    async def restart(self, service):
        StubClient.calls.append(("restart", service))
        return {"ok": True, "message": "restarted"}

    async def logs(self, service, lines=200):
        StubClient.calls.append(("logs", service, lines))
        return ["line 1", "line 2"]

    async def adguard_reset(self):
        StubClient.calls.append(("reset",))
        return {"ok": True}


@pytest.fixture
def stub(monkeypatch):
    StubClient.calls = []
    StubClient.roles = {}
    monkeypatch.setattr(lb_router, "AgentClient", StubClient)
    monkeypatch.setattr(agents_router, "AgentClient", StubClient)
    from app.routers import servers as servers_router

    monkeypatch.setattr(servers_router, "AgentClient", StubClient)
    return StubClient


# --------------------------------------------------------------------------- #
# Agents
# --------------------------------------------------------------------------- #
def test_agent_list_reports_roles_and_links(client, viewer_headers, session, zone):
    agent = make_agent(session, zone=zone)
    s = make_server(session, "dns-a", zone, agent)
    lb = make_lb(session, "lb", zone, agent)
    rows = client.get("/api/agents", headers=viewer_headers).json()
    assert len(rows) == 1
    row = rows[0]
    assert row["roles"] == ["adguard", "dnsdist"]
    assert row["server_ids"] == [s.id] and row["load_balancer_ids"] == [lb.id]
    assert row["url"] == "https://10.0.0.11:8443"


def test_agent_delete_requires_admin_and_force_when_referenced(client, editor_headers, admin_headers, session, zone):
    agent = make_agent(session, zone=zone)
    s = make_server(session, "dns-a", zone, agent)
    make_lb(session, "lb", zone, agent)
    agent_id, server_id = agent.id, s.id
    assert client.delete(f"/api/agents/{agent_id}", headers=editor_headers).status_code == 403
    assert client.delete(f"/api/agents/{agent_id}", headers=admin_headers).status_code == 409
    assert client.delete(f"/api/agents/{agent_id}?force=true", headers=admin_headers).status_code == 204
    session.expire_all()
    assert session.get(Agent, agent_id) is None
    assert session.query(LoadBalancer).count() == 0
    detached = session.get(Server, server_id)
    assert detached.agent_id is None and detached.tls_cert is None


def test_agent_logs_and_restart_go_through_the_client(client, editor_headers, viewer_headers, session, zone, stub):
    agent = make_agent(session, zone=zone)
    r = client.get(f"/api/agents/{agent.id}/logs?service=dnsdist&lines=50", headers=editor_headers)
    assert r.status_code == 200 and r.json()["lines"] == ["line 1", "line 2"]
    assert client.get(f"/api/agents/{agent.id}/logs?service=shell", headers=editor_headers).status_code == 400
    assert client.get(f"/api/agents/{agent.id}/logs", headers=viewer_headers).status_code == 403
    r = client.post(f"/api/agents/{agent.id}/services/dnsdist/restart", headers=editor_headers)
    assert r.status_code == 200 and r.json()["ok"]
    assert client.post(f"/api/agents/{agent.id}/services/sshd/restart", headers=editor_headers).status_code == 400
    assert ("restart", "dnsdist") in stub.calls


def test_download_manifest_and_binary(client, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "agent_bin_dir", str(tmp_path))
    assert client.get("/api/agents/download/manifest").status_code == 404
    blob = b"\x7fELF fake agent"
    (tmp_path / "adguard-admin-agent-linux-amd64").write_bytes(blob)
    (tmp_path / "VERSION").write_text("0.1.0\n")
    m = client.get("/api/agents/download/manifest").json()
    assert m["version"] == "0.1.0"
    assert m["files"]["linux/amd64"] == {"sha256": hashlib.sha256(blob).hexdigest(), "size": len(blob)}
    assert "linux/arm64" not in m["files"]
    r = client.get("/api/agents/download/linux/amd64")
    assert r.status_code == 200 and r.content == blob
    assert client.get("/api/agents/download/linux/arm64").status_code == 404
    assert client.get("/api/agents/download/linux/mips").status_code == 404
    # Cached manifest is invalidated when the file changes.
    os.utime(tmp_path / "adguard-admin-agent-linux-amd64", (1, 1))
    (tmp_path / "adguard-admin-agent-linux-amd64").write_bytes(blob + b"!")
    assert client.get("/api/agents/download/manifest").json()["files"]["linux/amd64"]["size"] == len(blob) + 1


# --------------------------------------------------------------------------- #
# Load balancers
# --------------------------------------------------------------------------- #
def test_load_balancer_crud_and_constraints(client, editor_headers, session, zone):
    agent = make_agent(session, zone=zone)
    make_server(session, "dns-a", zone, agent)
    body = {"name": "lb-a", "zone_id": zone.id, "agent_id": agent.id, "policy": "roundrobin",
            "listen_addresses": ["0.0.0.0:53", "[::]:53"], "acl": ["10.0.0.0/8"], "vrrp_priority": 150}
    r = client.post("/api/load-balancers", json=body, headers=editor_headers)
    assert r.status_code == 201, r.text
    lb = r.json()
    assert lb["policy"] == "roundrobin" and lb["listen_addresses"] == ["0.0.0.0:53", "[::]:53"]
    assert lb["backends"][0]["server_name"] == "dns-a" and lb["backends"][0]["address"] == "127.0.0.1"
    assert lb["vip"] is None

    # One balancer per host; a balancer needs a zone; validation on specs.
    assert client.post("/api/load-balancers", json=body, headers=editor_headers).status_code == 409
    assert client.post("/api/load-balancers", json={**body, "zone_id": None}, headers=editor_headers).status_code == 400
    assert client.post("/api/load-balancers", json={**body, "listen_addresses": ["nope"]}, headers=editor_headers).status_code == 422
    assert client.post("/api/load-balancers", json={**body, "acl": ["10.0.0.0/99"]}, headers=editor_headers).status_code == 422
    assert client.post("/api/load-balancers", json={**body, "image": "bad image ref!"}, headers=editor_headers).status_code == 422

    r = client.patch(f"/api/load-balancers/{lb['id']}", json={"cache_enabled": True, "hc_name": "example.com"}, headers=editor_headers)
    assert r.status_code == 200 and r.json()["cache_enabled"] and r.json()["hc_name"] == "example.com."
    assert r.json()["in_sync"] is False

    assert client.get("/api/load-balancers", headers=editor_headers).json()[0]["name"] == "lb-a"


def test_backend_overrides_and_drain(client, editor_headers, session, zone, stub):
    agent = make_agent(session, zone=zone)
    sa = make_server(session, "dns-a", zone, agent)
    sb = make_server(session, "dns-b", zone, url="http://10.0.0.12:3000")
    lb = make_lb(session, "lb", zone, agent)

    r = client.put(f"/api/load-balancers/{lb.id}/backends/{sb.id}", json={"weight": 5, "enabled": False}, headers=editor_headers)
    assert r.status_code == 200
    b = {x["server_name"]: x for x in r.json()["backends"]}
    assert b["dns-b"]["weight"] == 5 and b["dns-b"]["enabled"] is False and b["dns-a"]["weight"] == 1
    assert session.query(LoadBalancerBackend).count() == 1
    assert client.put(f"/api/load-balancers/{lb.id}/backends/{sb.id}", json={"weight": 0}, headers=editor_headers).status_code == 422
    assert client.put(f"/api/load-balancers/{lb.id}/backends/9999", json={"weight": 2}, headers=editor_headers).status_code == 404

    assert client.post(f"/api/load-balancers/{lb.id}/backends/{sa.id}/drain", headers=editor_headers).json() == {"ok": True}
    assert client.post(f"/api/load-balancers/{lb.id}/backends/{sa.id}/undrain", headers=editor_headers).json() == {"ok": True}
    assert ("drain", f"dns-a-{sa.id}", "dnsdist") in stub.calls and ("undrain", f"dns-a-{sa.id}", "dnsdist") in stub.calls


def test_live_state_and_delete_disable_on_host(client, editor_headers, session, zone, stub):
    agent = make_agent(session, zone=zone)
    make_server(session, "dns-a", zone, agent)
    lb = make_lb(session, "lb", zone, agent)
    stub.roles["dnsdist"] = {"state": "ready", "backends": []}
    r = client.get(f"/api/load-balancers/{lb.id}/state", headers=editor_headers)
    assert r.status_code == 200 and r.json()["dnsdist"]["state"] == "ready" and r.json()["keepalived"] is None

    assert client.delete(f"/api/load-balancers/{lb.id}", headers=editor_headers).status_code == 204
    assert ("put", "dnsdist", {"enabled": False, "backends": [], "listen": ["0.0.0.0:53"]}) in stub.calls
    assert session.query(LoadBalancer).count() == 0


def test_load_balancer_read_merges_last_live_snapshot(client, viewer_headers, session, zone):
    agent = make_agent(session, zone=zone)
    sa = make_server(session, "dns-a", zone, agent)
    lb = make_lb(session, "lb", zone, agent)
    lb.state = {"state": "ready", "backends": [{"name": f"dns-a-{sa.id}", "state": "up", "qps": "2.5", "latency_ms": 1.2}]}
    session.add(lb)
    session.commit()
    row = client.get(f"/api/load-balancers/{lb.id}", headers=viewer_headers).json()
    live = row["backends"][0]["live"]
    assert live["state"] == "up" and live["qps"] == 2.5 and live["latency_ms"] == 1.2


def test_zone_vip_validation_and_vrrp_bootstrap(client, editor_headers, session, zone):
    assert client.patch(f"/api/zones/{zone.id}", json={"vip": "10.0.0.53"}, headers=editor_headers).status_code == 422
    assert client.patch(f"/api/zones/{zone.id}", json={"vip": "10.0.0.53/24", "vrrp_router_id": 300}, headers=editor_headers).status_code == 422
    r = client.patch(f"/api/zones/{zone.id}", json={"vip": "10.0.0.53/24"}, headers=editor_headers)
    assert r.status_code == 200 and r.json()["vip"] == "10.0.0.53/24"
    assert 1 <= r.json()["vrrp_router_id"] <= 255
    session.expire_all()
    assert session.get(type(zone), zone.id).vrrp_auth_enc
    r = client.patch(f"/api/zones/{zone.id}", json={"vip": None}, headers=editor_headers)
    assert r.status_code == 200 and r.json()["vip"] is None


def test_agent_managed_server_connection_fields_are_read_only(client, editor_headers, session, zone):
    agent = make_agent(session, zone=zone)
    s = make_server(session, "dns-a", zone, agent)
    r = client.patch(f"/api/servers/{s.id}", json={"url": "http://evil:3000"}, headers=editor_headers)
    assert r.status_code == 400
    r = client.patch(f"/api/servers/{s.id}", json={"dns_port": 5353, "expose_web_ui": True, "password": ""}, headers=editor_headers)
    assert r.status_code == 200 and r.json()["dns_port"] == 5353 and r.json()["expose_web_ui"] is True
    assert r.json()["agent_id"] == agent.id


# --------------------------------------------------------------------------- #
# IPVS direct-routing mode
# --------------------------------------------------------------------------- #
def test_ipvs_mode_needs_vip_and_one_mode_per_zone(client, editor_headers, session, zone):
    agent_a = make_agent(session, "host-a", "10.0.0.11", zone)
    agent_b = make_agent(session, "host-b", "10.0.0.12", zone)
    make_server(session, "dns-a", zone, agent_a)
    body = {"name": "lb-a", "zone_id": zone.id, "agent_id": agent_a.id, "mode": "ipvs", "ipvs_algo": "sh"}
    r = client.post("/api/load-balancers", json=body, headers=editor_headers)
    assert r.status_code == 400 and "VIP" in r.json()["detail"]

    client.patch(f"/api/zones/{zone.id}", json={"vip": "10.0.0.53/24"}, headers=editor_headers)
    r = client.post("/api/load-balancers", json=body, headers=editor_headers)
    assert r.status_code == 201, r.text
    lb = r.json()
    assert lb["mode"] == "ipvs" and lb["ipvs_algo"] == "sh" and lb["vip"] == "10.0.0.53/24"
    # In ipvs mode the director's own AdGuard is addressed by host address :53, not loopback:5335.
    assert (lb["backends"][0]["address"], lb["backends"][0]["port"]) == ("10.0.0.11", 53)

    # A second balancer in the same zone must use the same mode.
    r = client.post("/api/load-balancers", json={"name": "lb-b", "zone_id": zone.id, "agent_id": agent_b.id, "mode": "dnsdist"}, headers=editor_headers)
    assert r.status_code == 409 and "ipvs mode" in r.json()["detail"]
    r = client.post("/api/load-balancers", json={"name": "lb-b", "zone_id": zone.id, "agent_id": agent_b.id, "mode": "ipvs"}, headers=editor_headers)
    assert r.status_code == 201
    # Switching one of them alone is refused too.
    assert client.patch(f"/api/load-balancers/{lb['id']}", json={"mode": "dnsdist"}, headers=editor_headers).status_code == 409


def test_ipvs_drain_restart_and_delete_target_keepalived(client, editor_headers, session, zone, stub):
    zone.vip = "10.0.0.53/24"
    session.add(zone)
    session.commit()
    agent = make_agent(session, zone=zone)
    sa = make_server(session, "dns-a", zone, agent)
    lb = make_lb(session, "lb", zone, agent, mode="ipvs")
    assert client.post(f"/api/load-balancers/{lb.id}/backends/{sa.id}/drain", headers=editor_headers).json() == {"ok": True}
    assert ("drain", f"dns-a-{sa.id}", "keepalived") in stub.calls
    assert client.post(f"/api/load-balancers/{lb.id}/restart", headers=editor_headers).status_code == 200
    assert ("restart", "keepalived") in stub.calls
    assert client.delete(f"/api/load-balancers/{lb.id}", headers=editor_headers).status_code == 204
    assert any(c[0] == "put" and c[1] == "keepalived" and c[2]["enabled"] is False for c in stub.calls)
    assert not any(c[0] == "put" and c[1] == "dnsdist" for c in stub.calls)


def test_ipvs_read_merges_keepalived_backends(client, viewer_headers, session, zone):
    zone.vip = "10.0.0.53/24"
    session.add(zone)
    session.commit()
    agent = make_agent(session, zone=zone)
    sa = make_server(session, "dns-a", zone, agent)
    lb = make_lb(session, "lb", zone, agent, mode="ipvs")
    lb.keepalived_state = {"state": "ready", "vip_owner": True, "ipvs": {"present": True, "backends": [
        {"name": f"dns-a-{sa.id}", "address": "10.0.0.11", "port": 53, "weight": 1, "state": "up",
         "drained": False, "conns": 100, "active_conns": 1, "inactive_conns": 9, "in_pkts": 100, "in_pps": 2.0},
    ]}}
    session.add(lb)
    session.commit()
    row = client.get(f"/api/load-balancers/{lb.id}", headers=viewer_headers).json()
    live = row["backends"][0]["live"]
    assert live["state"] == "up" and live["qps"] == 2.0 and live["queries"] == 100 and live["conns"] == 100
    assert live["active_conns"] == 1 and live["latency_ms"] is None
    assert row["state"] is None


def test_provision_token_with_ipvs_mode(client, editor_headers, session, zone):
    body = {"name": "edge", "zone_id": zone.id, "roles": ["adguard", "dnsdist"], "lb_mode": "ipvs"}
    assert client.post("/api/provision/tokens", json=body, headers=editor_headers).status_code == 400
    client.patch(f"/api/zones/{zone.id}", json={"vip": "10.0.0.53/24"}, headers=editor_headers)
    r = client.post("/api/provision/tokens", json=body, headers=editor_headers)
    assert r.status_code == 200 and r.json()["lb_mode"] == "ipvs"
    from tests.test_pki import make_csr

    csr, _ = make_csr()
    r = client.post(f"/api/provision/{r.json()['token']}/enroll",
                    json={"csr_pem": csr, "address": "10.0.0.9", "port": 8443})
    assert r.status_code == 200
    lb = session.exec(__import__("sqlmodel").select(LoadBalancer)).one()
    assert lb.mode.value == "ipvs"


# --------------------------------------------------------------------------- #
# Agent updates and AdGuard reinstall
# --------------------------------------------------------------------------- #
def test_update_available_follows_the_shipped_manifest(client, viewer_headers, session, zone, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "agent_bin_dir", str(tmp_path))
    agent = make_agent(session, zone=zone)
    agent.version = "0.1.0"
    session.add(agent)
    session.commit()
    assert client.get("/api/agents", headers=viewer_headers).json()[0]["update_available"] is False
    (tmp_path / "adguard-admin-agent-linux-amd64").write_bytes(b"\x7fELF new")
    (tmp_path / "VERSION").write_text("0.2.0\n")
    assert client.get("/api/agents", headers=viewer_headers).json()[0]["update_available"] is True
    agent.version = "0.2.0"
    session.add(agent)
    session.commit()
    assert client.get("/api/agents", headers=viewer_headers).json()[0]["update_available"] is False


def test_update_endpoint_pushes_and_records(client, editor_headers, viewer_headers, session, zone, monkeypatch):
    from app import hosts

    agent = make_agent(session, zone=zone)
    calls = []

    async def fake_update(agent_id):
        calls.append(agent_id)
        out = hosts.AgentOutcome(agent_id=agent_id, name="host-a", status=hosts.SyncStatus.online)
        out.update_requested = True
        hosts._record_agent(out)
        return out

    monkeypatch.setattr(agents_router, "update_agent_now", fake_update)
    assert client.post(f"/api/agents/{agent.id}/update", headers=viewer_headers).status_code == 403
    r = client.post(f"/api/agents/{agent.id}/update", headers=editor_headers)
    assert r.status_code == 200 and calls == [agent.id]
    assert r.json()["update_attempted_at"] is not None


def test_reinstall_is_admin_only_and_needs_an_agent(client, admin_headers, editor_headers, session, zone, stub):
    agent = make_agent(session, zone=zone)
    managed = make_server(session, "dns-a", zone, agent)
    direct = make_server(session, "direct", zone, url="http://10.0.0.20:3000")
    assert client.post(f"/api/servers/{managed.id}/reinstall", headers=editor_headers).status_code == 403
    assert client.post(f"/api/servers/{direct.id}/reinstall", headers=admin_headers).status_code == 409
    r = client.post(f"/api/servers/{managed.id}/reinstall", headers=admin_headers)
    assert r.status_code == 200 and ("reset",) in stub.calls
    session.expire_all()
    s = session.get(Server, managed.id)
    assert s.status.value == "provisioning" and s.agent_state["message"] == "reinstall requested"
