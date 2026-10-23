"""The metric store: rates, rollups, the Dashboard reads and /metrics."""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app import telemetry
from app.config import settings
from app.models import LbMode, MetricSample, Server, SyncStatus, Zone
from tests.conftest import auth_headers
from tests.test_hosts import make_agent, make_lb, make_server


def make_zone(session, name="LAN", vip=None):
    z = Zone(name=name, slug=name.lower(), vip=vip)
    session.add(z)
    session.commit()
    session.refresh(z)
    return z


def sample(session, kind, entity_id, ts, **values):
    row = MetricSample(ts=ts, resolution=telemetry.RES_MINUTE, kind=kind, entity_id=entity_id, values=values)
    session.add(row)
    session.commit()
    session.refresh(row)
    return row


def stats(queries=1000, blocked=100, hour_q=50, hour_b=5, avg_s=0.012):
    return {
        "num_dns_queries": queries, "num_blocked_filtering": blocked,
        "num_replaced_safebrowsing": 0, "num_replaced_parental": 0, "num_replaced_safesearch": 0,
        "avg_processing_time": avg_s, "time_units": "hours",
        "dns_queries": [10, 20, hour_q], "blocked_filtering": [1, 2, hour_b],
        "replaced_safebrowsing": [0, 0, 0], "replaced_parental": [0, 0, 0],
        "top_queried_domains": [{"example.com": 40}, {"a.lan": 10}],
        "top_blocked_domains": [{"ads.example": 5}],
        "top_clients": [{"192.168.2.10": 30}],
    }


# --------------------------------------------------------------------------- #
# rates
# --------------------------------------------------------------------------- #
def test_rate_from_counter_with_reset_and_gap(session):
    at = telemetry.now_utc()
    prev = MetricSample(ts=at - timedelta(seconds=60), kind="server", entity_id=1, values={"q_counter": 100})
    assert telemetry.rate(prev, "q_counter", 160, at) == 1.0
    # The counter went down: a new hour bucket (or a restart), so the whole
    # value is the delta.
    assert telemetry.rate(prev, "q_counter", 30, at) == 0.5
    assert telemetry.rate(None, "q_counter", 30, at) is None
    assert telemetry.rate(prev, "missing", 30, at) is None
    stale = MetricSample(ts=at - timedelta(days=2), kind="server", entity_id=1, values={"q_counter": 100})
    assert telemetry.rate(stale, "q_counter", 160, at) is None


def test_server_values_prefer_hour_bucket_over_window(session):
    at = telemetry.now_utc()
    prev = MetricSample(ts=at - timedelta(seconds=60), kind="server", entity_id=1,
                        values={"q_counter": 20, "b_counter": 2})
    v = telemetry.server_values(stats(hour_q=80, hour_b=8), online=True, in_sync=True, prev=prev, at=at)
    assert v["q_counter"] == 80 and v["b_counter"] == 8
    assert v["qps"] == 1.0 and v["bps"] == 0.1
    assert v["queries_24h"] == 1000 and v["blocked_24h"] == 100 and v["avg_ms"] == 12.0
    # Without the arrays the window totals stand in.
    s = stats()
    del s["dns_queries"]
    v = telemetry.server_values(s, online=True, in_sync=False, prev=None, at=at)
    assert v["q_counter"] == 1000 and v["b_counter"] == 100 and v["qps"] is None
    assert telemetry.server_values(None, online=False, in_sync=False, prev=None, at=at) == {"online": 0, "in_sync": 0}


def test_agent_and_balancer_values(session):
    at = telemetry.now_utc()
    zone = make_zone(session, vip="10.0.0.53/24")
    agent = make_agent(session, zone=zone)
    agent.status = SyncStatus.online
    agent.cert_not_after = at + timedelta(days=100)
    agent.health = {
        "load": [0.5, 0.4, 0.3],
        "mem": {"total_bytes": 1000, "available_bytes": 250},
        "disks": [{"path": "/", "total_bytes": 100, "free_bytes": 50}, {"path": "/var", "total_bytes": 100, "free_bytes": 10}],
        "services": {"adguard": {"present": True, "running": True}, "keepalived": {"present": True, "running": False}},
    }
    v = telemetry.agent_values(agent, at=at)
    assert v["online"] == 1 and v["load1"] == 0.5 and v["mem_used"] == 0.75 and v["disk_used"] == 0.9
    assert v["services_down"] == 1 and 99 < v["cert_days"] <= 100

    lb = make_lb(session, "lb-ipvs", zone, agent, mode=LbMode.ipvs, status=SyncStatus.online, in_sync=True,
                 keepalived_state={"vip_owner": True, "ipvs": {"present": True, "director": True, "backends": [
                     {"name": "a", "state": "up", "in_pkts": 600}, {"name": "b", "state": "down", "in_pkts": 400}]}})
    prev = MetricSample(ts=at - timedelta(seconds=60), kind="load_balancer", entity_id=lb.id, values={"q_counter": 940})
    v = telemetry.balancer_values(lb, prev=prev, at=at)
    assert v == {"online": 1, "in_sync": 1, "vip_owner": 1, "director": 1, "backends_total": 2, "backends_up": 1,
                 "q_counter": 1000, "qps": 1.0}

    lb2 = make_lb(session, "lb-dnsdist", zone, agent, status=SyncStatus.online,
                  state={"backends": [{"name": "a", "state": "up", "drained": True}],
                         "stats": {"queries": 500, "cache-hits": 30, "cache-misses": 70}})
    v = telemetry.balancer_values(lb2, prev=None, at=at)
    assert v["backends_up"] == 0 and v["backends_total"] == 1 and v["cache_hit"] == 0.3
    assert v["q_counter"] == 500 and v["qps"] is None and "director" not in v


# --------------------------------------------------------------------------- #
# the collector end to end
# --------------------------------------------------------------------------- #
@pytest.mark.anyio
async def test_collect_all_stores_samples_and_snapshots(session, monkeypatch):
    zone = make_zone(session)
    ok = make_server(session, "ok", zone)
    ok.status = SyncStatus.online
    bad = make_server(session, "bad", zone)
    session.add(ok)
    session.commit()

    async def fake_fan_out(targets, call, *, limit=None):
        from app.fleet import Outcome
        return [
            Outcome(target=t, value=stats()) if t.name == "ok" else Outcome(target=t, error="connect refused")
            for t in targets
        ]

    monkeypatch.setattr(telemetry, "fan_out", fake_fan_out)
    await telemetry.collect_all(limit=2)
    await telemetry.collect_all(limit=2)

    session.expire_all()
    rows = session.exec(__import__("sqlmodel").select(MetricSample)).all()
    by = {(r.entity_id): r for r in rows if r.kind == "server"}
    assert len([r for r in rows if r.kind == "server"]) == 4
    latest = telemetry.latest(session, "server")
    assert latest[ok.id].values["online"] == 1 and latest[ok.id].values["queries_24h"] == 1000
    # Second sample of an unchanged counter: a rate of zero, not None.
    assert latest[ok.id].values["qps"] == 0.0
    assert latest[bad.id].values == {"online": 0, "in_sync": 0}
    ok_row = session.get(Server, ok.id)
    assert ok_row.stats_snapshot["num_dns_queries"] == 1000
    assert ok_row.stats_snapshot["top_queried_domains"][0] == {"example.com": 40}
    assert session.get(Server, bad.id).stats_snapshot["error"] == "connect refused"
    assert by


def test_rollup_and_prune(session, monkeypatch):
    monkeypatch.setattr(settings, "metrics_retention_days", 7)
    monkeypatch.setattr(settings, "metrics_rollup_retention_days", 90)
    at = datetime(2026, 10, 23, 12, 30)
    two_hours_ago = at - timedelta(hours=2)
    # Three minute-samples in the hour that ended two hours ago, one in the
    # current (incomplete) hour, one ancient.
    for minute, qps in ((0, 1.0), (1, 3.0), (2, None)):
        sample(session, "server", 1, two_hours_ago.replace(minute=minute), qps=qps, online=1, q_counter=5)
    sample(session, "server", 1, at - timedelta(minutes=5), qps=9.0, online=1)
    sample(session, "server", 1, at - timedelta(days=10), qps=9.0, online=1)
    old_hour = MetricSample(ts=at - timedelta(days=100), resolution="1h", kind="server", entity_id=1, values={"qps": 1})
    session.add(old_hour)
    session.commit()

    assert telemetry.rollup(session, at) == 1
    session.commit()
    hours = session.exec(__import__("sqlmodel").select(MetricSample).where(MetricSample.resolution == "1h")).all()
    new = [h for h in hours if h.ts == two_hours_ago.replace(minute=0)]
    assert len(new) == 1
    # Mean of the non-null rates; counters are not carried over.
    assert new[0].values["qps"] == 2.0 and new[0].values["online"] == 1.0 and new[0].values["samples"] == 3
    assert "q_counter" not in new[0].values
    # Running it again adds nothing.
    assert telemetry.rollup(session, at) == 0

    telemetry.prune(session, at)
    session.commit()
    rows = session.exec(__import__("sqlmodel").select(MetricSample)).all()
    assert all(r.ts >= at - timedelta(days=7) for r in rows if r.resolution == "1m")
    assert all(r.ts >= at - timedelta(days=90) for r in rows if r.resolution == "1h")


# --------------------------------------------------------------------------- #
# reads
# --------------------------------------------------------------------------- #
def test_series_buckets_sum_servers_and_fill_gaps(session):
    at = telemetry.now_utc()
    zone = make_zone(session)
    a = make_server(session, "a", zone)
    b = make_server(session, "b", zone)
    for m in range(1, 4):
        sample(session, "server", a.id, at - timedelta(minutes=m), qps=2.0, bps=0.5, avg_ms=10.0, online=1)
        sample(session, "server", b.id, at - timedelta(minutes=m), qps=1.0, bps=0.5, avg_ms=30.0, online=1)
    out = telemetry.series(session, "server", [a.id, b.id], "1h")
    assert out["step_s"] == 60 and out["resolution"] == "1m" and out["entities"] == 2
    assert len(out["points"]) == 60
    filled = [p for p in out["points"] if p["qps"] is not None]
    assert len(filled) == 3
    assert filled[0]["qps"] == 3.0 and filled[0]["bps"] == 1.0 and filled[0]["avg_ms"] == 20.0 and filled[0]["reporting"] == 2
    assert out["points"][0]["qps"] is None
    span, step, res = telemetry.plan_range("7d")
    assert res == "1h" and step == 3600
    assert telemetry.plan_range("24h")[1] == 600


def test_overview_traffic_and_attention(session):
    at = telemetry.now_utc()
    lan = make_zone(session, "LAN", vip="10.0.0.53/24")
    dmz = make_zone(session, "DMZ")
    agent = make_agent(session, zone=lan)
    agent.status = SyncStatus.offline
    agent.last_error = "connect timeout"
    agent.cert_not_after = at + timedelta(days=10)
    s1 = make_server(session, "lan-1", lan)
    s1.status = SyncStatus.online
    s1.in_sync = True
    s1.stats_snapshot = telemetry.snapshot_of(stats(), error=None, at=at)
    s2 = make_server(session, "lan-2", lan)
    s2.status = SyncStatus.offline
    s2.last_error = "refused"
    s3 = make_server(session, "dmz-1", dmz)
    s3.status = SyncStatus.online
    s3.in_sync = False
    s3.stats_snapshot = telemetry.snapshot_of(stats(queries=500, blocked=50), error=None, at=at)
    session.add_all([agent, s1, s2, s3])
    session.commit()
    sample(session, "server", s1.id, at, online=1, qps=2.0, bps=0.2, queries_24h=1000, blocked_24h=100)
    sample(session, "server", s3.id, at, online=1, qps=1.0, bps=0.1, queries_24h=500, blocked_24h=50)
    lb = make_lb(session, "lb-1", lan, agent, mode=LbMode.ipvs, status=SyncStatus.online, in_sync=True,
                 keepalived_state={"vip_owner": False, "ipvs": {"present": True, "backends": [
                     {"name": "lan-1-1", "state": "up"}, {"name": "lan-2-2", "state": "down"}]}})

    ov = telemetry.overview(session)
    assert ov["fleet"]["qps"] == 3.0 and ov["fleet"]["queries_24h"] == 1500 and ov["fleet"]["blocked_pct"] == 10.0
    assert ov["fleet"]["servers"] == 3 and ov["fleet"]["reporting"] == 2
    lan_row = next(z for z in ov["zones"] if z["zone_id"] == lan.id)
    assert lan_row["qps"] == 2.0 and lan_row["servers"] == 2 and lan_row["reporting"] == 1

    tr = telemetry.traffic(session, None, None)
    assert tr["totals"]["num_dns_queries"] == 1500 and tr["reporting"] == 2 and tr["selected"] == 3
    assert tr["top_queried"][0] == {"name": "example.com", "count": 80}
    offline = next(s for s in tr["servers"] if s["name"] == "lan-2")
    assert offline["online"] is False and offline["error"] == "refused"
    assert telemetry.traffic(session, dmz.id, None)["totals"]["num_dns_queries"] == 500

    items = telemetry.attention(session, last_sync=at - timedelta(hours=4))  # > 3 test intervals
    messages: dict = {}
    for i in items:  # worst first, so the first finding per entity is its worst
        messages.setdefault((i["kind"], i["name"]), i)
    assert messages[("server", "lan-2")]["severity"] == "critical"
    assert messages[("server", "dmz-1")]["message"].startswith("configuration drift")
    assert messages[("agent", "host-a")]["severity"] == "critical"
    # A server that is offline because its host is offline is not listed twice.
    s_on_host = make_server(session, "on-host", lan, agent=agent)
    s_on_host.status = SyncStatus.offline
    session.add(s_on_host)
    session.commit()
    names = [(i["kind"], i["name"]) for i in telemetry.attention(session, last_sync=at)]
    assert ("server", "on-host") not in names and ("agent", "host-a") in names
    assert any(i["message"].startswith("agent certificate expires in") for i in items)
    assert messages[("load_balancer", "lb-1")]["message"] == "1 backend down: lan-2-2"
    assert messages[("zone", "LAN")]["message"] == "no balancer holds the VIP 10.0.0.53/24"
    assert messages[("fleet", "reconcile loop")]["severity"] == "warning"
    assert items[0]["severity"] == "critical"
    assert telemetry.attention(session, last_sync=None) and \
        not [i for i in telemetry.attention(session, last_sync=at) if i["kind"] == "fleet"]
    assert lb.id


# --------------------------------------------------------------------------- #
# the HTTP surface
# --------------------------------------------------------------------------- #
def test_api_reads_from_store(client, session, admin_user):
    headers = auth_headers(client, "admin-user", "pw-for-tests-123")
    zone = make_zone(session)
    s = make_server(session, "s", zone)
    s.status = SyncStatus.online
    s.in_sync = True
    s.stats_snapshot = telemetry.snapshot_of(stats(), error=None, at=telemetry.now_utc())
    session.add(s)
    session.commit()
    sample(session, "server", s.id, telemetry.now_utc(), online=1, qps=4.0, bps=1.0, queries_24h=1000, blocked_24h=100)
    assert client.get("/api/metrics", headers=headers).json()["totals"]["num_dns_queries"] == 1000
    assert client.get("/api/metrics/overview", headers=headers).json()["fleet"]["qps"] == 4.0
    ser = client.get("/api/metrics/series?range=6h", headers=headers).json()
    assert ser["step_s"] == 300 and any(p["qps"] == 4.0 for p in ser["points"])
    assert client.get("/api/metrics/attention", headers=headers).json() == []
    assert client.get("/api/metrics/series").status_code == 401


def test_prometheus_endpoint_is_gated_and_exposes_the_fleet(client, session, monkeypatch):
    monkeypatch.setattr(settings, "metrics_token", "")
    assert client.get("/metrics").status_code == 404
    monkeypatch.setattr(settings, "metrics_token", "scrape-me")
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401

    at = telemetry.now_utc()
    zone = make_zone(session, "LAN", vip="10.0.0.53/24")
    agent = make_agent(session, 'host "a"', zone=zone)
    agent.status = SyncStatus.online
    agent.version = "8835c5af"
    agent.cert_not_after = at + timedelta(days=200)
    s = make_server(session, "lan-1", zone, agent=agent)
    s.status = SyncStatus.online
    s.in_sync = True
    s.version = "v0.107.80"
    session.add_all([agent, s])
    session.commit()
    sample(session, "server", s.id, at, online=1, qps=4.5, bps=1.0, queries_24h=1000, blocked_24h=100, avg_ms=12.0)
    sample(session, "agent", agent.id, at, online=1, load1=0.5, mem_used=0.4, disk_used=0.6, services_down=0)
    lb = make_lb(session, "lb-1", zone, agent, mode=LbMode.ipvs, status=SyncStatus.online, in_sync=True,
                 keepalived_state={"vip_owner": True, "ipvs": {"present": True, "director": True, "backends": [
                     {"name": "lan-1-1", "state": "up", "in_pps": 4.5}]}})
    sample(session, "load_balancer", lb.id, at, online=1, in_sync=1, vip_owner=1, director=1, backends_up=1,
           backends_total=1, qps=4.5)

    resp = client.get("/metrics", headers={"Authorization": "Bearer scrape-me"})
    assert resp.status_code == 200 and resp.headers["content-type"].startswith("text/plain")
    body = resp.text
    assert 'adguard_admin_server_queries_per_second{server="lan-1",zone="LAN"} 4.5' in body
    assert 'adguard_admin_server_info{server="lan-1",zone="LAN",version="v0.107.80",enabled="true"} 1' in body
    assert 'adguard_admin_agent_load1{host="host \\"a\\"",zone="LAN"} 0.5' in body
    assert 'adguard_admin_balancer_vip_owner{balancer="lb-1",zone="LAN",mode="ipvs",host="host \\"a\\""} 1' in body
    assert 'adguard_admin_balancer_backend_queries_per_second{balancer="lb-1",zone="LAN",mode="ipvs",host="host \\"a\\"",backend="lan-1-1"} 4.5' in body
    assert "# TYPE adguard_admin_fleet_servers gauge" in body
    assert "adguard_admin_fleet_servers{} 1" in body
    assert body.count("# HELP adguard_admin_server_up ") == 1
