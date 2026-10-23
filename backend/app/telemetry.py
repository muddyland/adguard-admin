"""Metric samples: collected once a cycle, stored in the database, served to
the Dashboard, the Traffic page and Prometheus.

Why a store: the Dashboard used to fan out to every AdGuard server on each
page load and could only ever show "now". The reconcile loop already talks to
every server and agent once a minute, so the collector rides on it: one stats
call per server, plus what the host and balancer reconciles have just written.
One row per entity per cycle, with the per-second rates computed here from the
previous row, so readers never have to reason about counters.

Resolutions: "1m" rows are kept for METRICS_RETENTION_DAYS; once an hour they
are rolled up into "1h" rows (means of the rates and gauges) that live for
METRICS_ROLLUP_RETENTION_DAYS.
"""
from __future__ import annotations

import logging
import math
import secrets
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from sqlmodel import Session, delete, select

from .config import settings
from .database import engine
from .fleet import as_number, blocked_total, fan_out, load_targets
from .models import Agent, LbMode, LoadBalancer, MetricSample, Server, SyncStatus, Zone

logger = logging.getLogger("adguard_admin.telemetry")

RES_MINUTE = "1m"
RES_HOUR = "1h"
KIND_SERVER = "server"
KIND_AGENT = "agent"
KIND_BALANCER = "load_balancer"

# Fields that are rates or gauges and therefore average cleanly into rollups.
# Counters (the *_counter fields) exist only so the next sample can derive a
# rate; they are never rolled up.
AVERAGED = (
    "online", "in_sync", "qps", "bps", "avg_ms", "queries_24h", "blocked_24h",
    "load1", "load5", "load15", "mem_used", "disk_used", "services_down", "cert_days",
    "vip_owner", "director", "backends_up", "backends_total", "cache_hit",
)


# --------------------------------------------------------------------------- #
# Time helpers. SQLite hands back naive datetimes; everything here is naive UTC.
# --------------------------------------------------------------------------- #
def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def naive(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def iso(dt: datetime | None) -> str | None:
    return dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z") if dt else None


def rate(prev: MetricSample | None, counter: str, current: float | None, at: datetime) -> float | None:
    """Per-second rate from the previous row's counter.

    A counter that went down was reset (dnsdist restarted, keepalived
    reprogrammed the table, AdGuard rolled into a new hour bucket), so the new
    value is the whole delta. None when there is nothing to compare against or
    the gap is too long to mean anything.
    """
    if current is None or prev is None:
        return None
    before = prev.values.get(counter)
    if before is None:
        return None
    dt = (at - naive(prev.ts)).total_seconds()
    if dt <= 0 or dt > settings.sync_interval_seconds * 5:
        return None
    delta = current - before if current >= before else current
    return round(max(0.0, delta / dt), 3)


def latest(session: Session, kind: str, within: timedelta | None = None) -> dict[int, MetricSample]:
    """The newest 1m row per entity of a kind (optionally only recent ones)."""
    stmt = select(MetricSample).where(MetricSample.kind == kind, MetricSample.resolution == RES_MINUTE)
    if within is not None:
        stmt = stmt.where(MetricSample.ts >= now_utc() - within)
    out: dict[int, MetricSample] = {}
    for row in session.exec(stmt.order_by(MetricSample.ts)).all():
        out[row.entity_id] = row
    return out


# --------------------------------------------------------------------------- #
# Sample builders
# --------------------------------------------------------------------------- #
def _last(values) -> float | None:
    if isinstance(values, list) and values:
        return as_number(values[-1])
    return None


def server_values(stats: dict | None, *, online: bool, in_sync: bool, prev: MetricSample | None, at: datetime) -> dict:
    v: dict[str, Any] = {"online": 1 if online else 0, "in_sync": 1 if in_sync else 0}
    if not online or not isinstance(stats, dict):
        return v
    q_total = as_number(stats.get("num_dns_queries", 0))
    b_total = blocked_total(stats)
    v["queries_24h"] = q_total
    v["blocked_24h"] = b_total
    v["avg_ms"] = round(as_number(stats.get("avg_processing_time", 0.0)) * 1000, 3)
    # AdGuard's totals are a sliding window that drops a bucket every hour, so
    # they cannot be differenced. The last bucket of the per-hour arrays only
    # ever grows within its hour and resets at the boundary, which the reset
    # rule in rate() handles.
    q_counter = _last(stats.get("dns_queries"))
    if q_counter is None:
        q_counter = q_total
        b_counter = b_total
    else:
        b_counter = sum(
            _last(stats.get(key)) or 0.0
            for key in ("blocked_filtering", "replaced_safebrowsing", "replaced_parental")
        )
    v["q_counter"] = q_counter
    v["b_counter"] = b_counter
    v["qps"] = rate(prev, "q_counter", q_counter, at)
    v["bps"] = rate(prev, "b_counter", b_counter, at)
    return v


def snapshot_of(stats: dict | None, *, error: str | None, at: datetime) -> dict:
    """What the Traffic page shows per server: the window totals and top lists."""
    snap: dict[str, Any] = {"fetched_at": iso(at)}
    if not isinstance(stats, dict):
        snap["error"] = error or "no data"
        return snap
    q = as_number(stats.get("num_dns_queries", 0))
    b = blocked_total(stats)
    snap.update({
        "num_dns_queries": int(q), "num_blocked": int(b),
        "blocked_pct": round(b / q * 100, 2) if q else 0,
        "avg_processing_ms": round(as_number(stats.get("avg_processing_time", 0.0)) * 1000, 2),
        "time_units": stats.get("time_units"),
    })
    for key in ("top_queried_domains", "top_blocked_domains", "top_clients"):
        lst = stats.get(key)
        snap[key] = lst[:25] if isinstance(lst, list) else []
    return snap


def agent_values(agent: Agent, *, at: datetime) -> dict:
    v: dict[str, Any] = {"online": 1 if agent.status == SyncStatus.online else 0}
    h = agent.health if isinstance(agent.health, dict) else {}
    load = h.get("load")
    if isinstance(load, list):
        for i, key in enumerate(("load1", "load5", "load15")):
            if i < len(load):
                v[key] = round(as_number(load[i]), 3)
    mem = h.get("mem") if isinstance(h.get("mem"), dict) else {}
    total = as_number(mem.get("total_bytes", 0))
    if total > 0:
        v["mem_used"] = round(1 - as_number(mem.get("available_bytes", 0)) / total, 4)
    worst = None
    for d in h.get("disks") or []:
        if not isinstance(d, dict):
            continue
        dt = as_number(d.get("total_bytes", 0))
        if dt > 0:
            used = 1 - as_number(d.get("free_bytes", 0)) / dt
            worst = used if worst is None else max(worst, used)
    if worst is not None:
        v["disk_used"] = round(worst, 4)
    services = h.get("services") if isinstance(h.get("services"), dict) else {}
    v["services_down"] = sum(
        1 for s in services.values()
        if isinstance(s, dict) and s.get("present") and not s.get("running")
    )
    if agent.cert_not_after:
        v["cert_days"] = round((naive(agent.cert_not_after) - at).total_seconds() / 86400, 2)
    return v


def balancer_values(lb: LoadBalancer, *, prev: MetricSample | None, at: datetime) -> dict:
    v: dict[str, Any] = {
        "online": 1 if lb.status == SyncStatus.online else 0,
        "in_sync": 1 if lb.in_sync else 0,
    }
    ks = lb.keepalived_state if isinstance(lb.keepalived_state, dict) else {}
    if ks:
        v["vip_owner"] = 1 if ks.get("vip_owner") else 0
    if lb.mode == LbMode.ipvs:
        ipvs = ks.get("ipvs") if isinstance(ks.get("ipvs"), dict) else {}
        backends = [b for b in (ipvs.get("backends") or []) if isinstance(b, dict)]
        if "director" in ipvs:
            v["director"] = 1 if ipvs.get("director") else 0
        counter = None
        if backends and all(b.get("in_pkts") is not None for b in backends):
            counter = sum(as_number(b.get("in_pkts")) for b in backends)
    else:
        st = lb.state if isinstance(lb.state, dict) else {}
        backends = [b for b in (st.get("backends") or []) if isinstance(b, dict)]
        stats = st.get("stats") if isinstance(st.get("stats"), dict) else {}
        counter = as_number(stats["queries"]) if "queries" in stats else None
        hits, misses = as_number(stats.get("cache-hits", 0)), as_number(stats.get("cache-misses", 0))
        if hits + misses > 0:
            v["cache_hit"] = round(hits / (hits + misses), 4)
    v["backends_total"] = len(backends)
    v["backends_up"] = sum(1 for b in backends if b.get("state") == "up" and not b.get("drained"))
    if counter is not None:
        v["q_counter"] = counter
        v["qps"] = rate(prev, "q_counter", counter, at)
    return v


# --------------------------------------------------------------------------- #
# The collector
# --------------------------------------------------------------------------- #
_last_rollup: datetime | None = None


async def collect_all(*, limit: int | None = None) -> None:
    """One sample per enabled server, agent and balancer, then housekeeping."""
    if not settings.metrics_enabled:
        return
    at = now_utc()
    targets = load_targets()
    outcomes = await fan_out(targets, lambda c: c.stats(), limit=limit)

    with Session(engine) as session:
        prev_servers = latest(session, KIND_SERVER, within=timedelta(minutes=30))
        prev_lbs = latest(session, KIND_BALANCER, within=timedelta(minutes=30))
        servers = {s.id: s for s in session.exec(select(Server)).all()}
        for out in outcomes:
            server = servers.get(out.target.id)
            if server is None:
                continue
            stats = out.value if out.ok and isinstance(out.value, dict) else None
            online = out.ok and server.status != SyncStatus.error
            session.add(MetricSample(
                ts=at, resolution=RES_MINUTE, kind=KIND_SERVER, entity_id=server.id,
                values=server_values(stats, online=online, in_sync=bool(server.in_sync),
                                     prev=prev_servers.get(server.id), at=at),
            ))
            server.stats_snapshot = snapshot_of(stats, error=out.error, at=at)
            session.add(server)
        for agent in session.exec(select(Agent)).all():
            session.add(MetricSample(
                ts=at, resolution=RES_MINUTE, kind=KIND_AGENT, entity_id=agent.id,
                values=agent_values(agent, at=at),
            ))
        for lb in session.exec(select(LoadBalancer)).all():
            if not lb.enabled:
                continue
            session.add(MetricSample(
                ts=at, resolution=RES_MINUTE, kind=KIND_BALANCER, entity_id=lb.id,
                values=balancer_values(lb, prev=prev_lbs.get(lb.id), at=at),
            ))
        session.commit()

    global _last_rollup
    if _last_rollup is None or at - _last_rollup >= timedelta(hours=1):
        try:
            with Session(engine) as session:
                rollup(session, at)
                prune(session, at)
                session.commit()
            _last_rollup = at
        except Exception:
            logger.exception("metrics rollup failed")


def _mean(values: Iterable[float | None]) -> float | None:
    xs = [x for x in values if x is not None and not (isinstance(x, float) and math.isnan(x))]
    return round(sum(xs) / len(xs), 3) if xs else None


def rollup(session: Session, at: datetime) -> int:
    """Turn every complete hour of 1m rows that has no 1h row yet into one.

    Bounded to the 1m retention window, which is also as far back as there is
    anything to roll up.
    """
    hour = at.replace(minute=0, second=0, microsecond=0)
    floor = at - timedelta(days=settings.metrics_retention_days)
    done = {
        (r.kind, r.entity_id, naive(r.ts))
        for r in session.exec(
            select(MetricSample).where(MetricSample.resolution == RES_HOUR, MetricSample.ts >= floor)
        ).all()
    }
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in session.exec(
        select(MetricSample).where(
            MetricSample.resolution == RES_MINUTE, MetricSample.ts >= floor, MetricSample.ts < hour,
        )
    ).all():
        start = naive(r.ts).replace(minute=0, second=0, microsecond=0)
        key = (r.kind, r.entity_id, start)
        if key not in done:
            groups[key].append(r.values)
    for (kind, entity_id, start), rows in groups.items():
        values = {k: _mean(v.get(k) for v in rows) for k in AVERAGED}
        values = {k: v for k, v in values.items() if v is not None}
        values["samples"] = len(rows)
        session.add(MetricSample(ts=start, resolution=RES_HOUR, kind=kind, entity_id=entity_id, values=values))
    return len(groups)


def prune(session: Session, at: datetime) -> None:
    session.exec(delete(MetricSample).where(
        MetricSample.resolution == RES_MINUTE,
        MetricSample.ts < at - timedelta(days=settings.metrics_retention_days),
    ))
    session.exec(delete(MetricSample).where(
        MetricSample.resolution == RES_HOUR,
        MetricSample.ts < at - timedelta(days=settings.metrics_rollup_retention_days),
    ))


# --------------------------------------------------------------------------- #
# Reads
# --------------------------------------------------------------------------- #
RANGES = {"1h": 3600, "6h": 6 * 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}
STEPS = (60, 300, 600, 900, 1800, 3600, 7200, 21600, 43200)


def plan_range(name: str) -> tuple[int, int, str]:
    """(span seconds, step seconds, resolution) for a named range."""
    span = RANGES.get(name, RANGES["24h"])
    resolution = RES_MINUTE if span <= 48 * 3600 else RES_HOUR
    floor = 60 if resolution == RES_MINUTE else 3600
    want = span / 200  # about 200 points per chart
    step = next((s for s in STEPS if s >= want and s >= floor), STEPS[-1])
    return span, step, resolution


def series(session: Session, kind: str, entity_ids: list[int], range_name: str, *, fields=("qps", "bps", "avg_ms")) -> dict:
    """Bucketed, fleet-summed series for a set of entities.

    Within a bucket each entity's samples are averaged, then entities are
    summed (rates) or averaged (avg_ms), so a bucket with two samples from one
    server and one from another is not biased toward the chatty one. Buckets
    with no data are present with nulls so the x-axis stays continuous.
    """
    span, step, resolution = plan_range(range_name)
    end = now_utc()
    start = end - timedelta(seconds=span)
    per_bucket: dict[int, dict[int, dict[str, list]]] = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    if entity_ids:
        rows = session.exec(
            select(MetricSample).where(
                MetricSample.kind == kind, MetricSample.resolution == resolution,
                MetricSample.entity_id.in_(entity_ids),  # type: ignore[attr-defined]
                MetricSample.ts >= start, MetricSample.ts <= end,
            )
        ).all()
        for r in rows:
            b = int(naive(r.ts).timestamp() // step * step)
            for f in fields:
                per_bucket[b][r.entity_id][f].append(r.values.get(f))
            per_bucket[b][r.entity_id]["online"].append(r.values.get("online"))
    first = int(start.timestamp() // step * step) + step
    last = int(end.timestamp() // step * step)
    points = []
    for b in range(first, last + 1, step):
        ents = per_bucket.get(b, {})
        point: dict[str, Any] = {"ts": iso(datetime.fromtimestamp(b, tz=timezone.utc).replace(tzinfo=None))}
        for f in fields:
            means = [_mean(e[f]) for e in ents.values()]
            means = [m for m in means if m is not None]
            if not means:
                point[f] = None
            elif f == "avg_ms":
                point[f] = round(sum(means) / len(means), 3)
            else:
                point[f] = round(sum(means), 3)
        point["reporting"] = sum(1 for e in ents.values() if (_mean(e["online"]) or 0) >= 0.5)
        points.append(point)
    return {"range": range_name if range_name in RANGES else "24h", "step_s": step, "resolution": resolution,
            "entities": len(entity_ids), "points": points}


def overview(session: Session) -> dict:
    """Fleet and per-zone traffic from the newest samples and snapshots."""
    fresh = latest(session, KIND_SERVER, within=timedelta(seconds=settings.sync_interval_seconds * 5))
    servers = session.exec(select(Server).where(Server.enabled == True)).all()  # noqa: E712
    zones = session.exec(select(Zone)).all()
    by_zone: dict[int | None, list[Server]] = defaultdict(list)
    for s in servers:
        by_zone[s.zone_id].append(s)

    def sum_of(group: list[Server]) -> dict:
        qps = bps = q24 = b24 = 0.0
        reporting = 0
        have_rate = False
        for s in group:
            row = fresh.get(s.id)
            if not row or not row.values.get("online"):
                continue
            reporting += 1
            v = row.values
            q24 += v.get("queries_24h") or 0
            b24 += v.get("blocked_24h") or 0
            if v.get("qps") is not None:
                have_rate = True
                qps += v["qps"]
                bps += v.get("bps") or 0
        return {
            "servers": len(group), "reporting": reporting,
            "qps": round(qps, 2) if have_rate else None, "bps": round(bps, 2) if have_rate else None,
            "queries_24h": int(q24), "blocked_24h": int(b24),
            "blocked_pct": round(b24 / q24 * 100, 2) if q24 else 0,
        }

    newest = max((naive(r.ts) for r in fresh.values()), default=None)
    return {
        "as_of": iso(newest),
        "fleet": sum_of(servers),
        "zones": [{"zone_id": z.id, "name": z.name, **sum_of(by_zone.get(z.id, []))} for z in zones],
    }


def traffic(session: Session, zone_id: int | None, server_id: int | None) -> dict:
    """The per-server breakdown and merged top lists, from stored snapshots.

    Same shape the live endpoint used to return, so the page did not change
    with the data source.
    """
    stmt = select(Server).where(Server.enabled == True)  # noqa: E712
    if zone_id is not None:
        stmt = stmt.where(Server.zone_id == zone_id)
    if server_id is not None:
        stmt = stmt.where(Server.id == server_id)
    servers = session.exec(stmt.order_by(Server.name)).all()
    per_server, tops_q, tops_b, tops_c = [], [], [], []
    total_q = total_b = 0
    weighted = 0.0
    reporting = 0
    oldest = None
    for s in servers:
        snap = s.stats_snapshot if isinstance(s.stats_snapshot, dict) else None
        if not snap or "error" in snap or s.status in (SyncStatus.offline, SyncStatus.error):
            per_server.append({"server_id": s.id, "name": s.name, "online": False,
                               "error": (snap or {}).get("error") or s.last_error or "no data yet"})
            continue
        reporting += 1
        q, b = snap.get("num_dns_queries", 0), snap.get("num_blocked", 0)
        total_q += q
        total_b += b
        weighted += snap.get("avg_processing_ms", 0) * q
        tops_q.append(snap.get("top_queried_domains"))
        tops_b.append(snap.get("top_blocked_domains"))
        tops_c.append(snap.get("top_clients"))
        per_server.append({
            "server_id": s.id, "name": s.name, "online": True,
            "num_dns_queries": q, "num_blocked": b,
            "blocked_pct": snap.get("blocked_pct", 0), "avg_processing_ms": snap.get("avg_processing_ms", 0),
        })
        fetched = snap.get("fetched_at")
        if fetched and (oldest is None or fetched < oldest):
            oldest = fetched
    return {
        "totals": {
            "num_dns_queries": int(total_q), "num_blocked": int(total_b),
            "blocked_pct": round(total_b / total_q * 100, 2) if total_q else 0,
            "avg_processing_ms": round(weighted / total_q, 2) if total_q else 0,
        },
        "servers": per_server, "reporting": reporting, "selected": len(servers),
        "top_queried": merge_top(tops_q), "top_blocked": merge_top(tops_b), "top_clients": merge_top(tops_c),
        "as_of": oldest,
    }


def merge_top(lists: list, limit: int = 10) -> list[dict]:
    """AdGuard top lists are [{'name': count}, ...]; sum counts across servers."""
    agg: dict[str, float] = {}
    for lst in lists:
        if not isinstance(lst, list):
            continue
        for item in lst:
            if not isinstance(item, dict):
                continue
            for key, value in item.items():
                agg[str(key)] = agg.get(str(key), 0) + as_number(value)
    top = sorted(agg.items(), key=lambda kv: kv[1], reverse=True)[:limit]
    return [{"name": k, "count": int(v)} for k, v in top]


# --------------------------------------------------------------------------- #
# Needs attention
# --------------------------------------------------------------------------- #
def attention(session: Session, *, last_sync: datetime | None) -> list[dict]:
    """Everything that is currently wrong, worst first. Empty means all clear."""
    at = now_utc()
    items: list[dict] = []

    def add(severity: str, kind: str, entity_id: int | None, name: str, message: str, link: str) -> None:
        items.append({"severity": severity, "kind": kind, "entity_id": entity_id, "name": name,
                      "message": message, "link": link})

    zones = {z.id: z for z in session.exec(select(Zone)).all()}
    agents = {a.id: a for a in session.exec(select(Agent)).all()}
    # One unreachable host is one finding: the server and balancer that live
    # on it are down for the same reason, so they are not listed again.
    down_hosts = {a.id for a in agents.values() if a.status in (SyncStatus.offline, SyncStatus.error)}
    for s in session.exec(select(Server).where(Server.enabled == True)).all():  # noqa: E712
        if s.status in (SyncStatus.offline, SyncStatus.error):
            if s.agent_id in down_hosts:
                continue
            add("critical", "server", s.id, s.name, s.last_error or f"server is {s.status.value}", "/servers")
        elif s.status == SyncStatus.online and not s.in_sync:
            add("warning", "server", s.id, s.name, "configuration drift: not in sync", "/servers")
        if s.cooldown_until and naive(s.cooldown_until) > at:
            add("warning", "server", s.id, s.name, "in cooldown after an auth failure or rate limit", "/servers")
        if getattr(s.update_state, "value", s.update_state) == "failed":
            add("warning", "server", s.id, s.name, "last AdGuard update failed: " + (s.update_error or ""), "/updates")
    for a in agents.values():
        if a.status in (SyncStatus.offline, SyncStatus.error):
            add("critical", "agent", a.id, a.name, a.last_error or "host agent unreachable", "/hosts")
        if a.cert_not_after:
            days = (naive(a.cert_not_after) - at).total_seconds() / 86400
            if days < 0:
                add("critical", "agent", a.id, a.name, "agent certificate has expired", "/hosts")
            elif days < 30:
                add("warning", "agent", a.id, a.name, f"agent certificate expires in {int(days)} days", "/hosts")
        if a.update_error:
            add("warning", "agent", a.id, a.name, "agent self-update failed: " + a.update_error, "/hosts")
        h = a.health if isinstance(a.health, dict) else {}
        for d in h.get("disks") or []:
            if isinstance(d, dict) and as_number(d.get("total_bytes", 0)) > 0:
                used = 1 - as_number(d.get("free_bytes", 0)) / as_number(d.get("total_bytes", 0))
                if used >= 0.9:
                    add("warning", "agent", a.id, a.name, f"disk {d.get('path', '/')} is {int(used * 100)}% full", "/hosts")
    lbs = session.exec(select(LoadBalancer).where(LoadBalancer.enabled == True)).all()  # noqa: E712
    by_zone: dict[int | None, list[LoadBalancer]] = defaultdict(list)
    for lb in lbs:
        by_zone[lb.zone_id].append(lb)
        if lb.status in (SyncStatus.offline, SyncStatus.error):
            if lb.agent_id not in down_hosts:
                add("critical", "load_balancer", lb.id, lb.name, lb.last_error or f"balancer is {lb.status.value}", "/load-balancers")
            continue
        if not lb.in_sync:
            add("warning", "load_balancer", lb.id, lb.name, "balancer configuration drift", "/load-balancers")
        ks = lb.keepalived_state if isinstance(lb.keepalived_state, dict) else {}
        if lb.mode == LbMode.ipvs:
            ipvs = ks.get("ipvs") if isinstance(ks.get("ipvs"), dict) else {}
            backends = ipvs.get("backends") or []
            if ipvs and ipvs.get("present") is False and ks.get("vip_owner"):
                add("critical", "load_balancer", lb.id, lb.name, "VIP owner has no IPVS virtual server programmed", "/load-balancers")
        else:
            st = lb.state if isinstance(lb.state, dict) else {}
            backends = st.get("backends") or []
        down = [b.get("name") for b in backends if isinstance(b, dict) and b.get("state") == "down" and not b.get("drained")]
        if down:
            add("warning", "load_balancer", lb.id, lb.name,
                f"{len(down)} backend{'s' if len(down) != 1 else ''} down: " + ", ".join(str(n) for n in down), "/load-balancers")
    for zone_id, group in by_zone.items():
        zone = zones.get(zone_id)
        if not zone or not zone.vip:
            continue
        states = [lb.keepalived_state for lb in group if isinstance(lb.keepalived_state, dict)]
        if states and not any(ks.get("vip_owner") for ks in states):
            add("critical", "zone", zone.id, zone.name, f"no balancer holds the VIP {zone.vip}", "/load-balancers")
    if last_sync is not None and at - naive(last_sync) > timedelta(seconds=settings.sync_interval_seconds * 3):
        add("warning", "fleet", None, "reconcile loop", "the last reconcile pass is older than three intervals", "/")
    order = {"critical": 0, "warning": 1, "info": 2}
    items.sort(key=lambda i: (order.get(i["severity"], 9), i["name"]))
    return items


# --------------------------------------------------------------------------- #
# Prometheus exposition
# --------------------------------------------------------------------------- #
def token_ok(header: str | None) -> bool:
    if not settings.metrics_token or not header:
        return False
    scheme, _, value = header.partition(" ")
    return scheme.lower() == "bearer" and secrets.compare_digest(value.strip(), settings.metrics_token)


def _esc(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class _Exposition:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.seen: set[str] = set()

    def metric(self, name: str, help_: str, kind: str = "gauge") -> None:
        if name not in self.seen:
            self.seen.add(name)
            self.lines.append(f"# HELP {name} {help_}")
            self.lines.append(f"# TYPE {name} {kind}")

    def sample(self, name: str, labels: dict[str, Any], value: float | int | None) -> None:
        if value is None:
            return
        lab = ",".join(f'{k}="{_esc(v)}"' for k, v in labels.items() if v is not None)
        v = int(value) if isinstance(value, bool) else value
        self.lines.append(f"{name}{{{lab}}} {v}")

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


def prometheus(session: Session, *, last_sync: datetime | None) -> str:
    """The fleet as Prometheus gauges, from the newest samples and the rows."""
    p = "adguard_admin_"
    x = _Exposition()
    zones = {z.id: z.name for z in session.exec(select(Zone)).all()}
    agents = {a.id: a for a in session.exec(select(Agent)).all()}
    fresh_s = latest(session, KIND_SERVER, within=timedelta(seconds=settings.sync_interval_seconds * 5))
    fresh_a = latest(session, KIND_AGENT, within=timedelta(seconds=settings.sync_interval_seconds * 5))
    fresh_l = latest(session, KIND_BALANCER, within=timedelta(seconds=settings.sync_interval_seconds * 5))
    at = now_utc()

    servers = session.exec(select(Server)).all()
    x.metric(p + "server_up", "1 when the AdGuard server answered its last reconcile")
    x.metric(p + "server_in_sync", "1 when the server matches its desired configuration")
    x.metric(p + "server_update_available", "1 when AdGuard reports a newer release")
    x.metric(p + "server_queries_per_second", "DNS queries per second, from the last two samples")
    x.metric(p + "server_blocked_per_second", "blocked queries per second, from the last two samples")
    x.metric(p + "server_queries_window", "queries in AdGuard's own statistics window (24h by default)")
    x.metric(p + "server_blocked_window", "blocked queries in AdGuard's statistics window")
    x.metric(p + "server_processing_milliseconds", "average processing time AdGuard reports")
    x.metric(p + "server_sample_age_seconds", "age of the newest stored sample for the server")
    x.metric(p + "server_info", "static labels for the server", "gauge")
    for s in servers:
        labels = {"server": s.name, "zone": zones.get(s.zone_id)}
        x.sample(p + "server_up", labels, 1 if s.status == SyncStatus.online else 0)
        x.sample(p + "server_in_sync", labels, 1 if s.in_sync else 0)
        x.sample(p + "server_update_available", labels, 1 if s.update_available else 0)
        x.sample(p + "server_info", {**labels, "version": s.version or "", "enabled": "true" if s.enabled else "false"}, 1)
        row = fresh_s.get(s.id)
        if row:
            v = row.values
            x.sample(p + "server_queries_per_second", labels, v.get("qps"))
            x.sample(p + "server_blocked_per_second", labels, v.get("bps"))
            x.sample(p + "server_queries_window", labels, v.get("queries_24h"))
            x.sample(p + "server_blocked_window", labels, v.get("blocked_24h"))
            x.sample(p + "server_processing_milliseconds", labels, v.get("avg_ms"))
            x.sample(p + "server_sample_age_seconds", labels, round((at - naive(row.ts)).total_seconds(), 1))

    x.metric(p + "agent_up", "1 when the host agent answered its last reconcile")
    x.metric(p + "agent_load1", "1-minute load average on the host")
    x.metric(p + "agent_memory_used_ratio", "used memory as a fraction of total")
    x.metric(p + "agent_disk_used_ratio", "used space as a fraction of the fullest monitored disk")
    x.metric(p + "agent_services_down", "managed services present on the host but not running")
    x.metric(p + "agent_cert_expiry_timestamp_seconds", "when the agent certificate expires, as a Unix time")
    x.metric(p + "agent_info", "static labels for the host agent")
    for a in agents.values():
        labels = {"host": a.name, "zone": zones.get(a.zone_id)}
        x.sample(p + "agent_up", labels, 1 if a.status == SyncStatus.online else 0)
        x.sample(p + "agent_info", {**labels, "version": a.version or "", "arch": a.arch or "", "os": a.os or ""}, 1)
        if a.cert_not_after:
            x.sample(p + "agent_cert_expiry_timestamp_seconds", labels,
                     int(naive(a.cert_not_after).replace(tzinfo=timezone.utc).timestamp()))
        row = fresh_a.get(a.id)
        if row:
            v = row.values
            x.sample(p + "agent_load1", labels, v.get("load1"))
            x.sample(p + "agent_memory_used_ratio", labels, v.get("mem_used"))
            x.sample(p + "agent_disk_used_ratio", labels, v.get("disk_used"))
            x.sample(p + "agent_services_down", labels, v.get("services_down"))

    x.metric(p + "balancer_up", "1 when the balancer host answered its last reconcile")
    x.metric(p + "balancer_in_sync", "1 when the balancer matches its desired configuration")
    x.metric(p + "balancer_vip_owner", "1 when this balancer currently holds the zone VIP")
    x.metric(p + "balancer_director", "1 when this balancer schedules queries (ipvs: the owner; dnsdist: always)")
    x.metric(p + "balancer_backends_up", "backends the balancer considers up and not drained")
    x.metric(p + "balancer_backends_total", "backends the balancer knows")
    x.metric(p + "balancer_queries_per_second", "queries per second through the balancer, from the last two samples")
    x.metric(p + "balancer_cache_hit_ratio", "dnsdist cache hits as a fraction of lookups")
    x.metric(p + "balancer_backend_up", "1 when the balancer considers the backend up")
    x.metric(p + "balancer_backend_queries_per_second", "queries per second the balancer reports for the backend")
    for lb in session.exec(select(LoadBalancer)).all():
        labels = {"balancer": lb.name, "zone": zones.get(lb.zone_id), "mode": lb.mode.value,
                  "host": agents.get(lb.agent_id).name if agents.get(lb.agent_id) else None}
        x.sample(p + "balancer_up", labels, 1 if lb.status == SyncStatus.online else 0)
        x.sample(p + "balancer_in_sync", labels, 1 if lb.in_sync else 0)
        row = fresh_l.get(lb.id)
        if row:
            v = row.values
            x.sample(p + "balancer_vip_owner", labels, v.get("vip_owner"))
            x.sample(p + "balancer_director", labels, v.get("director", 1 if lb.mode == LbMode.dnsdist else None))
            x.sample(p + "balancer_backends_up", labels, v.get("backends_up"))
            x.sample(p + "balancer_backends_total", labels, v.get("backends_total"))
            x.sample(p + "balancer_queries_per_second", labels, v.get("qps"))
            x.sample(p + "balancer_cache_hit_ratio", labels, v.get("cache_hit"))
        if lb.mode == LbMode.ipvs:
            ks = lb.keepalived_state if isinstance(lb.keepalived_state, dict) else {}
            backends = (ks.get("ipvs") or {}).get("backends") or [] if isinstance(ks.get("ipvs"), dict) else []
            qps_key = "in_pps"
        else:
            st = lb.state if isinstance(lb.state, dict) else {}
            backends = st.get("backends") or []
            qps_key = "qps"
        for b in backends:
            if not isinstance(b, dict):
                continue
            bl = {**labels, "backend": b.get("name")}
            x.sample(p + "balancer_backend_up", bl, 1 if b.get("state") == "up" else 0)
            x.sample(p + "balancer_backend_queries_per_second", bl, b.get(qps_key))

    x.metric(p + "fleet_servers", "servers managed")
    x.metric(p + "fleet_servers_online", "servers online at the last reconcile")
    x.metric(p + "fleet_agents_online", "host agents online at the last reconcile")
    x.metric(p + "fleet_last_sync_timestamp_seconds", "when the last reconcile pass finished, as a Unix time")
    x.sample(p + "fleet_servers", {}, len(servers))
    x.sample(p + "fleet_servers_online", {}, sum(1 for s in servers if s.status == SyncStatus.online))
    x.sample(p + "fleet_agents_online", {}, sum(1 for a in agents.values() if a.status == SyncStatus.online))
    if last_sync:
        x.sample(p + "fleet_last_sync_timestamp_seconds", {},
                 int(naive(last_sync).replace(tzinfo=timezone.utc).timestamp()))
    return x.text()
