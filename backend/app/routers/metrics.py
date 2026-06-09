"""Aggregated traffic metrics across the fleet.

Fetches /control/stats from each selected, enabled server concurrently and
combines the numbers. Supports filtering by zone and/or a single server.
"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Query
from sqlmodel import Session, select

from ..adguard_client import AdGuardClient, AdGuardError
from ..certs import verify_for
from ..database import engine
from ..deps import CurrentUser
from ..models import Server
from ..security import decrypt_secret

router = APIRouter(prefix="/api/metrics", tags=["metrics"])


def _blocked(s: dict) -> int:
    return (
        s.get("num_blocked_filtering", 0)
        + s.get("num_replaced_safebrowsing", 0)
        + s.get("num_replaced_parental", 0)
        + s.get("num_replaced_safesearch", 0)
    )


def _merge_top(lists: list, limit: int = 10) -> list[dict]:
    """AdGuard top lists are [{'name': count}, ...]; sum counts across servers."""
    agg: dict[str, int] = {}
    for lst in lists:
        for item in lst or []:
            for key, value in item.items():
                agg[key] = agg.get(key, 0) + value
    top = sorted(agg.items(), key=lambda kv: kv[1], reverse=True)[:limit]
    return [{"name": k, "count": v} for k, v in top]


async def _fetch(srv: dict) -> dict:
    client = AdGuardClient(srv["url"], srv["username"], srv["password"], verify=verify_for(srv["tls_cert"]))
    try:
        return {"ok": True, "srv": srv, "stats": await client.stats()}
    except AdGuardError as exc:
        return {"ok": False, "srv": srv, "error": str(exc)}
    finally:
        await client.aclose()


@router.get("")
async def metrics(
    _: CurrentUser,
    zone_id: int | None = Query(default=None),
    server_id: int | None = Query(default=None),
):
    # Read everything we need inside the session, then fan out concurrently.
    with Session(engine) as session:
        stmt = select(Server).where(Server.enabled == True)  # noqa: E712
        if zone_id is not None:
            stmt = stmt.where(Server.zone_id == zone_id)
        if server_id is not None:
            stmt = stmt.where(Server.id == server_id)
        targets = [
            {
                "id": s.id, "name": s.name, "url": s.url, "username": s.username,
                "password": decrypt_secret(s.password_enc), "tls_cert": s.tls_cert,
            }
            for s in session.exec(stmt).all()
        ]

    results = await asyncio.gather(*[_fetch(t) for t in targets]) if targets else []

    per_server = []
    total_q = total_b = 0
    weighted_time = 0.0
    reporting = 0
    tops_q, tops_b, tops_c = [], [], []

    for r in results:
        srv = r["srv"]
        if not r["ok"]:
            per_server.append({"server_id": srv["id"], "name": srv["name"], "online": False, "error": r["error"]})
            continue
        s = r["stats"]
        reporting += 1
        q = s.get("num_dns_queries", 0)
        b = _blocked(s)
        avg = s.get("avg_processing_time", 0.0) or 0.0  # seconds
        total_q += q
        total_b += b
        weighted_time += avg * q
        tops_q.append(s.get("top_queried_domains"))
        tops_b.append(s.get("top_blocked_domains"))
        tops_c.append(s.get("top_clients"))
        per_server.append({
            "server_id": srv["id"], "name": srv["name"], "online": True,
            "num_dns_queries": q, "num_blocked": b,
            "blocked_pct": round(b / q * 100, 2) if q else 0,
            "avg_processing_ms": round(avg * 1000, 2),
        })

    totals = {
        "num_dns_queries": total_q,
        "num_blocked": total_b,
        "blocked_pct": round(total_b / total_q * 100, 2) if total_q else 0,
        "avg_processing_ms": round(weighted_time / total_q * 1000, 2) if total_q else 0,
    }
    return {
        "totals": totals,
        "servers": per_server,
        "reporting": reporting,
        "selected": len(targets),
        "top_queried": _merge_top(tops_q),
        "top_blocked": _merge_top(tops_b),
        "top_clients": _merge_top(tops_c),
    }
