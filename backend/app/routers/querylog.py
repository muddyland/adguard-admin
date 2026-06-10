"""Combined query log across the fleet.

Fetches /control/querylog from each selected, enabled server concurrently, tags
each entry with its server, merges and sorts by time. Filtering (search,
response_status) is pushed down to each AdGuard instance; zone/server narrow the
set of servers queried.
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

router = APIRouter(prefix="/api/querylog", tags=["querylog"])


def _answer(entry: dict) -> str:
    return ", ".join(a.get("value", "") for a in (entry.get("answer") or []) if a.get("value"))


async def _fetch(srv: dict, params: dict) -> tuple[dict, list]:
    client = AdGuardClient(srv["url"], srv["username"], srv["password"], verify=verify_for(srv["tls_cert"]))
    try:
        data = await client.query_log(params)
        return srv, (data.get("data") or [])
    except AdGuardError:
        return srv, []
    finally:
        await client.aclose()


@router.get("")
async def query_log(
    _: CurrentUser,
    zone_id: int | None = Query(default=None),
    server_id: int | None = Query(default=None),
    search: str | None = Query(default=None),
    response_status: str = Query(default="all"),
    limit: int = Query(default=100, ge=1, le=500),
):
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

    params: dict = {"limit": limit}
    if search:
        params["search"] = search
    if response_status and response_status != "all":
        params["response_status"] = response_status

    results = await asyncio.gather(*[_fetch(t, params) for t in targets]) if targets else []

    entries = []
    for srv, data in results:
        for e in data:
            reason = e.get("reason") or ""
            q = e.get("question") or {}
            entries.append({
                "server_id": srv["id"],
                "server": srv["name"],
                "time": e.get("time"),
                "client": e.get("client"),
                "question": q.get("host"),
                "type": q.get("type"),
                "answer": _answer(e),
                "reason": reason,
                "blocked": reason.startswith("Filtered"),
                "elapsed_ms": e.get("elapsedMs"),
                "upstream": e.get("upstream"),
                "cached": e.get("cached", False),
            })

    entries.sort(key=lambda x: x["time"] or "", reverse=True)
    return {"entries": entries[:limit], "servers_queried": len(targets), "total_fetched": len(entries)}
