"""Combined query log across the fleet.

Fetches /control/querylog from each selected, enabled server concurrently, tags
each entry with its server, merges and sorts by time. Filtering (search,
response_status) is pushed down to each AdGuard instance; zone/server narrow the
set of servers queried.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Query
from sqlmodel import Session, select

from ..adguard_client import AdGuardClient, AdGuardError
from ..certs import verify_for
from ..config import settings
from ..database import engine
from ..deps import CurrentUser
from ..models import Server
from ..security import decrypt_secret

router = APIRouter(prefix="/api/querylog", tags=["querylog"])

logger = logging.getLogger("adguard_admin.querylog")

# Sorts before every real timestamp, for entries whose time we can't parse.
_EPOCH = datetime.min.replace(tzinfo=timezone.utc)


def _answer(entry: dict) -> str:
    return ", ".join(a.get("value", "") for a in (entry.get("answer") or []) if a.get("value"))


def _parse_time(value) -> datetime:
    """Parse an AdGuard RFC 3339 timestamp to an aware datetime.

    Entries are merged from several servers, so sorting the raw strings was only
    correct while every server emitted the same format and UTC offset. Compare
    real instants instead.
    """
    if not isinstance(value, str) or not value:
        return _EPOCH
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return _EPOCH
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


async def _fetch(srv: dict, params: dict) -> tuple[dict, list]:
    # Client construction can raise (bad pinned cert / bad FERNET_KEY); keep it
    # inside the try so one broken server can't 500 the whole query log.
    client = None
    try:
        client = AdGuardClient(
            srv["url"], srv["username"], srv["password"],
            timeout=settings.adguard_timeout_seconds,
            verify=verify_for(srv["tls_cert"]),
        )
        data = await client.query_log(params)
        return srv, (data.get("data") or [])
    except AdGuardError:
        return srv, []
    except Exception as exc:
        logger.warning("query log fetch failed for %s: %s", srv.get("name"), exc)
        return srv, []
    finally:
        if client is not None:
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

    settled = (
        await asyncio.gather(*[_fetch(t, params) for t in targets], return_exceptions=True)
        if targets else []
    )
    results = []
    for target, item in zip(targets, settled):
        if isinstance(item, BaseException):
            logger.warning("query log task for %s raised: %s", target.get("name"), item)
            results.append((target, []))
        else:
            results.append(item)

    entries = []
    for srv, data in results:
        for e in data:
            if not isinstance(e, dict):
                continue
            reason = e.get("reason") or ""
            q = e.get("question") or {}
            # AdGuard serializes the queried domain under "name" (older builds /
            # docs used "host"); prefer the unicode form for IDNs when present.
            host = q.get("unicode_name") or q.get("name") or q.get("host")
            client_ip = e.get("client") or ""
            # Prefer a friendly client name (rDNS / configured client) over the bare IP.
            client_name = (e.get("client_info") or {}).get("name") or e.get("client_id") or ""
            entries.append({
                "server_id": srv["id"],
                "server": srv["name"],
                "time": e.get("time"),
                "client": client_ip,
                "client_name": client_name,
                "question": host,
                "type": q.get("type"),
                "answer": _answer(e),
                "reason": reason,
                "blocked": reason.startswith("Filtered"),
                "elapsed_ms": e.get("elapsedMs"),
                "upstream": e.get("upstream"),
                "cached": e.get("cached", False),
            })

    entries.sort(key=lambda x: _parse_time(x["time"]), reverse=True)
    return {"entries": entries[:limit], "servers_queried": len(targets), "total_fetched": len(entries)}
