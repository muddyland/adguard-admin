"""Talking to many AdGuard servers at once.

The dashboard and the Home Assistant compatibility layer need the same three
things: the set of servers a request applies to, a bounded concurrent fan-out
over them that one broken box cannot fail, and stat coercion that survives
whatever an AdGuard build happens to send.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from sqlmodel import Session, select

from .adguard_client import AdGuardClient
from .certs import verify_for
from .config import settings
from .database import engine
from .models import Server
from .security import decrypt_secret

logger = logging.getLogger("adguard_admin.fleet")


@dataclass(frozen=True)
class Target:
    """One server, detached from the ORM so a fan-out holds no DB connection."""

    id: int
    name: str
    url: str
    username: str | None
    password: str | None
    tls_cert: str | None


def load_targets(zone_id: int | None = None, server_id: int | None = None) -> list[Target]:
    """Enabled servers, optionally narrowed to a zone and/or a single server."""
    with Session(engine) as session:
        stmt = select(Server).where(Server.enabled == True)  # noqa: E712
        if zone_id is not None:
            stmt = stmt.where(Server.zone_id == zone_id)
        if server_id is not None:
            stmt = stmt.where(Server.id == server_id)
        return [
            Target(
                id=s.id,
                name=s.name,
                url=s.url,
                username=s.username,
                password=decrypt_secret(s.password_enc),
                tls_cert=s.tls_cert,
            )
            for s in session.exec(stmt.order_by(Server.name)).all()
        ]


@dataclass
class Outcome:
    """What one server answered, or why it didn't."""

    target: Target
    value: Any = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


Call = Callable[[AdGuardClient], Awaitable[Any]]


async def _call_one(target: Target, call: Call) -> Outcome:
    # Client construction can raise (a malformed pinned cert, a bad FERNET_KEY),
    # so it lives inside the try: one broken server must never fail the whole
    # request — that bug already cost the dashboard once.
    client = None
    try:
        client = AdGuardClient(
            target.url,
            target.username,
            target.password,
            timeout=settings.adguard_timeout_seconds,
            verify=verify_for(target.tls_cert),
        )
        return Outcome(target=target, value=await call(client))
    except Exception as exc:
        logger.info("fleet call failed for %s: %s", target.name, exc)
        return Outcome(target=target, error=str(exc) or exc.__class__.__name__)
    finally:
        if client is not None:
            await client.aclose()


async def fan_out(targets: list[Target], call: Call, *, limit: int | None = None) -> list[Outcome]:
    """Run `call(client)` against every target, at most `limit` at a time.

    Always returns one Outcome per target, in the order given, whether the call
    succeeded, failed or raised something the per-server guard didn't expect.
    """
    if not targets:
        return []
    semaphore = asyncio.Semaphore(max(1, limit or settings.sync_max_concurrency))

    async def _guarded(target: Target) -> Outcome:
        async with semaphore:
            return await _call_one(target, call)

    settled = await asyncio.gather(
        *(_guarded(t) for t in targets), return_exceptions=True
    )
    outcomes: list[Outcome] = []
    for target, item in zip(targets, settled):
        if isinstance(item, BaseException):
            logger.warning("fleet task for %s raised: %s", target.name, item)
            outcomes.append(Outcome(target=target, error=str(item) or item.__class__.__name__))
        else:
            outcomes.append(item)
    return outcomes


# --------------------------------------------------------------------------- #
# Stat coercion
# --------------------------------------------------------------------------- #
def as_number(value) -> float:
    """Coerce a stat to a number, tolerating whatever an AdGuard build sends."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0
    return value


def blocked_total(stats: dict) -> float:
    """Everything AdGuard counts as "blocked", the way its own dashboard does."""
    return (
        as_number(stats.get("num_blocked_filtering", 0))
        + as_number(stats.get("num_replaced_safebrowsing", 0))
        + as_number(stats.get("num_replaced_parental", 0))
        + as_number(stats.get("num_replaced_safesearch", 0))
    )
