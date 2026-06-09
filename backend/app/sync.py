"""Reconciliation engine.

The admin database is the source of truth. For each enabled server we compute
its *desired* set of DNS rewrites = (all enabled global records) + (all enabled
records in the server's zone). We then diff against what's actually on the
server and apply the difference. Servers that are offline are skipped and
retried on the next loop, so state converges automatically once they come back.
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlmodel import Session, select

from .adguard_client import AdGuardClient, AdGuardError, Rewrite
from .certs import verify_for
from .config import settings
from .database import engine
from .models import ConfigScope, DNSRecord, ForwardZone, RecordScope, Server, SyncStatus, Upstream
from .security import decrypt_secret

logger = logging.getLogger("adguard_admin.sync")


@dataclass
class ServerSyncResult:
    server_id: int
    server_name: str
    status: SyncStatus
    added: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    upstreams_changed: bool = False
    error: str | None = None
    version: str | None = None


def desired_rewrites_for_server(session: Session, server: Server) -> set[Rewrite]:
    """Global records + records scoped to this server's zone."""
    stmt = select(DNSRecord).where(DNSRecord.enabled == True)  # noqa: E712
    desired: set[Rewrite] = set()
    for rec in session.exec(stmt).all():
        if rec.scope == RecordScope.global_:
            desired.add(Rewrite(domain=rec.domain, answer=rec.answer))
        elif rec.scope == RecordScope.zone and rec.zone_id == server.zone_id and server.zone_id is not None:
            desired.add(Rewrite(domain=rec.domain, answer=rec.answer))
    return desired


def _scope_matches(item, server: Server) -> bool:
    if item.scope == ConfigScope.global_:
        return True
    if item.scope == ConfigScope.zone:
        return server.zone_id is not None and item.zone_id == server.zone_id
    if item.scope == ConfigScope.server:
        return item.server_id == server.id
    return False


def desired_upstreams_for_server(session: Session, server: Server) -> list[str]:
    """Build the AdGuard upstream_dns list: general upstreams + forward-zone entries.

    General entries are plain addresses; forward zones render to AdGuard's
    per-domain syntax, e.g. [/internal.lan/corp.lan/]10.0.0.53.
    """
    entries: list[str] = []

    for u in session.exec(select(Upstream).where(Upstream.enabled == True)).all():  # noqa: E712
        if _scope_matches(u, server) and u.address.strip():
            entries.append(u.address.strip())

    for fz in session.exec(select(ForwardZone).where(ForwardZone.enabled == True)).all():  # noqa: E712
        if not _scope_matches(fz, server):
            continue
        domains = [d for d in re.split(r"[,\s]+", fz.domains.strip()) if d]
        upstreams = [a for a in re.split(r"[,\s\n]+", fz.upstreams.strip()) if a]
        if not domains or not upstreams:
            continue
        prefix = "[/" + "/".join(domains) + "/]"
        for addr in upstreams:
            entries.append(prefix + addr)

    # De-dupe while preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for e in entries:
        if e not in seen:
            seen.add(e)
            out.append(e)
    return out


async def reconcile_server(session: Session, server: Server, *, dry_run: bool = False) -> ServerSyncResult:
    result = ServerSyncResult(server_id=server.id, server_name=server.name, status=SyncStatus.unknown)
    desired = desired_rewrites_for_server(session, server)
    password = decrypt_secret(server.password_enc)

    client = AdGuardClient(server.url, server.username, password, verify=verify_for(server.tls_cert))
    try:
        status = await client.status()
        result.version = status.get("version")
        server.version = result.version
        server.last_seen = datetime.now(timezone.utc)

        current = set(await client.list_rewrites())
        desired_keys = {r.key() for r in desired}
        current_keys = {r.key() for r in current}

        to_add = [r for r in desired if r.key() not in current_keys]
        # Only prune records we'd otherwise manage, unless prune is enabled.
        to_delete = (
            [r for r in current if r.key() not in desired_keys]
            if server.prune
            else []
        )

        if not dry_run:
            for r in to_add:
                await client.add_rewrite(r)
            for r in to_delete:
                await client.delete_rewrite(r)

        result.added = [f"{r.domain} -> {r.answer}" for r in to_add]
        result.deleted = [f"{r.domain} -> {r.answer}" for r in to_delete]
        result.status = SyncStatus.online

        # Optionally reconcile upstream DNS config (opt-in per server). We only
        # push when there's a non-empty desired set, so we never blank out a
        # server's upstreams just because nothing is defined here.
        upstreams_in_sync = True
        if server.manage_upstreams:
            desired_up = desired_upstreams_for_server(session, server)
            if desired_up:
                current_up = (await client.dns_info()).get("upstream_dns") or []
                if set(current_up) != set(desired_up):
                    upstreams_in_sync = False
                    if not dry_run:
                        await client.set_upstreams(desired_up)
        result.upstreams_changed = not upstreams_in_sync

        server.status = SyncStatus.online
        server.in_sync = not to_add and not to_delete and upstreams_in_sync
        server.last_error = None
        if not dry_run:
            server.last_synced = datetime.now(timezone.utc)

    except AdGuardError as exc:
        logger.warning("reconcile failed for %s: %s", server.name, exc)
        result.status = SyncStatus.offline
        result.error = str(exc)
        server.status = SyncStatus.offline
        server.in_sync = False
        server.last_error = str(exc)
    except Exception as exc:  # defensive: never let one server kill the loop
        logger.exception("unexpected error reconciling %s", server.name)
        result.status = SyncStatus.error
        result.error = str(exc)
        server.status = SyncStatus.error
        server.in_sync = False
        server.last_error = str(exc)
    finally:
        await client.aclose()

    session.add(server)
    session.commit()
    session.refresh(server)
    return result


async def reconcile_all(*, dry_run: bool = False, only_server_id: int | None = None) -> list[ServerSyncResult]:
    with Session(engine) as session:
        stmt = select(Server).where(Server.enabled == True)  # noqa: E712
        if only_server_id is not None:
            stmt = stmt.where(Server.id == only_server_id)
        servers = session.exec(stmt).all()
        results: list[ServerSyncResult] = []
        for server in servers:
            results.append(await reconcile_server(session, server, dry_run=dry_run))
        return results


class SyncManager:
    """Owns the background reconcile loop."""

    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self.last_run: datetime | None = None
        self.last_results: list[ServerSyncResult] = []

    async def _loop(self) -> None:
        logger.info("sync loop started (interval=%ss)", settings.sync_interval_seconds)
        while not self._stop.is_set():
            try:
                self.last_results = await reconcile_all()
                self.last_run = datetime.now(timezone.utc)
            except Exception:
                logger.exception("reconcile_all crashed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=settings.sync_interval_seconds)
            except asyncio.TimeoutError:
                pass

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            await self._task


sync_manager = SyncManager()
