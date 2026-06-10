"""Reconciliation engine.

The admin database is the source of truth. For each enabled server we compute
its *desired* set of DNS rewrites = (all enabled global records) + (all enabled
records in the server's zone). We then diff against what's actually on the
server and apply the difference. Servers that are offline are skipped and
retried on the next loop, so state converges automatically once they come back.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlmodel import Session, select

from .adguard_client import AdGuardClient, AdGuardError, Rewrite
from .certs import verify_for
from .config import settings
from .database import engine
from .models import (
    ConfigScope,
    DnsServerKind,
    DNSRecord,
    ForwardZone,
    RecordScope,
    Server,
    SyncStatus,
    Upstream,
)
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
        elif rec.scope == RecordScope.zone and server.zone_id is not None and server.zone_id in (rec.zone_ids or []):
            desired.add(Rewrite(domain=rec.domain, answer=rec.answer))
    return desired


def _scope_matches(item, server: Server) -> bool:
    if item.scope == ConfigScope.global_:
        return True
    if item.scope == ConfigScope.zone:
        return server.zone_id is not None and server.zone_id in (item.zone_ids or [])
    if item.scope == ConfigScope.server:
        return item.server_id == server.id
    return False


def _dedupe(entries: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for e in entries:
        if e and e not in seen:
            seen.add(e)
            out.append(e)
    return out


def _addresses_of_kind(session: Session, server: Server, kind: DnsServerKind) -> list[str]:
    """Plain matching addresses for a given DNS server kind (no forward zones)."""
    rows = session.exec(
        select(Upstream).where(Upstream.enabled == True, Upstream.kind == kind)  # noqa: E712
    ).all()
    return _dedupe([u.address.strip() for u in rows if _scope_matches(u, server) and u.address.strip()])


def desired_upstreams_for_server(session: Session, server: Server) -> list[str]:
    """Build the AdGuard upstream_dns list: general upstreams + forward-zone entries.

    General entries are plain addresses; forward zones render to AdGuard's
    per-domain syntax, e.g. [/internal.lan/corp.lan/]10.0.0.53.
    """
    entries: list[str] = _addresses_of_kind(session, server, DnsServerKind.upstream)

    for fz in session.exec(select(ForwardZone).where(ForwardZone.enabled == True)).all():  # noqa: E712
        if not _scope_matches(fz, server):
            continue
        domains = [d for d in re.split(r"[,\s]+", fz.domains.strip()) if d]
        upstreams = [a for a in re.split(r"[,\s]+", fz.upstreams.strip()) if a]
        if not domains or not upstreams:
            continue
        # AdGuard syntax: one entry, space-separated upstreams:
        #   [/domain1/domain2/]server1 server2 server3
        entries.append("[/" + "/".join(domains) + "/]" + " ".join(upstreams))

    return _dedupe(entries)


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

        # Update-available check (best-effort; uses AdGuard's cached result).
        try:
            vinfo = await client.version_check()
            new_version = (vinfo.get("new_version") or "").strip()
            server.latest_version = new_version or None
            server.update_available = bool(new_version) and new_version != (result.version or "")
        except AdGuardError:
            pass  # update checks may be disabled; don't fail the sync

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

        # Optionally reconcile DNS config (opt-in per server): upstream_dns,
        # bootstrap_dns, fallback_dns and local_ptr_upstreams (private resolvers).
        # We only push a list when its desired set is non-empty, so we never blank
        # out a server's config just because nothing is defined here.
        upstreams_in_sync = True
        if server.manage_upstreams:
            info = await client.dns_info()
            desired_lists = {
                "upstream_dns": desired_upstreams_for_server(session, server),
                "bootstrap_dns": _addresses_of_kind(session, server, DnsServerKind.bootstrap),
                "fallback_dns": _addresses_of_kind(session, server, DnsServerKind.fallback),
                "local_ptr_upstreams": _addresses_of_kind(session, server, DnsServerKind.private),
            }
            payload: dict = {}
            for key, desired_vals in desired_lists.items():
                if desired_vals and set(info.get(key) or []) != set(desired_vals):
                    payload[key] = desired_vals
            # Ensure private resolvers actually take effect when we set them.
            if "local_ptr_upstreams" in payload:
                payload["use_private_ptr_resolvers"] = True
            if payload:
                upstreams_in_sync = False
                if not dry_run:
                    await client.set_dns_config(payload)
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


def _host_from_url(url: str) -> str | None:
    try:
        u = url if "://" in url else "//" + url
        return urllib.parse.urlparse(u).hostname
    except ValueError:
        return None


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def reconcile_hostname_records() -> None:
    """Auto-maintain global rewrites mapping each server's hostname URL to its IP,
    so every server can resolve the others by name. Servers given by bare IP are
    skipped. User-defined records of the same name are left untouched. Blocking
    DNS lookups here are fine — this runs in a worker thread.
    """
    with Session(engine) as session:
        servers = session.exec(select(Server)).all()
        managed_hostnames: set[str] = set()
        resolved: dict[str, str] = {}
        for srv in servers:
            host = _host_from_url(srv.url)
            if not host or _is_ip(host):
                continue
            host = host.lower()
            managed_hostnames.add(host)
            try:
                resolved[host] = socket.gethostbyname(host)
            except OSError:
                logger.debug("could not resolve server hostname %s", host)

        autos = {r.domain: r for r in session.exec(
            select(DNSRecord).where(DNSRecord.managed == True)  # noqa: E712
        ).all()}
        user_global = {r.domain for r in session.exec(
            select(DNSRecord).where(DNSRecord.managed == False, DNSRecord.scope == RecordScope.global_)  # noqa: E712
        ).all()}

        changed = False
        for host, ip in resolved.items():
            if host in user_global:
                continue  # respect an explicit user record for this name
            rec = autos.get(host)
            if rec is None:
                session.add(DNSRecord(
                    domain=host, answer=ip, scope=RecordScope.global_, zone_ids=[],
                    enabled=True, managed=True, description="Auto-registered from servers list",
                ))
                changed = True
            elif rec.answer != ip:
                rec.answer = ip
                rec.updated_at = datetime.now(timezone.utc)
                session.add(rec)
                changed = True

        # Drop auto records whose hostname is no longer a server (or became an IP).
        for domain, rec in autos.items():
            if domain not in managed_hostnames:
                session.delete(rec)
                changed = True

        if changed:
            session.commit()


async def reconcile_all(*, dry_run: bool = False, only_server_id: int | None = None) -> list[ServerSyncResult]:
    # Refresh server-hostname records first so they're part of this cycle's
    # desired state. Run in a thread — gethostbyname blocks.
    if not dry_run:
        try:
            await asyncio.to_thread(reconcile_hostname_records)
        except Exception:
            logger.exception("hostname record reconcile failed")

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
