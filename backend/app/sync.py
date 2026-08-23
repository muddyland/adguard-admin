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
from datetime import datetime, timedelta, timezone

from sqlmodel import Session, select

from .adguard_client import AdGuardClient, AdGuardError, Rewrite
from .certs import verify_for
from .config import settings
from .database import engine
from .models import (
    BlockedService,
    ConfigScope,
    DnsServerKind,
    DNSRecord,
    FilterKind,
    FilterList,
    ForwardZone,
    RecordScope,
    Server,
    SyncStatus,
    Upstream,
)
from .security import decrypt_secret

logger = logging.getLogger("adguard_admin.sync")


@dataclass(frozen=True)
class FilterSpec:
    """The parts of a FilterList the apply phase needs, detached from the ORM."""
    name: str
    url: str
    enabled: bool


@dataclass
class ServerPlan:
    """Everything reconciliation needs, read in one short transaction.

    The apply phase does only network I/O against this snapshot. Previously it
    queried the database *between* HTTP calls, which meant a pooled SQLite
    connection stayed checked out for the whole of a server's round-trips — with
    several slow servers in flight the pool ran dry and API requests stalled.
    """
    server_id: int
    name: str
    url: str
    username: str | None
    password_enc: str | None
    tls_cert: str | None
    prune: bool
    manage_upstreams: bool
    manage_filtering: bool
    rewrites: set[Rewrite] = field(default_factory=set)
    upstream_lists: dict[str, list[str]] = field(default_factory=dict)
    filters: dict[str, list[FilterSpec]] = field(default_factory=dict)
    blocked_services: list[str] = field(default_factory=list)


@dataclass
class ServerUpdates:
    """Columns the apply phase decided to write back."""
    status: SyncStatus = SyncStatus.unknown
    in_sync: bool = False
    version: str | None = None
    latest_version: str | None = None
    update_available: bool = False
    # Whether AdGuard says it can replace its own binary (false inside Docker).
    can_autoupdate: bool = False
    update_check_disabled: bool = False
    last_error: str | None = None
    last_seen: datetime | None = None
    last_synced: datetime | None = None
    cooldown_until: datetime | None = None
    clear_cooldown: bool = False


@dataclass
class ServerSyncResult:
    server_id: int
    server_name: str
    status: SyncStatus
    added: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    upstreams_changed: bool = False
    filtering_changed: bool = False
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


def _filters_for_server(session: Session, server: Server, kind: FilterKind) -> list[FilterList]:
    """Filter lists of one kind (blocklist/allowlist) that apply to this server."""
    rows = session.exec(select(FilterList).where(FilterList.kind == kind)).all()
    return [f for f in rows if _scope_matches(f, server) and f.url.strip()]


def desired_blocked_services_for_server(session: Session, server: Server) -> list[str]:
    """Sorted set of service ids that should be blocked on this server."""
    rows = session.exec(
        select(BlockedService).where(BlockedService.enabled == True)  # noqa: E712
    ).all()
    return sorted({r.service_id.strip() for r in rows if _scope_matches(r, server) and r.service_id.strip()})


# AdGuard's filtering/status splits lists into these two response keys.
_FILTER_KINDS = [
    (FilterKind.blocklist, False, "filters"),
    (FilterKind.allowlist, True, "whitelist_filters"),
]


def build_plan(session: Session, server: Server) -> ServerPlan:
    """Snapshot everything the apply phase needs, in one short read.

    Deliberately eager: the alternative is querying between HTTP calls, which
    keeps a pooled connection checked out for the whole exchange.
    """
    plan = ServerPlan(
        server_id=server.id,
        name=server.name,
        url=server.url,
        username=server.username,
        password_enc=server.password_enc,
        tls_cert=server.tls_cert,
        prune=server.prune,
        manage_upstreams=server.manage_upstreams,
        manage_filtering=server.manage_filtering,
        rewrites=desired_rewrites_for_server(session, server),
    )

    if server.manage_upstreams:
        plan.upstream_lists = {
            "upstream_dns": desired_upstreams_for_server(session, server),
            "bootstrap_dns": _addresses_of_kind(session, server, DnsServerKind.bootstrap),
            "fallback_dns": _addresses_of_kind(session, server, DnsServerKind.fallback),
            "local_ptr_upstreams": _addresses_of_kind(session, server, DnsServerKind.private),
        }

    if server.manage_filtering:
        plan.filters = {
            key: [
                FilterSpec(name=f.name, url=f.url, enabled=f.enabled)
                for f in _filters_for_server(session, server, kind)
            ]
            for kind, _whitelist, key in _FILTER_KINDS
        }
        plan.blocked_services = desired_blocked_services_for_server(session, server)

    return plan


def apply_updates(session: Session, server_id: int, updates: ServerUpdates) -> None:
    """Write the apply phase's decisions back, in its own short transaction."""
    server = session.get(Server, server_id)
    if server is None:  # deleted while we were talking to it
        return
    server.status = updates.status
    server.in_sync = updates.in_sync
    server.last_error = updates.last_error
    if updates.version is not None:
        server.version = updates.version
    if updates.latest_version is not None or updates.status == SyncStatus.online:
        server.latest_version = updates.latest_version
        server.update_available = updates.update_available
        server.can_autoupdate = updates.can_autoupdate
        server.update_check_disabled = updates.update_check_disabled
    if updates.last_seen is not None:
        server.last_seen = updates.last_seen
    if updates.last_synced is not None:
        server.last_synced = updates.last_synced
    if updates.clear_cooldown:
        server.cooldown_until = None
    elif updates.cooldown_until is not None:
        server.cooldown_until = updates.cooldown_until
    session.add(server)
    session.commit()


async def _reconcile_filtering(plan: ServerPlan, client: AdGuardClient, *, dry_run: bool) -> bool:
    """Apply blocklists, allowlists and blocked services. Returns True if anything
    changed (or would change, in dry-run). Removals only happen when prune is on.

    Reads nothing from the database — everything comes from `plan`.
    """
    changed = False
    status = await client.filtering_status()

    desired_block_enabled = 0
    for kind, whitelist, key in _FILTER_KINDS:
        desired = plan.filters.get(key, [])
        if kind == FilterKind.blocklist:
            desired_block_enabled = sum(1 for f in desired if f.enabled)
        current = {(it.get("url") or "").strip(): it for it in (status.get(key) or []) if it.get("url")}
        desired_urls: set[str] = set()
        for f in desired:
            url = f.url.strip()
            desired_urls.add(url)
            cur = current.get(url)
            if cur is None:
                changed = True
                if not dry_run:
                    await client.filtering_add_url(f.name, url, whitelist)
                    # add_url always adds enabled; disable afterwards if needed.
                    if not f.enabled:
                        await client.filtering_set_url(url, {"enabled": False, "name": f.name, "url": url}, whitelist)
            elif bool(cur.get("enabled")) != f.enabled or (cur.get("name") or "") != f.name:
                changed = True
                if not dry_run:
                    await client.filtering_set_url(url, {"enabled": f.enabled, "name": f.name, "url": url}, whitelist)
        if plan.prune:
            for url in current:
                if url and url not in desired_urls:
                    changed = True
                    if not dry_run:
                        await client.filtering_remove_url(url, whitelist)

    # Make sure the filtering engine itself is on when we manage blocklists.
    if desired_block_enabled and not status.get("enabled"):
        changed = True
        if not dry_run:
            await client.filtering_config(True, int(status.get("interval") or 24))

    # Blocked services. Only act when we have a managed set, so we never wipe a
    # server's services just because none are defined here (mirrors upstreams).
    desired_ids = plan.blocked_services
    if desired_ids:
        try:
            cur = await client.blocked_services_get()
            cur_ids = set(cur.get("ids") or [])
            target = set(desired_ids) if plan.prune else (cur_ids | set(desired_ids))
            if target != cur_ids:
                changed = True
                if not dry_run:
                    await client.blocked_services_update(sorted(target), cur.get("schedule"))
        except AdGuardError as exc:
            logger.debug("blocked services not reconciled for %s: %s", plan.name, exc)

    return changed


async def apply_plan(plan: ServerPlan, *, dry_run: bool = False) -> tuple[ServerSyncResult, ServerUpdates]:
    """Talk to one AdGuard instance. Performs no database access at all.

    Everything it needs is in `plan`; everything it decides comes back in
    ServerUpdates for the caller to persist in a separate short transaction.
    """
    result = ServerSyncResult(
        server_id=plan.server_id, server_name=plan.name, status=SyncStatus.unknown
    )
    updates = ServerUpdates()

    # Building the client can itself fail — decrypt_secret raises on a malformed
    # FERNET_KEY and verify_for raises ssl.SSLError on an unparseable pinned
    # cert. Both used to happen outside the try, so a single bad server aborted
    # the whole cycle and every server after it silently stopped reconciling.
    try:
        password = decrypt_secret(plan.password_enc)
        client = AdGuardClient(
            plan.url, plan.username, password,
            timeout=settings.adguard_timeout_seconds,
            verify=verify_for(plan.tls_cert),
        )
    except Exception as exc:
        logger.exception("could not build a client for %s", plan.name)
        result.status = SyncStatus.error
        result.error = str(exc)
        updates.status = SyncStatus.error
        updates.in_sync = False
        updates.last_error = f"Server configuration error: {exc}"
        return result, updates

    try:
        status = await client.status()
        result.version = status.get("version")
        updates.version = result.version
        updates.last_seen = datetime.now(timezone.utc)

        # Update-available check (best-effort; uses AdGuard's cached result).
        try:
            vinfo = await client.version_check()
            new_version = (vinfo.get("new_version") or "").strip()
            updates.latest_version = new_version or None
            updates.update_available = bool(new_version) and new_version != (result.version or "")
            updates.can_autoupdate = bool(vinfo.get("can_autoupdate"))
            # AdGuard answers {"disabled": true} when its update check is off; it
            # then never reports a new release, which is not the same as being
            # current. Record it so the UI can say which one it is.
            updates.update_check_disabled = bool(vinfo.get("disabled"))
        except AdGuardError:
            pass  # update checks may be disabled; don't fail the sync

        current = set(await client.list_rewrites())
        desired_keys = {r.key() for r in plan.rewrites}
        current_keys = {r.key() for r in current}

        to_add = [r for r in plan.rewrites if r.key() not in current_keys]
        # Only prune records we'd otherwise manage, unless prune is enabled.
        to_delete = (
            [r for r in current if r.key() not in desired_keys]
            if plan.prune
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
        if plan.manage_upstreams:
            info = await client.dns_info()
            payload: dict = {}
            for key, desired_vals in plan.upstream_lists.items():
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

        # Optionally reconcile filtering (opt-in per server): blocklists,
        # allowlists and blocked services.
        filtering_in_sync = True
        if plan.manage_filtering:
            filtering_changed = await _reconcile_filtering(plan, client, dry_run=dry_run)
            filtering_in_sync = not filtering_changed
        result.filtering_changed = not filtering_in_sync

        updates.status = SyncStatus.online
        updates.in_sync = not to_add and not to_delete and upstreams_in_sync and filtering_in_sync
        updates.last_error = None
        updates.clear_cooldown = True  # healthy again
        if not dry_run:
            updates.last_synced = datetime.now(timezone.utc)

    except AdGuardError as exc:
        logger.warning("reconcile failed for %s: %s", plan.name, exc)
        result.status = SyncStatus.error if exc.status_code in (401, 403, 429) else SyncStatus.offline
        result.error = str(exc)
        updates.in_sync = False
        if exc.status_code in (401, 403, 429):
            # Auth rejected / rate-limited: back off so we don't deepen the lockout.
            secs = exc.retry_after or (900 if exc.status_code == 429 else 300)
            updates.cooldown_until = datetime.now(timezone.utc) + timedelta(seconds=secs)
            updates.status = SyncStatus.error
            if exc.status_code == 429:
                updates.last_error = f"Auth rate-limited by AdGuard (429); backing off ~{secs // 60}m. Check the server's credentials."
            else:
                updates.last_error = f"Authentication failed (HTTP {exc.status_code}); retrying in ~{secs // 60}m. Check the server's credentials."
        else:
            updates.status = SyncStatus.offline
            updates.last_error = str(exc)
    except Exception as exc:  # defensive: never let one server kill the loop
        logger.exception("unexpected error reconciling %s", plan.name)
        result.status = SyncStatus.error
        result.error = str(exc)
        updates.status = SyncStatus.error
        updates.in_sync = False
        updates.last_error = str(exc)
    finally:
        await client.aclose()

    return result, updates


async def reconcile_server(session: Session, server: Server, *, dry_run: bool = False) -> ServerSyncResult:
    """Reconcile one server: snapshot -> network -> persist.

    The session's connection is released back to the pool before any network
    I/O and only re-acquired to write the outcome, so a slow or unreachable
    server no longer ties up a database connection for the whole exchange.
    """
    plan = build_plan(session, server)
    server_id = plan.server_id
    # Ends the read transaction, returning the connection to the pool.
    session.commit()

    result, updates = await apply_plan(plan, dry_run=dry_run)

    apply_updates(session, server_id, updates)
    if server in session:
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


def _due_servers(force: bool, only_server_id: int | None) -> list[int]:
    """Ids of enabled servers that are due this cycle. Read in its own short
    session so we don't hold a connection open across the network I/O below."""
    now = datetime.now(timezone.utc)
    with Session(engine) as session:
        stmt = select(Server).where(Server.enabled == True)  # noqa: E712
        if only_server_id is not None:
            stmt = stmt.where(Server.id == only_server_id)
        due: list[int] = []
        for server in session.exec(stmt).all():
            # Honor an auth/rate-limit cooldown (unless this is a forced/manual run).
            if not force and server.cooldown_until:
                cu = server.cooldown_until
                if cu.tzinfo is None:
                    cu = cu.replace(tzinfo=timezone.utc)
                if cu > now:
                    continue
            due.append(server.id)
        return due


# One lock per server. This is the only mutual exclusion reconciliation actually
# needs: two concurrent passes over the *same* server would compute the same diff
# and both apply it. A single global lock also prevented that, but it made a
# manual "Sync now" queue behind the entire in-flight fleet cycle, so the request
# hung for as long as the slowest server's timeouts took.
_server_locks: dict[int, asyncio.Lock] = {}


def lock_for(server_id: int) -> asyncio.Lock:
    """The mutual-exclusion lock for one server.

    Shared with the auto-updater (app.updater): an upgrade restarts AdGuard
    Home, so a reconcile pass must not be talking to the same box at the time.
    """
    lock = _server_locks.get(server_id)
    if lock is None:
        lock = _server_locks.setdefault(server_id, asyncio.Lock())
    return lock



async def _reconcile_one(server_id: int, *, dry_run: bool) -> ServerSyncResult | None:
    """Reconcile a single server, never raising.

    Skips the server if another pass is already mid-flight for it, rather than
    waiting: the caller is either the periodic loop (which will come back around
    anyway) or a manual trigger (which should answer promptly).
    """
    lock = lock_for(server_id)
    if lock.locked():
        logger.info("server id=%s is already reconciling; skipping this pass", server_id)
        return ServerSyncResult(
            server_id=server_id,
            server_name=f"server #{server_id}",
            status=SyncStatus.unknown,
            error="A sync for this server is already in progress.",
        )

    async with lock:
        try:
            # The session is deliberately NOT held across the HTTP calls below;
            # see reconcile_server. Holding one checked a pooled SQLite
            # connection out for the full duration of every server's network
            # round-trips, which starved API requests once a few servers were slow.
            with Session(engine) as session:
                server = session.get(Server, server_id)
                if server is None:  # deleted mid-cycle
                    return None
                return await reconcile_server(session, server, dry_run=dry_run)
        except Exception as exc:
            # Last line of defence. One server must never take down the cycle.
            logger.exception("reconcile of server id=%s failed outright", server_id)
            return ServerSyncResult(
                server_id=server_id,
                server_name=f"server #{server_id}",
                status=SyncStatus.error,
                error=str(exc),
            )


async def reconcile_all(
    *, dry_run: bool = False, only_server_id: int | None = None, force: bool = False
) -> list[ServerSyncResult]:
    # Refresh server-hostname records first so they're part of this cycle's
    # desired state. Run in a thread — gethostbyname blocks.
    if not dry_run:
        try:
            await asyncio.to_thread(reconcile_hostname_records)
        except Exception:
            logger.exception("hostname record reconcile failed")

    server_ids = await asyncio.to_thread(_due_servers, force, only_server_id)
    if not server_ids:
        return []

    # Bounded fan-out. Strictly sequential reconciliation could not finish a
    # cycle within sync_interval_seconds once a handful of servers were slow or
    # unreachable (each burns the full per-request timeout).
    limit = max(1, settings.sync_max_concurrency)
    semaphore = asyncio.Semaphore(limit)

    async def _guarded(server_id: int) -> ServerSyncResult | None:
        async with semaphore:
            return await _reconcile_one(server_id, dry_run=dry_run)

    settled = await asyncio.gather(
        *(_guarded(sid) for sid in server_ids), return_exceptions=True
    )

    results: list[ServerSyncResult] = []
    for server_id, item in zip(server_ids, settled):
        if isinstance(item, BaseException):
            logger.exception(
                "reconcile task for server id=%s raised", server_id, exc_info=item
            )
            results.append(ServerSyncResult(
                server_id=server_id, server_name=f"server #{server_id}",
                status=SyncStatus.error, error=str(item),
            ))
        elif item is not None:
            results.append(item)
    return results


class SyncManager:
    """Owns the background reconcile loop."""

    # How long to wait for an in-flight cycle during shutdown before cancelling.
    SHUTDOWN_GRACE_SECONDS = 15.0

    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        # Guards the *periodic* cycle only, and is never waited on: if a cycle
        # overruns the interval we skip the next tick rather than queueing more.
        # Correctness against concurrent passes over the same server is handled
        # by the per-server locks in _reconcile_one, so callers never block on
        # the whole fleet.
        self._cycle_lock = asyncio.Lock()
        self.last_run: datetime | None = None
        self.last_results: list[ServerSyncResult] = []

    @property
    def cycle_in_progress(self) -> bool:
        return self._cycle_lock.locked()

    async def run_once(
        self, *, dry_run: bool = False, only_server_id: int | None = None, force: bool = False
    ) -> list[ServerSyncResult]:
        """Run a reconcile pass now.

        Does not wait for an in-flight periodic cycle. Any server that cycle is
        currently working on is reported as already-in-progress and left alone.
        """
        results = await reconcile_all(
            dry_run=dry_run, only_server_id=only_server_id, force=force
        )
        if not dry_run and only_server_id is None:
            self.last_results = results
            self.last_run = datetime.now(timezone.utc)
        return results

    async def _run_periodic_cycle(self) -> None:
        if self._cycle_lock.locked():
            logger.warning(
                "previous reconcile cycle is still running after %ss; skipping this tick",
                settings.sync_interval_seconds,
            )
            return
        async with self._cycle_lock:
            await self.run_once()

    async def _loop(self) -> None:
        logger.info(
            "sync loop started (interval=%ss, concurrency=%s)",
            settings.sync_interval_seconds, settings.sync_max_concurrency,
        )
        while not self._stop.is_set():
            try:
                await self._run_periodic_cycle()
            except asyncio.CancelledError:
                raise
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
        task = self._task
        if not task:
            return
        # Don't let shutdown block for a whole cycle over slow servers.
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=self.SHUTDOWN_GRACE_SECONDS)
        except asyncio.TimeoutError:
            logger.warning(
                "sync loop did not finish within %ss; cancelling",
                self.SHUTDOWN_GRACE_SECONDS,
            )
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: B014 - shutdown path
                pass
        finally:
            self._task = None


sync_manager = SyncManager()
