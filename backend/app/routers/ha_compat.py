"""An AdGuard-Home-compatible /control API served over the whole fleet.

Home Assistant's built-in AdGuard Home integration talks to a fixed set of
/control endpoints with HTTP Basic auth, and its config flow only asks for host,
port, TLS and credentials — there is no base-path field, and it refuses a second
entry with the same host and port. So the endpoints have to live at this app's
root, and one host:port is exactly one AdGuard "instance" as far as Home
Assistant is concerned. That instance is the fleet: reads aggregate every enabled
server in scope, writes fan out to all of them.

Where this deliberately differs from a real AdGuard Home:

* **Booleans aggregate with AND.** The protection switch reads "on" only when
  every reporting server has protection on, so one unprotected box shows up
  instead of hiding behind a majority. Unreachable servers don't vote.
* **POST /control/version.json answers {"disabled": true}**, which makes Home
  Assistant skip creating an update entity. This app already owns fleet updates
  (app.updater) with a maintenance window and one-at-a-time rollout; a second,
  unscheduled "install" button that restarts every resolver at once is not
  something to offer.
* **Filter-list writes go into this app's database**, not straight onto the
  servers, because filter lists are part of the source of truth. Reconciliation
  pushes them out on its next cycle — a server with prune on would otherwise
  delete anything written behind reconciliation's back. Same for DNS rewrites.
* **The remaining toggles are not modelled**, so protection, filtering,
  safebrowsing, parental, safesearch and the query log are applied directly and
  are *not* re-applied to a server that was offline at the time.

Scope comes from HA_COMPAT_SCOPE for the bare /control prefix, or from the path
for the /zone/{slug}/control and /server/{ident}/control prefixes. Home Assistant
can only reach the first of those; the others are for scripts and for clients
that let you set a base path.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Annotated, Any, Callable, Coroutine

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from sqlmodel import select

from .. import APP_VERSION
from ..adguard_client import AdGuardClient, Rewrite
from ..config import parse_compat_scope, settings
from ..deps import SessionDep, user_has_role
from ..fleet import Outcome, as_number, fan_out, load_targets
from ..models import (
    ConfigScope,
    DNSRecord,
    FilterKind,
    FilterList,
    RecordScope,
    Role,
    Server,
    User,
    Zone,
)
from ..ratelimit import RateLimiter
from ..security import verify_password
from ..sync import desired_rewrites_for_server
from ..validators import ValidationError, validate_display_name
from .auth import client_ip

logger = logging.getLogger("adguard_admin.ha_compat")

router = APIRouter(tags=["adguard-compat"])

_BASIC_REALM = {"WWW-Authenticate": 'Basic realm="AdGuard Admin"'}

# Deliberately its own limiter rather than sharing the web UI's. A Home
# Assistant instance holding a stale password polls every 30 seconds, and a
# shared budget would lock the operator out of the UI at the same time.
compat_limiter = RateLimiter(
    max_attempts=settings.login_max_attempts,
    window_seconds=settings.login_window_seconds,
    lockout_seconds=settings.login_lockout_seconds,
)


# --------------------------------------------------------------------------- #
# Read cache
# --------------------------------------------------------------------------- #
class ReadCache:
    """Tiny per-key TTL cache that also collapses concurrent loads into one.

    Home Assistant polls fourteen entities independently and seven of them read
    /control/stats, so without this a single poll cycle fans out to the whole
    fleet a dozen times over. Keys are (endpoint, scope) pairs — a small fixed
    set — so neither dict grows without bound.
    """

    def __init__(self) -> None:
        self._entries: dict[str, tuple[float, Any]] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def clear(self) -> None:
        self._entries.clear()

    def _fresh(self, key: str, ttl: float) -> tuple[bool, Any]:
        entry = self._entries.get(key)
        if entry is not None and time.monotonic() - entry[0] < ttl:
            return True, entry[1]
        return False, None

    async def get(self, key: str, loader: Callable[[], Coroutine[Any, Any, Any]]) -> Any:
        ttl = max(0, settings.ha_compat_cache_seconds)
        if ttl:
            hit, value = self._fresh(key, ttl)
            if hit:
                return value
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            # Another request may have filled the entry while we waited for it.
            if ttl:
                hit, value = self._fresh(key, ttl)
                if hit:
                    return value
            value = await loader()
            self._entries[key] = (time.monotonic(), value)
            return value


cache = ReadCache()


# --------------------------------------------------------------------------- #
# Authentication (HTTP Basic against local accounts)
# --------------------------------------------------------------------------- #
_basic = HTTPBasic(auto_error=False)


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail=detail, headers=_BASIC_REALM
    )


def compat_user(
    request: Request,
    session: SessionDep,
    credentials: Annotated[HTTPBasicCredentials | None, Depends(_basic)] = None,
) -> User:
    """Authenticate a /control request against a local account.

    OIDC-only accounts have no password and therefore cannot be used here;
    create a local account for Home Assistant instead.
    """
    if not settings.ha_compat_enabled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="The AdGuard-compatible API is disabled (HA_COMPAT_ENABLED=false)",
        )
    if credentials is None:
        raise _unauthorized("Not authenticated")

    ip = client_ip(request)
    keys = [f"compat-ip:{ip}", f"compat-user:{credentials.username.lower()}"]
    for key in keys:
        retry_after = compat_limiter.retry_after(key)
        if retry_after:
            logger.warning("Compat API throttled for %s (retry in %ss)", key, retry_after)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed attempts. Try again later.",
                headers={"Retry-After": str(retry_after), **_BASIC_REALM},
            )

    user = session.exec(select(User).where(User.username == credentials.username)).first()
    # A disabled account is folded into the same branch on purpose: answering it
    # differently turns it into an unlimited oracle for testing passwords.
    if (
        not user
        or not user.is_active
        or not user.hashed_password
        or not verify_password(credentials.password, user.hashed_password)
    ):
        for key in keys:
            compat_limiter.record_failure(key)
        logger.info("Failed compat-API auth for username=%r from %s", credentials.username, ip)
        raise _unauthorized("Incorrect username or password")

    for key in keys:
        compat_limiter.record_success(key)
    return user


CompatUser = Annotated[User, Depends(compat_user)]


def compat_editor(user: CompatUser) -> User:
    if not user_has_role(user, Role.editor):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Requires editor role or higher"
        )
    return user


CompatEditor = Annotated[User, Depends(compat_editor)]


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Scope:
    """Which servers — and which desired records — one /control tree covers."""

    label: str
    zone_id: int | None = None
    server_id: int | None = None

    @property
    def cache_key(self) -> str:
        return f"z{self.zone_id}s{self.server_id}"


def _zone_scope(session, slug: str) -> Scope:
    zone = session.exec(select(Zone).where(Zone.slug == slug)).first()
    if zone is None:
        raise HTTPException(status_code=404, detail=f"No zone with slug {slug!r}")
    return Scope(label=f"zone {zone.slug}", zone_id=zone.id)


def _server_scope(session, ident: str) -> Scope:
    server = None
    if ident.isdigit():
        server = session.get(Server, int(ident))
    if server is None:
        server = session.exec(select(Server).where(Server.name == ident)).first()
    if server is None:
        raise HTTPException(status_code=404, detail=f"No server with id or name {ident!r}")
    return Scope(label=f"server {server.name}", server_id=server.id)


def resolve_scope(request: Request, session: SessionDep) -> Scope:
    """Read the scope off the path, falling back to HA_COMPAT_SCOPE.

    The same router is mounted under three prefixes, so which one was matched is
    visible only as a path parameter.
    """
    slug = request.path_params.get("zone_slug")
    if slug is not None:
        return _zone_scope(session, slug)
    ident = request.path_params.get("server_ident")
    if ident is not None:
        return _server_scope(session, ident)

    # Validated at startup by config_problems, so this cannot normally raise.
    kind, selector = parse_compat_scope(settings.ha_compat_scope)
    if kind == "zone":
        return _zone_scope(session, selector)
    if kind == "server":
        return _server_scope(session, selector)
    return Scope(label="fleet")


ScopeDep = Annotated[Scope, Depends(resolve_scope)]


# --------------------------------------------------------------------------- #
# Aggregation helpers
# --------------------------------------------------------------------------- #
Call = Callable[[AdGuardClient], Coroutine[Any, Any, Any]]


async def _gather(scope: Scope, key: str, call: Call) -> list[Outcome]:
    """Fan a read out across the scope, memoised for ha_compat_cache_seconds."""

    async def loader() -> list[Outcome]:
        targets = load_targets(scope.zone_id, scope.server_id)
        return await fan_out(targets, call)

    return await cache.get(f"{key}@{scope.cache_key}", loader)


def _values(outcomes: list[Outcome]) -> list[dict]:
    """The payloads of the servers that actually answered with an object."""
    return [o.value for o in outcomes if o.ok and isinstance(o.value, dict)]


def _all_on(values: list[dict], key: str = "enabled") -> bool:
    """True when every reporting server has `key` on. False when none reported."""
    if not values:
        return False
    return all(bool(v.get(key)) for v in values)


def _max_int(values: list[dict], key: str, default: int) -> int:
    numbers = [as_number(v.get(key)) for v in values if v.get(key) is not None]
    return int(max(numbers)) if numbers else default


def _first(values: list[dict], key: str, default):
    for v in values:
        if v.get(key) is not None:
            return v[key]
    return default


def _sum_stat(values: list[dict], key: str) -> int:
    return int(sum(as_number(v.get(key, 0)) for v in values))


def _sum_series(values: list[dict], key: str) -> list[int]:
    """Element-wise sum of AdGuard's per-hour/per-day series, padded to the longest."""
    series = [v.get(key) for v in values if isinstance(v.get(key), list)]
    if not series:
        return []
    out = [0.0] * max(len(s) for s in series)
    for s in series:
        for i, item in enumerate(s):
            out[i] += as_number(item)
    return [int(n) for n in out]


def _merge_top(values: list[dict], key: str, limit: int = 10) -> list[dict]:
    """AdGuard's top lists are [{name: count}, ...]; sum counts across servers.

    Keeps AdGuard's own shape rather than the dashboard's {"name", "count"} one,
    because clients here expect to be talking to AdGuard Home.
    """
    agg: dict[str, float] = {}
    for value in values:
        lst = value.get(key)
        if not isinstance(lst, list):
            continue
        for item in lst:
            if not isinstance(item, dict):
                continue
            for name, count in item.items():
                agg[str(name)] = agg.get(str(name), 0) + as_number(count)
    top = sorted(agg.items(), key=lambda kv: kv[1], reverse=True)[:limit]
    return [{name: int(count)} for name, count in top]


def _merge_filters(values: list[dict], key: str) -> list[dict]:
    """Merge the servers' filter lists by URL.

    rules_count takes the maximum rather than the sum: the same subscription on
    five servers holds the same rules, and summing it would tell Home Assistant
    the fleet blocks five times as much as it does. `enabled` is ANDed, so a list
    switched off on one box does not read as fully enabled.
    """
    merged: dict[str, dict] = {}
    for value in values:
        for item in value.get(key) or []:
            if not isinstance(item, dict):
                continue
            url = (item.get("url") or "").strip()
            if not url:
                continue
            rules = int(as_number(item.get("rules_count", 0)))
            current = merged.get(url)
            if current is None:
                merged[url] = {
                    "id": len(merged) + 1,
                    "url": url,
                    "name": item.get("name") or url,
                    "enabled": bool(item.get("enabled")),
                    "rules_count": rules,
                    "last_updated": item.get("last_updated"),
                }
            else:
                current["enabled"] = current["enabled"] and bool(item.get("enabled"))
                current["rules_count"] = max(current["rules_count"], rules)
    return list(merged.values())


async def _apply(scope: Scope, call: Call, *, what: str) -> dict:
    """Fan a write out across the scope and report AdGuard's empty 200.

    Succeeds when at least one server took it; a server that was unreachable is
    logged and left behind, because none of these toggles are part of the desired
    state that reconciliation re-applies.
    """
    targets = load_targets(scope.zone_id, scope.server_id)
    if not targets:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"No enabled AdGuard servers in scope ({scope.label})",
        )
    outcomes = await fan_out(targets, call)
    cache.clear()

    applied = [o.target.name for o in outcomes if o.ok]
    failed = {o.target.name: o.error for o in outcomes if not o.ok}
    if not applied:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"{what} failed on every server: {failed}",
        )
    if failed:
        logger.warning("%s applied to %s but failed on %s", what, applied, failed)
    else:
        logger.info("%s applied to %s", what, applied)
    return {}


# --------------------------------------------------------------------------- #
# Reads
# --------------------------------------------------------------------------- #
@router.get("/status")
async def control_status(_: CompatUser, scope: ScopeDep) -> dict:
    """The endpoint every client hits first; must answer even with no servers."""
    outcomes = await _gather(scope, "status", lambda c: c.status())
    values = _values(outcomes)
    return {
        # Not an AdGuard Home version on purpose: this is the admin app. Home
        # Assistant only shows it as the device's software version.
        "version": f"AdGuard Admin {APP_VERSION}",
        "language": "en",
        "dns_addresses": sorted(
            {
                addr
                for v in values
                for addr in (v.get("dns_addresses") or [])
                if isinstance(addr, str)
            }
        ),
        "dns_port": int(as_number(_first(values, "dns_port", settings.adguard_dns_port))),
        "protection_enabled": _all_on(values, "protection_enabled"),
        "protection_disabled_duration": 0,
        "dhcp_available": False,
        "running": bool(values),
        # Beyond AdGuard's own payload, for humans reading this by hand.
        "scope": scope.label,
        "servers_total": len(outcomes),
        "servers_reporting": len(values),
    }


@router.get("/stats")
async def control_stats(_: CompatUser, scope: ScopeDep) -> dict:
    outcomes = await _gather(scope, "stats", lambda c: c.stats())
    values = _values(outcomes)

    total_queries = sum(as_number(v.get("num_dns_queries", 0)) for v in values)
    # Weighted by each server's query count, so a quiet box with a slow upstream
    # cannot drag the fleet average around.
    weighted = sum(
        as_number(v.get("avg_processing_time", 0)) * as_number(v.get("num_dns_queries", 0))
        for v in values
    )
    return {
        "num_dns_queries": int(total_queries),
        "num_blocked_filtering": _sum_stat(values, "num_blocked_filtering"),
        "num_replaced_safebrowsing": _sum_stat(values, "num_replaced_safebrowsing"),
        "num_replaced_safesearch": _sum_stat(values, "num_replaced_safesearch"),
        "num_replaced_parental": _sum_stat(values, "num_replaced_parental"),
        # Seconds, as AdGuard reports it; clients scale it themselves.
        "avg_processing_time": round(weighted / total_queries, 6) if total_queries else 0,
        "time_units": _first(values, "time_units", "hours"),
        "dns_queries": _sum_series(values, "dns_queries"),
        "blocked_filtering": _sum_series(values, "blocked_filtering"),
        "replaced_safebrowsing": _sum_series(values, "replaced_safebrowsing"),
        "replaced_parental": _sum_series(values, "replaced_parental"),
        "top_queried_domains": _merge_top(values, "top_queried_domains"),
        "top_blocked_domains": _merge_top(values, "top_blocked_domains"),
        "top_clients": _merge_top(values, "top_clients"),
    }


@router.get("/stats_info")
async def control_stats_info(_: CompatUser, scope: ScopeDep) -> dict:
    outcomes = await _gather(scope, "stats_info", lambda c: c.stats())
    values = _values(outcomes)
    return {"enabled": bool(values), "interval": _max_int(values, "interval", 24)}


@router.get("/filtering/status")
async def control_filtering_status(_: CompatUser, scope: ScopeDep) -> dict:
    outcomes = await _gather(scope, "filtering/status", lambda c: c.filtering_status())
    values = _values(outcomes)
    return {
        "enabled": _all_on(values),
        "interval": _max_int(values, "interval", 24),
        "filters": _merge_filters(values, "filters"),
        "whitelist_filters": _merge_filters(values, "whitelist_filters"),
        "user_rules": sorted(
            {r for v in values for r in (v.get("user_rules") or []) if isinstance(r, str)}
        ),
    }


async def _safety_status(scope: Scope, service: str) -> dict:
    outcomes = await _gather(scope, f"{service}/status", lambda c: c.safety_status(service))
    return {"enabled": _all_on(_values(outcomes))}


@router.get("/safebrowsing/status")
async def control_safebrowsing_status(_: CompatUser, scope: ScopeDep) -> dict:
    return await _safety_status(scope, "safebrowsing")


@router.get("/parental/status")
async def control_parental_status(_: CompatUser, scope: ScopeDep) -> dict:
    return await _safety_status(scope, "parental")


@router.get("/safesearch/status")
async def control_safesearch_status(_: CompatUser, scope: ScopeDep) -> dict:
    return await _safety_status(scope, "safesearch")


@router.get("/querylog_info")
async def control_querylog_info(_: CompatUser, scope: ScopeDep) -> dict:
    outcomes = await _gather(scope, "querylog_info", lambda c: c.querylog_info())
    values = _values(outcomes)
    return {
        "enabled": _all_on(values),
        "interval": _first(values, "interval", 24),
        "anonymize_client_ip": _all_on(values, "anonymize_client_ip"),
    }


@router.get("/rewrite/list")
def control_rewrite_list(_: CompatUser, session: SessionDep, scope: ScopeDep) -> list[dict]:
    """The *desired* rewrites for this scope, from this app's own database.

    Answering from the database rather than from the servers is the point of the
    app: this is what every server in scope is supposed to be serving, whether or
    not it has converged yet.
    """
    return [
        {"domain": r.domain, "answer": r.answer}
        for r in _records_in_scope(session, scope)
    ]


def _records_in_scope(session, scope: Scope) -> list[Rewrite]:
    if scope.server_id is not None:
        server = session.get(Server, scope.server_id)
        if server is None:
            return []
        rewrites = desired_rewrites_for_server(session, server)
        return sorted(rewrites, key=lambda r: (r.domain, r.answer))

    rows = session.exec(
        select(DNSRecord).where(DNSRecord.enabled == True)  # noqa: E712
    ).all()
    if scope.zone_id is not None:
        rows = [
            r
            for r in rows
            if r.scope == RecordScope.global_ or scope.zone_id in (r.zone_ids or [])
        ]
    return sorted(
        (Rewrite(domain=r.domain, answer=r.answer) for r in rows),
        key=lambda r: (r.domain, r.answer),
    )


# --------------------------------------------------------------------------- #
# Writes that fan straight out (not part of the desired state)
# --------------------------------------------------------------------------- #
class ProtectionBody(BaseModel):
    enabled: bool
    # Milliseconds, and AdGuard only accepts it alongside enabled=false.
    duration: int | None = None


@router.post("/protection")
async def control_protection(body: ProtectionBody, _: CompatEditor, scope: ScopeDep) -> dict:
    return await _apply(
        scope,
        lambda c: c.set_protection(body.enabled, body.duration),
        what=f"protection={body.enabled}",
    )


@router.post("/dns_config")
async def control_dns_config(body: dict, _: CompatEditor, scope: ScopeDep) -> dict:
    """The older way to toggle protection, and the one Home Assistant uses today.

    python-adguardhome 0.8.1 — which Home Assistant pins — posts
    {"protection_enabled": bool} here; only its unreleased successor uses
    /control/protection. Both have to work.

    Nothing else from AdGuard's DNS config is accepted. Upstreams, bootstrap and
    fallback resolvers and the forward zones all come from this app's own model,
    so a write taken here would be reverted on the next reconcile — better to say
    so than to look like it worked.
    """
    if "protection_enabled" not in body:
        raise HTTPException(
            status_code=400,
            detail="only protection_enabled is supported here",
        )
    unsupported = sorted(k for k in body if k != "protection_enabled")
    if unsupported:
        raise HTTPException(
            status_code=400,
            detail=(
                f"{', '.join(unsupported)} is reconciled from AdGuard Admin's own "
                "DNS settings; change it there (or via /api/upstreams) rather than here"
            ),
        )
    enabled = bool(body["protection_enabled"])
    return await _apply(
        scope, lambda c: c.set_protection(enabled), what=f"protection={enabled}"
    )


class ToggleIntervalBody(BaseModel):
    enabled: bool
    interval: float = 24


@router.post("/filtering/config")
async def control_filtering_config(
    body: ToggleIntervalBody, _: CompatEditor, scope: ScopeDep
) -> dict:
    return await _apply(
        scope,
        lambda c: c.filtering_config(body.enabled, int(body.interval)),
        what=f"filtering={body.enabled}",
    )


@router.post("/querylog_config")
async def control_querylog_config(
    body: ToggleIntervalBody, _: CompatEditor, scope: ScopeDep
) -> dict:
    return await _apply(
        scope,
        lambda c: c.querylog_config(body.enabled, body.interval),
        what=f"querylog={body.enabled}",
    )


def _safety_routes(service: str) -> None:
    """Register /{service}/enable and /{service}/disable.

    AdGuard has three near-identical pairs of these and they take no body, so
    they are generated rather than written out six times.
    """
    for enabled, action in ((True, "enable"), (False, "disable")):

        async def toggle(
            _: CompatEditor, scope: ScopeDep, _service=service, _enabled=enabled
        ) -> dict:
            return await _apply(
                scope,
                lambda c: c.set_safety(_service, _enabled),
                what=f"{_service}={_enabled}",
            )

        router.post(f"/{service}/{action}", name=f"control_{service}_{action}")(toggle)


for _svc in ("safebrowsing", "parental", "safesearch"):
    _safety_routes(_svc)


class RefreshBody(BaseModel):
    whitelist: bool = False


@router.post("/filtering/refresh")
async def control_filtering_refresh(
    _: CompatEditor,
    scope: ScopeDep,
    body: RefreshBody | None = None,
    force: bool = Query(default=False),
) -> dict:
    """Re-download the filter lists now. Returns how many lists AdGuard updated."""
    whitelist = body.whitelist if body else False
    targets = load_targets(scope.zone_id, scope.server_id)
    if not targets:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"No enabled AdGuard servers in scope ({scope.label})",
        )
    outcomes = await fan_out(targets, lambda c: c.filtering_refresh(whitelist, force))
    cache.clear()
    updated = _sum_stat(_values(outcomes), "updated")
    failed = {o.target.name: o.error for o in outcomes if not o.ok}
    if failed and len(failed) == len(outcomes):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"filter refresh failed on every server: {failed}",
        )
    if failed:
        logger.warning("filter refresh failed on %s", failed)
    return {"updated": updated}


# --------------------------------------------------------------------------- #
# Writes that land in the database (the source of truth)
# --------------------------------------------------------------------------- #
def _scope_fields(scope: Scope) -> dict:
    """Where a row created through this API belongs, mirroring the request scope."""
    if scope.server_id is not None:
        return {"scope": ConfigScope.server, "zone_ids": [], "server_id": scope.server_id}
    if scope.zone_id is not None:
        return {"scope": ConfigScope.zone, "zone_ids": [scope.zone_id], "server_id": None}
    return {"scope": ConfigScope.global_, "zone_ids": [], "server_id": None}


def _row_in_scope(row, scope: Scope) -> bool:
    if scope.server_id is not None:
        return row.server_id == scope.server_id
    if scope.zone_id is not None:
        return scope.zone_id in (row.zone_ids or [])
    return row.scope == ConfigScope.global_


def _valid_name(value: str, fallback: str) -> str:
    """A display name for a row created through this API.

    validate_display_name raises ValidationError, which would otherwise surface
    as a 500 rather than telling the caller what was wrong with its input.
    """
    if not value.strip():
        return fallback
    try:
        return validate_display_name(value, field="name")
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _validate_list_url(url: str) -> str:
    """Only http(s) subscriptions.

    AdGuard also accepts a local file path, but a path means something different
    on every server in a fleet, and reconciliation would push it to all of them.
    """
    text = (url or "").strip()
    if not text.lower().startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail="url must be an http(s) filter-list URL; local paths are not supported here",
        )
    return text


class AddUrlBody(BaseModel):
    url: str
    name: str = ""
    whitelist: bool = False


@router.post("/filtering/add_url")
def control_filtering_add_url(
    body: AddUrlBody, user: CompatEditor, session: SessionDep, scope: ScopeDep
) -> dict:
    """Subscribe to a filter list — recorded here, pushed out by reconciliation.

    It only reaches servers that have "Manage filtering" switched on; that is the
    same opt-in the UI uses, and a server without it is never touched.
    """
    url = _validate_list_url(body.url)
    kind = FilterKind.allowlist if body.whitelist else FilterKind.blocklist
    name = _valid_name(body.name, url)

    existing = session.exec(select(FilterList).where(FilterList.kind == kind)).all()
    if any(f.url.strip().lower() == url.lower() and _row_in_scope(f, scope) for f in existing):
        raise HTTPException(status_code=400, detail="that filter list is already subscribed")

    row = FilterList(
        name=name,
        url=url,
        kind=kind,
        enabled=True,
        description=f"Added via the AdGuard-compatible API by {user.username}",
        **_scope_fields(scope),
    )
    session.add(row)
    session.commit()
    cache.clear()
    logger.info("compat API added %s list %s (%s) at %s", kind.value, name, url, scope.label)
    _warn_if_nobody_manages_filtering(session, scope)
    return {}


class RemoveUrlBody(BaseModel):
    url: str
    whitelist: bool = False


@router.post("/filtering/remove_url")
def control_filtering_remove_url(
    body: RemoveUrlBody, _: CompatEditor, session: SessionDep, scope: ScopeDep
) -> dict:
    """Unsubscribe. Lenient about an unknown URL, the way AdGuard Home is."""
    kind = FilterKind.allowlist if body.whitelist else FilterKind.blocklist
    url = (body.url or "").strip().lower()
    rows = [
        f
        for f in session.exec(select(FilterList).where(FilterList.kind == kind)).all()
        if f.url.strip().lower() == url and _row_in_scope(f, scope)
    ]
    for row in rows:
        session.delete(row)
    session.commit()
    cache.clear()
    logger.info("compat API removed %s %s list(s) for %s", len(rows), kind.value, body.url)
    return {}


class SetUrlData(BaseModel):
    enabled: bool = True
    name: str = ""
    url: str = ""


class SetUrlBody(BaseModel):
    url: str
    data: SetUrlData
    whitelist: bool = False


@router.post("/filtering/set_url")
def control_filtering_set_url(
    body: SetUrlBody, _: CompatEditor, session: SessionDep, scope: ScopeDep
) -> dict:
    """Enable, disable or rename a subscription this app already knows about."""
    kind = FilterKind.allowlist if body.whitelist else FilterKind.blocklist
    url = (body.url or "").strip().lower()
    rows = [
        f
        for f in session.exec(select(FilterList).where(FilterList.kind == kind)).all()
        if f.url.strip().lower() == url and _row_in_scope(f, scope)
    ]
    if not rows:
        raise HTTPException(status_code=404, detail=f"no {kind.value} subscribed for {body.url!r}")

    for row in rows:
        row.enabled = body.data.enabled
        if body.data.name.strip():
            row.name = _valid_name(body.data.name, row.name)
        if body.data.url.strip():
            row.url = _validate_list_url(body.data.url)
        session.add(row)
    session.commit()
    cache.clear()
    logger.info(
        "compat API set %s %s enabled=%s", kind.value, body.url, body.data.enabled
    )
    return {}


class RewriteBody(BaseModel):
    domain: str
    answer: str


@router.post("/rewrite/add")
def control_rewrite_add(
    body: RewriteBody, _: CompatEditor, session: SessionDep, scope: ScopeDep
) -> dict:
    """Add a DNS rewrite to the source of truth, for reconciliation to push out."""
    domain = (body.domain or "").strip().lower()
    answer = (body.answer or "").strip()
    if not domain or not answer:
        raise HTTPException(status_code=400, detail="domain and answer are both required")

    fields = _scope_fields(scope)
    if fields["scope"] == ConfigScope.server:
        # DNSRecord has no per-server scope: a server-scoped /control tree can
        # only add a record to that server's zone, or globally if it has none.
        server = session.get(Server, scope.server_id)
        zone_id = server.zone_id if server else None
        record_scope = RecordScope.zone if zone_id else RecordScope.global_
        zone_ids = [zone_id] if zone_id else []
    elif fields["scope"] == ConfigScope.zone:
        record_scope, zone_ids = RecordScope.zone, list(fields["zone_ids"])
    else:
        record_scope, zone_ids = RecordScope.global_, []

    existing = session.exec(
        select(DNSRecord).where(DNSRecord.domain == domain, DNSRecord.answer == answer)
    ).first()
    if existing is not None:
        raise HTTPException(status_code=400, detail="that rewrite already exists")

    session.add(
        DNSRecord(
            domain=domain,
            answer=answer,
            scope=record_scope,
            zone_ids=zone_ids,
            enabled=True,
            description="Added via the AdGuard-compatible API",
        )
    )
    session.commit()
    logger.info("compat API added rewrite %s -> %s (%s)", domain, answer, scope.label)
    return {}


@router.post("/rewrite/delete")
def control_rewrite_delete(
    body: RewriteBody, _: CompatEditor, session: SessionDep, scope: ScopeDep
) -> dict:
    domain = (body.domain or "").strip().lower()
    answer = (body.answer or "").strip()
    rows = session.exec(
        select(DNSRecord).where(DNSRecord.domain == domain, DNSRecord.answer == answer)
    ).all()
    # Checked before anything is deleted, so a mixed batch is refused whole.
    if any(row.managed for row in rows):
        # Auto-maintained server-hostname records; the UI refuses these too.
        raise HTTPException(
            status_code=409, detail="that rewrite is auto-managed from the servers list"
        )
    for row in rows:
        session.delete(row)
    session.commit()
    logger.info("compat API removed %s rewrite(s) for %s", len(rows), domain)
    return {}


# --------------------------------------------------------------------------- #
# Updates: answered, but not offered
# --------------------------------------------------------------------------- #
@router.post("/version.json")
def control_version_json(_: CompatUser) -> dict:
    """Report that the version check is off, so clients skip their update entity.

    The response must contain only the keys python-adguardhome's dataclass
    accepts — it does `AdGuardHomeAvailableUpdate(**response)`, so an extra key
    is a TypeError on the client. Fleet updates live in app.updater, which rolls
    one server at a time inside a maintenance window.
    """
    return {
        "disabled": True,
        "new_version": "",
        "announcement": "AdGuard Admin manages AdGuard Home updates itself, one server at a time.",
        "announcement_url": "",
        "can_autoupdate": False,
    }


@router.post("/update")
def control_update(_: CompatEditor) -> dict:
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=(
            "Upgrading AdGuard Home is not exposed here. AdGuard Admin rolls updates "
            "one server at a time inside its maintenance window; use the Updates page "
            "or POST /api/updates."
        ),
    )


def _warn_if_nobody_manages_filtering(session, scope: Scope) -> None:
    """Say so in the log when a filter-list write cannot reach anything.

    Filtering is opt-in per server, so a subscription added here is recorded
    faithfully but stays invisible until a server opts in — which looks like the
    write was lost.
    """
    stmt = select(Server).where(
        Server.enabled == True,  # noqa: E712
        Server.manage_filtering == True,  # noqa: E712
    )
    if scope.zone_id is not None:
        stmt = stmt.where(Server.zone_id == scope.zone_id)
    if scope.server_id is not None:
        stmt = stmt.where(Server.id == scope.server_id)
    if session.exec(stmt).first() is None:
        logger.warning(
            "Filter list recorded, but no enabled server in %s has 'Manage filtering' on, "
            "so reconciliation will not push it anywhere yet.",
            scope.label,
        )
