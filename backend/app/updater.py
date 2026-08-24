"""Automatic AdGuard Home upgrades for the managed fleet.

Two very different things have to happen depending on how AdGuard Home was
installed, and the split is not a style choice — it is what the runtime allows:

* **Bare-metal.** AdGuard Home can replace its own binary and restart. This app
  drives that over the control API (`POST /control/update`), which is exactly
  what the "Update now" button in AdGuard's own UI does. Scheduling, the
  maintenance window, retries and the audit trail all live here, in the control
  plane, so the whole fleet upgrades from one place.

* **Docker.** A container cannot replace the image it is running from, and
  AdGuard reports `can_autoupdate: false` accordingly. There is no remote
  execution channel to the host either, so the control plane *cannot* do it.
  Instead an updater runs on the box itself (installed by provisioning, or with
  the one-liner from `app.update_agent`), pulls the image and recreates the
  container. This app records those servers as `delegated` and simply observes
  the version change on the next reconcile.

Nothing here happens unless the operator opts a server in (`Server.auto_update`)
and leaves the master switch on (`AUTO_UPDATE_ENABLED`). An upgrade restarts
AdGuard Home, which briefly stops DNS for everything behind it, so it is off by
default and can be confined to a maintenance window.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlmodel import Session, select

from .adguard_client import AdGuardClient, AdGuardError
from .certs import verify_for
from .config import parse_window, settings
from .database import engine
from .models import InstallMethod, Server, UpdateState
from .security import decrypt_secret
from .sync import lock_for

logger = logging.getLogger("adguard_admin.updater")

# How often to poll for the new version while a box restarts.
_POLL_INTERVAL_SECONDS = 5.0


@dataclass
class UpdateOutcome:
    """What happened to one server. Also the API response shape."""
    server_id: int
    server_name: str
    state: UpdateState
    from_version: str | None = None
    to_version: str | None = None
    message: str = ""

    @property
    def changed(self) -> bool:
        return self.state == UpdateState.succeeded


def _aware(value: datetime | None) -> datetime | None:
    """SQLite hands back naive datetimes; everything here works in UTC."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def in_maintenance_window(now: datetime, window: str | None = None) -> bool:
    """Is `now` (UTC) inside the configured window? No window means always."""
    spec = settings.auto_update_window if window is None else window
    try:
        parsed = parse_window(spec)
    except ValueError:
        # Startup rejects a malformed window; if one gets here anyway, refuse to
        # upgrade rather than guessing that "any time" was meant.
        logger.error("AUTO_UPDATE_WINDOW is invalid (%r); skipping automatic updates", spec)
        return False
    if parsed is None:
        return True
    start, end = parsed
    minutes = now.hour * 60 + now.minute
    if start < end:
        return start <= minutes < end
    # Wraps midnight, e.g. 23:00-02:00.
    return minutes >= start or minutes < end


def skip_reason(server: Server, now: datetime) -> str | None:
    """Why this server is not due for an automatic upgrade, or None if it is."""
    if not server.enabled:
        return "server is disabled"
    if not server.auto_update:
        return "automatic updates are off for this server"
    if not server.update_available or not (server.latest_version or "").strip():
        if server.update_check_disabled:
            if server.install_method == InstallMethod.docker:
                return "kept current by the on-box updater; the container cannot report releases"
            return (
                "this server's own update check is switched off, so it never reports a new "
                "release (AdGuard Home → Settings → General settings, or a --no-check-update flag)"
            )
        return "already on the latest version"

    cooldown = _aware(server.cooldown_until)
    if cooldown and cooldown > now:
        return "server is in an auth/rate-limit cooldown"

    target = (server.latest_version or "").strip()
    attempted = (server.update_attempted_version or "").strip()
    attempted_at = _aware(server.update_attempted_at)

    if server.update_state == UpdateState.delegated and attempted == target:
        # The on-box updater owns this one; re-asking every cycle just spams the
        # log and the server's audit trail.
        return "handled by the on-box updater"
    if server.update_state == UpdateState.failed and attempted == target and attempted_at:
        retry_at = attempted_at + timedelta(hours=max(0, settings.auto_update_retry_hours))
        if retry_at > now:
            return f"last attempt failed; retrying after {retry_at:%Y-%m-%d %H:%M} UTC"
    return None


def due_server_ids(*, force: bool = False, only_server_id: int | None = None) -> list[int]:
    """Ids of servers to upgrade this pass, read in one short transaction.

    `force` bypasses the maintenance window and the retry backoff (a human
    pressed "Update now"), but never the master switch being off, nor a server
    that has no update to install.
    """
    now = datetime.now(timezone.utc)
    if not force and not in_maintenance_window(now):
        return []
    with Session(engine) as session:
        stmt = select(Server)
        if only_server_id is not None:
            stmt = stmt.where(Server.id == only_server_id)
        due: list[int] = []
        for server in session.exec(stmt).all():
            if force:
                # Still refuse the pointless cases: nothing to install, or a box
                # we already know updates itself.
                if not server.update_available or not (server.latest_version or "").strip():
                    continue
            else:
                reason = skip_reason(server, now)
                if reason:
                    logger.debug("skipping %s: %s", server.name, reason)
                    continue
            due.append(server.id)
        return due


def _record(server_id: int, outcome: UpdateOutcome, *, target: str | None) -> None:
    """Persist an attempt's result in its own short transaction."""
    now = datetime.now(timezone.utc)
    with Session(engine) as session:
        server = session.get(Server, server_id)
        if server is None:  # deleted mid-flight
            return
        server.update_state = outcome.state
        server.update_attempted_at = now
        server.update_attempted_version = target
        server.update_error = None if outcome.state == UpdateState.succeeded else (outcome.message or None)
        if outcome.state == UpdateState.idle:
            # Nothing went wrong, so don't leave a red error on the row.
            server.update_error = None
        if outcome.state == UpdateState.succeeded:
            server.update_completed_at = now
            server.update_error = None
            if outcome.to_version:
                server.version = outcome.to_version
            # Reconcile will re-check, but don't leave a stale "update available"
            # badge in the UI for a whole cycle after we just installed it.
            server.update_available = False
            server.latest_version = None
        session.add(server)
        session.commit()


async def _await_new_version(
    client: AdGuardClient, previous: str | None, deadline: float
) -> str | None:
    """Poll /control/status until the box reports a version other than `previous`.

    Returns the version it came back on, or None if it never came back in time.
    Matching on "changed" rather than "== target" on purpose: AdGuard's release
    string and its version-check string are not always spelled identically.
    """
    loop = asyncio.get_running_loop()
    while loop.time() < deadline:
        await asyncio.sleep(_POLL_INTERVAL_SECONDS)
        try:
            status = await client.status()
        except AdGuardError:
            continue  # still down / restarting
        current = (status.get("version") or "").strip()
        if current and current != (previous or "").strip():
            return current
    return None


async def update_server(server_id: int) -> UpdateOutcome | None:
    """Upgrade one server. Never raises; returns None if it vanished.

    Takes the same per-server lock reconciliation uses, so a sync pass is never
    mid-conversation with a box that is restarting under it.
    """
    lock = lock_for(server_id)
    if lock.locked():
        with Session(engine) as session:
            server = session.get(Server, server_id)
            name = server.name if server else f"server #{server_id}"
        return UpdateOutcome(
            server_id=server_id, server_name=name, state=UpdateState.idle,
            message="Busy with another operation; will be picked up next pass.",
        )

    async with lock:
        # Snapshot what we need, then let the connection go: everything below is
        # network I/O and can take minutes while the box restarts.
        with Session(engine) as session:
            server = session.get(Server, server_id)
            if server is None:
                return None
            name, url = server.name, server.url
            username, password_enc = server.username, server.password_enc
            tls_cert = server.tls_cert
            install_method = server.install_method
            current_version = server.version

        try:
            client = AdGuardClient(
                url, username, decrypt_secret(password_enc),
                timeout=settings.adguard_timeout_seconds,
                verify=verify_for(tls_cert),
            )
        except Exception as exc:
            logger.exception("could not build a client for %s", name)
            outcome = UpdateOutcome(
                server_id=server_id, server_name=name, state=UpdateState.failed,
                from_version=current_version, message=f"Server configuration error: {exc}",
            )
            _record(server_id, outcome, target=None)
            return outcome

        target: str | None = None
        try:
            # Ask the box itself rather than trusting our cached flag: the fleet
            # view can be a cycle stale, and we are about to restart a resolver.
            info = await client.version_check(recheck=True)
            target = (info.get("new_version") or "").strip() or None
            can_autoupdate = bool(info.get("can_autoupdate"))
            check_disabled = bool(info.get("disabled"))
            status = await client.status()
            current_version = (status.get("version") or "").strip() or current_version

            if not target or target == (current_version or ""):
                # "No new version" and "I was never asked to look" are different
                # answers. AdGuard returns {"disabled": true} for the second, and
                # reporting it as up to date would hide a server stuck on an old
                # release forever.
                message = (
                    _check_disabled_message(install_method)
                    if check_disabled
                    else "Already on the latest version."
                )
                outcome = UpdateOutcome(
                    server_id=server_id, server_name=name, state=UpdateState.idle,
                    from_version=current_version, message=message,
                )
                _record(server_id, outcome, target=None)
                return outcome

            # A container is delegated on the strength of how it was installed,
            # not on what it claims. Older AdGuard releases answer
            # `can_autoupdate: true` inside Docker and then fail the upgrade with
            # a 500 — trying anyway buys a pointless failed attempt on every box.
            if install_method == InstallMethod.docker or not can_autoupdate:
                outcome = UpdateOutcome(
                    server_id=server_id, server_name=name, state=UpdateState.delegated,
                    from_version=current_version, to_version=target,
                    message=_delegated_message(install_method, target),
                )
                _record(server_id, outcome, target=target)
                logger.info("%s cannot self-upgrade to %s: %s", name, target, outcome.message)
                return outcome

            logger.info("upgrading %s: %s -> %s", name, current_version or "?", target)
            try:
                await client.update_now()
            except AdGuardError as exc:
                # A refusal has a status code. Anything else is the connection
                # dying as the process restarts — which means it started.
                if exc.status_code is not None:
                    raise AdGuardError(
                        f"{exc} — AdGuard refused to upgrade itself. This usually means the "
                        "install cannot be replaced in place (a container, a package install, "
                        "or a read-only binary), even though it reported that it could. "
                        "Set this server's install method so the right updater is used.",
                        status_code=exc.status_code,
                    ) from exc
                logger.debug("update request to %s ended in transport error (expected): %s", name, exc)

            deadline = asyncio.get_running_loop().time() + settings.auto_update_restart_timeout_seconds
            new_version = await _await_new_version(client, current_version, deadline)
            if new_version is None:
                outcome = UpdateOutcome(
                    server_id=server_id, server_name=name, state=UpdateState.failed,
                    from_version=current_version, to_version=target,
                    message=(
                        f"Upgrade to {target} was started but the server did not come back "
                        f"within {settings.auto_update_restart_timeout_seconds:g}s. It may still "
                        "be restarting — check the server before retrying."
                    ),
                )
                _record(server_id, outcome, target=target)
                logger.warning("%s: %s", name, outcome.message)
                return outcome

            outcome = UpdateOutcome(
                server_id=server_id, server_name=name, state=UpdateState.succeeded,
                from_version=current_version, to_version=new_version,
                message=f"Updated {current_version or '?'} -> {new_version}.",
            )
            _record(server_id, outcome, target=target)
            logger.info("%s updated to %s", name, new_version)
            return outcome

        except AdGuardError as exc:
            outcome = UpdateOutcome(
                server_id=server_id, server_name=name, state=UpdateState.failed,
                from_version=current_version, to_version=target, message=str(exc),
            )
            _record(server_id, outcome, target=target)
            logger.warning("update failed for %s: %s", name, exc)
            return outcome
        except Exception as exc:  # defensive: one server must not kill the pass
            logger.exception("unexpected error updating %s", name)
            outcome = UpdateOutcome(
                server_id=server_id, server_name=name, state=UpdateState.failed,
                from_version=current_version, to_version=target, message=str(exc),
            )
            _record(server_id, outcome, target=target)
            return outcome
        finally:
            await client.aclose()


def _check_disabled_message(install_method: InstallMethod | None) -> str:
    """Why this server never reports a new release, and whether that is a fault.

    For a container it is neither a fault nor fixable: the official image bakes
    `--no-check-update` into its command, which wins over `check_update` in the
    config, so the setting is absent from its UI entirely. Telling those
    operators to go and switch it on sends them looking for a control that does
    not exist. The on-box updater is what keeps a container current anyway.
    """
    if install_method == InstallMethod.docker:
        return (
            "AdGuard Home in Docker ships with --no-check-update, so it never reports "
            "new releases. That is expected and cannot be changed from its UI — the "
            "on-box updater keeps the container up to date instead."
        )
    return (
        "This server's update check is switched off, so it cannot report new releases. "
        "Turn on 'Automatically check for updates' in its AdGuard Home settings, or — if "
        "it is started with --no-check-update — remove that flag."
    )


def _delegated_message(install_method: InstallMethod | None, target: str) -> str:
    if install_method == InstallMethod.docker:
        return (
            f"AdGuard Home {target} is available. A container cannot replace its own "
            "image, so the on-box updater installs it — see Updates → 'Docker servers'."
        )
    return (
        f"AdGuard Home {target} is available, but this instance reports it cannot "
        "upgrade itself (a container, a package install, or a read-only binary). "
        "Install the on-box updater, or update it the way it was installed."
    )


async def run_updates(
    *, force: bool = False, only_server_id: int | None = None
) -> list[UpdateOutcome]:
    """One pass over every server that is due."""
    if not settings.auto_update_enabled and not force:
        logger.debug("automatic updates are disabled (AUTO_UPDATE_ENABLED=false)")
        return []

    server_ids = await asyncio.to_thread(
        due_server_ids, force=force, only_server_id=only_server_id
    )
    if not server_ids:
        return []

    # Deliberately narrow (default 1): upgrading the whole fleet at once would
    # take DNS down everywhere at the same moment.
    limit = max(1, settings.auto_update_max_concurrency)
    semaphore = asyncio.Semaphore(limit)

    async def _guarded(sid: int) -> UpdateOutcome | None:
        async with semaphore:
            return await update_server(sid)

    settled = await asyncio.gather(
        *(_guarded(sid) for sid in server_ids), return_exceptions=True
    )

    outcomes: list[UpdateOutcome] = []
    for sid, item in zip(server_ids, settled):
        if isinstance(item, BaseException):
            logger.exception("update task for server id=%s raised", sid, exc_info=item)
            outcomes.append(UpdateOutcome(
                server_id=sid, server_name=f"server #{sid}",
                state=UpdateState.failed, message=str(item),
            ))
        elif item is not None:
            outcomes.append(item)
    return outcomes


class UpdateManager:
    """Owns the background auto-update loop.

    Separate from SyncManager because it runs on a completely different
    timescale: reconciliation every minute, upgrades at most hourly and usually
    inside a maintenance window.
    """

    SHUTDOWN_GRACE_SECONDS = 20.0

    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._pass_lock = asyncio.Lock()
        self.last_run: datetime | None = None
        self.last_outcomes: list[UpdateOutcome] = []

    @property
    def pass_in_progress(self) -> bool:
        return self._pass_lock.locked()

    async def run_once(
        self, *, force: bool = False, only_server_id: int | None = None
    ) -> list[UpdateOutcome]:
        outcomes = await run_updates(force=force, only_server_id=only_server_id)
        if only_server_id is None:
            self.last_outcomes = outcomes
            self.last_run = datetime.now(timezone.utc)
        return outcomes

    async def _run_periodic_pass(self) -> None:
        if self._pass_lock.locked():
            logger.warning("previous update pass is still running; skipping this tick")
            return
        async with self._pass_lock:
            outcomes = await self.run_once()
            for o in outcomes:
                if o.state in (UpdateState.succeeded, UpdateState.failed):
                    logger.info("auto-update %s: %s", o.server_name, o.message)

    async def _loop(self) -> None:
        logger.info(
            "auto-update loop started (interval=%ss, window=%s)",
            settings.auto_update_interval_seconds,
            settings.auto_update_window or "any time",
        )
        while not self._stop.is_set():
            try:
                await self._run_periodic_pass()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("auto-update pass crashed")
            try:
                await asyncio.wait_for(
                    self._stop.wait(), timeout=settings.auto_update_interval_seconds
                )
            except asyncio.TimeoutError:
                pass

    def start(self) -> None:
        if not settings.auto_update_enabled:
            logger.info("automatic updates are disabled (AUTO_UPDATE_ENABLED=false)")
            return
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._stop.set()
        task = self._task
        if not task:
            return
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=self.SHUTDOWN_GRACE_SECONDS)
        except asyncio.TimeoutError:
            logger.warning(
                "auto-update loop did not finish within %ss; cancelling",
                self.SHUTDOWN_GRACE_SECONDS,
            )
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: B014 - shutdown path
                pass
        finally:
            self._task = None


update_manager = UpdateManager()
