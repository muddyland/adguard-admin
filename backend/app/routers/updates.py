"""Fleet-wide AdGuard Home version management.

Read the fleet's update posture, force a version re-check, and trigger upgrades
by hand. The scheduling itself lives in `app.updater`; this is the operator's
window onto it.

`GET /docker-agent.sh` is deliberately unauthenticated: it is a fixed, secretless
installer script that has to be reachable by `curl | bash` on a box that has no
credentials for this app (the same way `install.sh` is reached during
provisioning). Serving it needs no session, and gating it would break the
one-liner it exists to provide.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from sqlmodel import select

from ..adguard_client import AdGuardClient, AdGuardError
from ..certs import verify_for
from ..config import settings
from ..deps import CurrentUser, RequireEditor, SessionDep
from ..models import Server
from ..schemas import UpdateOutcomeRead, UpdateOverviewRead, UpdateServerRead
from ..security import decrypt_secret
from ..update_agent import render_agent_script
from ..updater import in_maintenance_window, skip_reason, update_manager

router = APIRouter(prefix="/api/updates", tags=["updates"])

logger = logging.getLogger("adguard_admin.updates")


def _docker_agent_command() -> str:
    base = settings.public_base_url.rstrip("/")
    return f'curl -fsSL "{base}/api/updates/docker-agent.sh" | sudo bash'


@router.get("", response_model=UpdateOverviewRead)
def overview(_: CurrentUser, session: SessionDep):
    """Every server's update posture, plus the schedule it runs on."""
    now = datetime.now(timezone.utc)
    rows = session.exec(select(Server).order_by(Server.name)).all()
    servers = []
    for s in rows:
        item = UpdateServerRead.model_validate(s, from_attributes=True)
        item.skip_reason = skip_reason(s, now)
        servers.append(item)
    return UpdateOverviewRead(
        servers=servers,
        enabled=settings.auto_update_enabled,
        window=settings.auto_update_window,
        in_window=in_maintenance_window(now),
        interval_seconds=settings.auto_update_interval_seconds,
        retry_hours=settings.auto_update_retry_hours,
        last_run=update_manager.last_run,
        pass_in_progress=update_manager.pass_in_progress,
        docker_agent_command=_docker_agent_command(),
    )


@router.post("/check", response_model=list[UpdateServerRead])
async def check_now(_: RequireEditor, session: SessionDep, server_id: int | None = None):
    """Ask each server to re-check for a new release, right now.

    Reconciliation already refreshes this once a cycle from AdGuard's cached
    answer; this forces the check upstream (`recheck_now`) so the page isn't
    showing yesterday's view after a release lands.
    """
    stmt = select(Server).where(Server.enabled == True)  # noqa: E712
    if server_id is not None:
        stmt = stmt.where(Server.id == server_id)
    rows = session.exec(stmt).all()
    if server_id is not None and not rows:
        raise HTTPException(status_code=404, detail="Server not found (or disabled)")

    # Snapshot before any network I/O so the pooled connection is not held for
    # the duration of a fleet-wide round trip.
    targets = [
        (s.id, s.name, s.url, s.username, s.password_enc, s.tls_cert, s.version)
        for s in rows
    ]
    session.commit()

    async def _check(target) -> tuple[int, str | None, bool, bool, bool]:
        sid, name, url, username, password_enc, tls_cert, version = target
        try:
            client = AdGuardClient(
                url, username, decrypt_secret(password_enc),
                timeout=settings.adguard_timeout_seconds, verify=verify_for(tls_cert),
            )
        except Exception as exc:
            logger.warning("version check skipped for %s: %s", name, exc)
            return sid, None, False, False, False
        try:
            info = await client.version_check(recheck=True)
            new_version = (info.get("new_version") or "").strip()
            available = bool(new_version) and new_version != (version or "")
            return (
                sid, new_version or None, available,
                bool(info.get("can_autoupdate")), bool(info.get("disabled")),
            )
        except AdGuardError as exc:
            logger.info("version check failed for %s: %s", name, exc)
            return sid, None, False, False, False
        finally:
            await client.aclose()

    limit = max(1, settings.sync_max_concurrency)
    semaphore = asyncio.Semaphore(limit)

    async def _guarded(target):
        async with semaphore:
            return await _check(target)

    results = await asyncio.gather(*(_guarded(t) for t in targets), return_exceptions=True)

    out: list[UpdateServerRead] = []
    now = datetime.now(timezone.utc)
    for result in results:
        if isinstance(result, BaseException):
            logger.exception("version check task raised", exc_info=result)
            continue
        sid, latest, available, can_autoupdate, check_disabled = result
        server = session.get(Server, sid)
        if server is None:  # deleted while we were asking
            continue
        server.latest_version = latest
        server.update_available = available
        server.can_autoupdate = can_autoupdate
        server.update_check_disabled = check_disabled
        session.add(server)
        session.commit()
        session.refresh(server)
        item = UpdateServerRead.model_validate(server, from_attributes=True)
        item.skip_reason = skip_reason(server, now)
        out.append(item)
    return out


@router.post("/run", response_model=list[UpdateOutcomeRead])
async def run_updates_now(_: RequireEditor, force: bool = False):
    """Run an update pass over every eligible server without waiting for the timer.

    `force=true` ignores the maintenance window and the retry backoff — but never
    upgrades a server that has no update waiting.
    """
    outcomes = await update_manager.run_once(force=force)
    return [UpdateOutcomeRead(**vars(o)) for o in outcomes]


@router.post("/{server_id}/run", response_model=UpdateOutcomeRead)
async def run_update_for_server(server_id: int, _: RequireEditor, session: SessionDep):
    """Update one server now, whatever the window and its auto_update flag say.

    This is a human pressing the button, so it is always a forced run. It still
    refuses when there is nothing to install.
    """
    server = session.get(Server, server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    session.commit()  # release the connection before the (slow) upgrade

    outcomes = await update_manager.run_once(force=True, only_server_id=server_id)
    if not outcomes:
        raise HTTPException(
            status_code=409,
            detail="Nothing to install — this server is already on the latest version it knows about.",
        )
    return UpdateOutcomeRead(**vars(outcomes[0]))


@router.get("/docker-agent.sh", response_class=PlainTextResponse)
def docker_agent_script():
    """Installer for the on-box updater used by dockerised AdGuard servers."""
    return PlainTextResponse(render_agent_script(), media_type="text/x-shellscript")
