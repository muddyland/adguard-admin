"""Traffic metrics, served from the sample store (see app.telemetry).

Nothing here talks to a server: the collector that rides on the reconcile
loop already did, once a cycle. `GET /api/metrics` keeps the shape the live
version had so the breakdown and top lists did not change with the source;
`/overview`, `/series` and `/attention` feed the Dashboard; `GET /metrics`
(no /api prefix) is the Prometheus scrape target.
"""
from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException, Query, Response
from sqlmodel import Session, select

from .. import telemetry
from ..database import engine
from ..deps import CurrentUser
from ..models import Server
from ..sync import sync_manager

router = APIRouter(prefix="/api/metrics", tags=["metrics"])
prom_router = APIRouter(tags=["metrics"])


@router.get("")
def metrics(
    _: CurrentUser,
    zone_id: int | None = Query(default=None),
    server_id: int | None = Query(default=None),
):
    with Session(engine) as session:
        return telemetry.traffic(session, zone_id, server_id)


@router.get("/overview")
def overview(_: CurrentUser):
    with Session(engine) as session:
        return telemetry.overview(session)


@router.get("/series")
def series(
    _: CurrentUser,
    range: str = Query(default="24h"),
    zone_id: int | None = Query(default=None),
    server_id: int | None = Query(default=None),
):
    with Session(engine) as session:
        stmt = select(Server.id).where(Server.enabled == True)  # noqa: E712
        if zone_id is not None:
            stmt = stmt.where(Server.zone_id == zone_id)
        if server_id is not None:
            stmt = stmt.where(Server.id == server_id)
        ids = list(session.exec(stmt).all())
        return telemetry.series(session, telemetry.KIND_SERVER, ids, range)


@router.get("/attention")
def attention(_: CurrentUser):
    with Session(engine) as session:
        return telemetry.attention(session, last_sync=sync_manager.last_run)


@prom_router.get("/metrics", include_in_schema=False)
def prometheus(authorization: str | None = Header(default=None)):
    if not telemetry.settings.metrics_token:
        raise HTTPException(status_code=404, detail="Not found")
    if not telemetry.token_ok(authorization):
        raise HTTPException(status_code=401, detail="Bearer token required",
                            headers={"WWW-Authenticate": "Bearer"})
    with Session(engine) as session:
        body = telemetry.prometheus(session, last_sync=sync_manager.last_run)
    return Response(content=body, media_type="text/plain; version=0.0.4; charset=utf-8")
