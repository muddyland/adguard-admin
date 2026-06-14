from fastapi import APIRouter, HTTPException, Query, status
from sqlmodel import select

from ..deps import CurrentUser, RequireEditor, SessionDep
from ..filter_catalog import SERVICE_CATALOG
from ..models import BlockedService, ConfigScope, Server, Zone
from ..schemas import (
    BlockedServiceCreate,
    BlockedServiceRead,
    BlockedServiceUpdate,
    CatalogService,
)

router = APIRouter(prefix="/api/blocked-services", tags=["blocked-services"])


def _validate_scope(session, scope: ConfigScope, zone_ids, server_id):
    if scope == ConfigScope.zone:
        if not zone_ids:
            raise HTTPException(status_code=400, detail="zone-scoped services require at least one zone")
        for zid in zone_ids:
            if not session.get(Zone, zid):
                raise HTTPException(status_code=400, detail=f"zone {zid} does not exist")
    if scope == ConfigScope.server:
        if server_id is None:
            raise HTTPException(status_code=400, detail="server-scoped services require a server_id")
        if not session.get(Server, server_id):
            raise HTTPException(status_code=400, detail="server_id does not exist")


@router.get("/catalog", response_model=list[CatalogService])
def service_catalog(_: CurrentUser):
    """Popular blockable services (id + display name) for the picker."""
    return SERVICE_CATALOG


@router.get("", response_model=list[BlockedServiceRead])
def list_blocked_services(
    _: CurrentUser,
    session: SessionDep,
    scope: ConfigScope | None = Query(default=None),
    zone_id: int | None = Query(default=None),
    server_id: int | None = Query(default=None),
):
    stmt = select(BlockedService)
    if scope is not None:
        stmt = stmt.where(BlockedService.scope == scope)
    if server_id is not None:
        stmt = stmt.where(BlockedService.server_id == server_id)
    rows = session.exec(stmt).all()
    if zone_id is not None:
        rows = [b for b in rows if zone_id in (b.zone_ids or [])]
    return rows


@router.post("", response_model=BlockedServiceRead, status_code=status.HTTP_201_CREATED)
def create_blocked_service(payload: BlockedServiceCreate, _: RequireEditor, session: SessionDep):
    _validate_scope(session, payload.scope, payload.zone_ids, payload.server_id)
    sid = payload.service_id.strip()
    if not sid:
        raise HTTPException(status_code=400, detail="service_id is required")
    bs = BlockedService(
        service_id=sid,
        scope=payload.scope,
        zone_ids=sorted(set(payload.zone_ids)) if payload.scope == ConfigScope.zone else [],
        server_id=payload.server_id if payload.scope == ConfigScope.server else None,
        enabled=payload.enabled,
        description=payload.description,
    )
    session.add(bs)
    session.commit()
    session.refresh(bs)
    return bs


@router.patch("/{service_id}", response_model=BlockedServiceRead)
def update_blocked_service(service_id: int, payload: BlockedServiceUpdate, _: RequireEditor, session: SessionDep):
    bs = session.get(BlockedService, service_id)
    if not bs:
        raise HTTPException(status_code=404, detail="Blocked service not found")
    data = payload.model_dump(exclude_unset=True)
    new_scope = data.get("scope", bs.scope)
    new_zones = data.get("zone_ids", bs.zone_ids)
    new_server = data.get("server_id", bs.server_id)
    _validate_scope(session, new_scope, new_zones, new_server)
    if new_scope != ConfigScope.zone:
        data["zone_ids"] = []
    elif "zone_ids" in data:
        data["zone_ids"] = sorted(set(data["zone_ids"]))
    if new_scope != ConfigScope.server:
        data["server_id"] = None
    if "service_id" in data and data["service_id"]:
        data["service_id"] = data["service_id"].strip()
    for key, value in data.items():
        setattr(bs, key, value)
    session.add(bs)
    session.commit()
    session.refresh(bs)
    return bs


@router.delete("/{service_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_blocked_service(service_id: int, _: RequireEditor, session: SessionDep):
    bs = session.get(BlockedService, service_id)
    if not bs:
        raise HTTPException(status_code=404, detail="Blocked service not found")
    session.delete(bs)
    session.commit()
