from fastapi import APIRouter, HTTPException, Query, status
from sqlmodel import select

from ..deps import CurrentUser, RequireEditor, SessionDep
from ..models import ConfigScope, ForwardZone, Server, Zone
from ..schemas import ForwardZoneCreate, ForwardZoneRead, ForwardZoneUpdate

router = APIRouter(prefix="/api/forward-zones", tags=["forward-zones"])


def _validate_scope(session, scope: ConfigScope, zone_id, server_id):
    if scope == ConfigScope.zone:
        if zone_id is None:
            raise HTTPException(status_code=400, detail="zone-scoped forward zones require a zone_id")
        if not session.get(Zone, zone_id):
            raise HTTPException(status_code=400, detail="zone_id does not exist")
    if scope == ConfigScope.server:
        if server_id is None:
            raise HTTPException(status_code=400, detail="server-scoped forward zones require a server_id")
        if not session.get(Server, server_id):
            raise HTTPException(status_code=400, detail="server_id does not exist")


@router.get("", response_model=list[ForwardZoneRead])
def list_forward_zones(
    _: CurrentUser,
    session: SessionDep,
    scope: ConfigScope | None = Query(default=None),
    zone_id: int | None = Query(default=None),
    server_id: int | None = Query(default=None),
):
    stmt = select(ForwardZone)
    if scope is not None:
        stmt = stmt.where(ForwardZone.scope == scope)
    if zone_id is not None:
        stmt = stmt.where(ForwardZone.zone_id == zone_id)
    if server_id is not None:
        stmt = stmt.where(ForwardZone.server_id == server_id)
    return session.exec(stmt).all()


@router.post("", response_model=ForwardZoneRead, status_code=status.HTTP_201_CREATED)
def create_forward_zone(payload: ForwardZoneCreate, _: RequireEditor, session: SessionDep):
    _validate_scope(session, payload.scope, payload.zone_id, payload.server_id)
    if not payload.domains.strip() or not payload.upstreams.strip():
        raise HTTPException(status_code=400, detail="domains and upstreams are required")
    fz = ForwardZone(
        domains=payload.domains.strip(),
        upstreams=payload.upstreams.strip(),
        scope=payload.scope,
        zone_id=payload.zone_id if payload.scope == ConfigScope.zone else None,
        server_id=payload.server_id if payload.scope == ConfigScope.server else None,
        enabled=payload.enabled,
        description=payload.description,
    )
    session.add(fz)
    session.commit()
    session.refresh(fz)
    return fz


@router.patch("/{fz_id}", response_model=ForwardZoneRead)
def update_forward_zone(fz_id: int, payload: ForwardZoneUpdate, _: RequireEditor, session: SessionDep):
    fz = session.get(ForwardZone, fz_id)
    if not fz:
        raise HTTPException(status_code=404, detail="Forward zone not found")
    data = payload.model_dump(exclude_unset=True)
    new_scope = data.get("scope", fz.scope)
    new_zone = data.get("zone_id", fz.zone_id)
    new_server = data.get("server_id", fz.server_id)
    _validate_scope(session, new_scope, new_zone, new_server)
    if new_scope != ConfigScope.zone:
        data["zone_id"] = None
    if new_scope != ConfigScope.server:
        data["server_id"] = None
    for field in ("domains", "upstreams"):
        if field in data and data[field]:
            data[field] = data[field].strip()
    for key, value in data.items():
        setattr(fz, key, value)
    session.add(fz)
    session.commit()
    session.refresh(fz)
    return fz


@router.delete("/{fz_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_forward_zone(fz_id: int, _: RequireEditor, session: SessionDep):
    fz = session.get(ForwardZone, fz_id)
    if not fz:
        raise HTTPException(status_code=404, detail="Forward zone not found")
    session.delete(fz)
    session.commit()
