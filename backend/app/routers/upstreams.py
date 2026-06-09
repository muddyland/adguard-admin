from fastapi import APIRouter, HTTPException, Query, status
from sqlmodel import select

from ..deps import CurrentUser, RequireEditor, SessionDep
from ..models import ConfigScope, DnsServerKind, Server, Upstream, Zone
from ..schemas import UpstreamCreate, UpstreamRead, UpstreamUpdate

router = APIRouter(prefix="/api/upstreams", tags=["upstreams"])


def _validate_scope(session, scope: ConfigScope, zone_ids, server_id):
    if scope == ConfigScope.zone:
        if not zone_ids:
            raise HTTPException(status_code=400, detail="zone-scoped upstreams require at least one zone")
        for zid in zone_ids:
            if not session.get(Zone, zid):
                raise HTTPException(status_code=400, detail=f"zone {zid} does not exist")
    if scope == ConfigScope.server:
        if server_id is None:
            raise HTTPException(status_code=400, detail="server-scoped upstreams require a server_id")
        if not session.get(Server, server_id):
            raise HTTPException(status_code=400, detail="server_id does not exist")


@router.get("", response_model=list[UpstreamRead])
def list_upstreams(
    _: CurrentUser,
    session: SessionDep,
    kind: DnsServerKind | None = Query(default=None),
    scope: ConfigScope | None = Query(default=None),
    zone_id: int | None = Query(default=None),
    server_id: int | None = Query(default=None),
):
    stmt = select(Upstream)
    if kind is not None:
        stmt = stmt.where(Upstream.kind == kind)
    if scope is not None:
        stmt = stmt.where(Upstream.scope == scope)
    if server_id is not None:
        stmt = stmt.where(Upstream.server_id == server_id)
    rows = session.exec(stmt).all()
    if zone_id is not None:
        rows = [u for u in rows if zone_id in (u.zone_ids or [])]
    return rows


@router.post("", response_model=UpstreamRead, status_code=status.HTTP_201_CREATED)
def create_upstream(payload: UpstreamCreate, _: RequireEditor, session: SessionDep):
    _validate_scope(session, payload.scope, payload.zone_ids, payload.server_id)
    up = Upstream(
        address=payload.address.strip(),
        kind=payload.kind,
        scope=payload.scope,
        zone_ids=sorted(set(payload.zone_ids)) if payload.scope == ConfigScope.zone else [],
        server_id=payload.server_id if payload.scope == ConfigScope.server else None,
        enabled=payload.enabled,
        description=payload.description,
    )
    session.add(up)
    session.commit()
    session.refresh(up)
    return up


@router.patch("/{upstream_id}", response_model=UpstreamRead)
def update_upstream(upstream_id: int, payload: UpstreamUpdate, _: RequireEditor, session: SessionDep):
    up = session.get(Upstream, upstream_id)
    if not up:
        raise HTTPException(status_code=404, detail="Upstream not found")
    data = payload.model_dump(exclude_unset=True)
    new_scope = data.get("scope", up.scope)
    new_zones = data.get("zone_ids", up.zone_ids)
    new_server = data.get("server_id", up.server_id)
    _validate_scope(session, new_scope, new_zones, new_server)
    if new_scope != ConfigScope.zone:
        data["zone_ids"] = []
    elif "zone_ids" in data:
        data["zone_ids"] = sorted(set(data["zone_ids"]))
    if new_scope != ConfigScope.server:
        data["server_id"] = None
    if "address" in data and data["address"]:
        data["address"] = data["address"].strip()
    for key, value in data.items():
        setattr(up, key, value)
    session.add(up)
    session.commit()
    session.refresh(up)
    return up


@router.delete("/{upstream_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_upstream(upstream_id: int, _: RequireEditor, session: SessionDep):
    up = session.get(Upstream, upstream_id)
    if not up:
        raise HTTPException(status_code=404, detail="Upstream not found")
    session.delete(up)
    session.commit()
