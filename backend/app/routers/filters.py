from fastapi import APIRouter, HTTPException, Query, status
from sqlmodel import select

from ..deps import CurrentUser, RequireEditor, SessionDep
from ..filter_catalog import FILTER_CATALOG
from ..models import ConfigScope, FilterKind, FilterList, Server, Zone
from ..schemas import CatalogFilter, FilterListCreate, FilterListRead, FilterListUpdate

router = APIRouter(prefix="/api/filters", tags=["filters"])


def _validate_scope(session, scope: ConfigScope, zone_ids, server_id):
    if scope == ConfigScope.zone:
        if not zone_ids:
            raise HTTPException(status_code=400, detail="zone-scoped lists require at least one zone")
        for zid in zone_ids:
            if not session.get(Zone, zid):
                raise HTTPException(status_code=400, detail=f"zone {zid} does not exist")
    if scope == ConfigScope.server:
        if server_id is None:
            raise HTTPException(status_code=400, detail="server-scoped lists require a server_id")
        if not session.get(Server, server_id):
            raise HTTPException(status_code=400, detail="server_id does not exist")


@router.get("/catalog", response_model=list[CatalogFilter])
def filter_catalog(_: CurrentUser):
    """Curated popular blocklists & allowlists, ready to add with one click."""
    return FILTER_CATALOG


@router.get("", response_model=list[FilterListRead])
def list_filters(
    _: CurrentUser,
    session: SessionDep,
    kind: FilterKind | None = Query(default=None),
    scope: ConfigScope | None = Query(default=None),
    zone_id: int | None = Query(default=None),
    server_id: int | None = Query(default=None),
):
    stmt = select(FilterList)
    if kind is not None:
        stmt = stmt.where(FilterList.kind == kind)
    if scope is not None:
        stmt = stmt.where(FilterList.scope == scope)
    if server_id is not None:
        stmt = stmt.where(FilterList.server_id == server_id)
    rows = session.exec(stmt).all()
    if zone_id is not None:
        rows = [f for f in rows if zone_id in (f.zone_ids or [])]
    return rows


@router.post("", response_model=FilterListRead, status_code=status.HTTP_201_CREATED)
def create_filter(payload: FilterListCreate, _: RequireEditor, session: SessionDep):
    _validate_scope(session, payload.scope, payload.zone_ids, payload.server_id)
    url = payload.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="url is required")
    if not payload.name.strip():
        raise HTTPException(status_code=400, detail="name is required")
    fl = FilterList(
        name=payload.name.strip(),
        url=url,
        kind=payload.kind,
        scope=payload.scope,
        zone_ids=sorted(set(payload.zone_ids)) if payload.scope == ConfigScope.zone else [],
        server_id=payload.server_id if payload.scope == ConfigScope.server else None,
        enabled=payload.enabled,
        description=payload.description,
    )
    session.add(fl)
    session.commit()
    session.refresh(fl)
    return fl


@router.patch("/{filter_id}", response_model=FilterListRead)
def update_filter(filter_id: int, payload: FilterListUpdate, _: RequireEditor, session: SessionDep):
    fl = session.get(FilterList, filter_id)
    if not fl:
        raise HTTPException(status_code=404, detail="Filter list not found")
    data = payload.model_dump(exclude_unset=True)
    new_scope = data.get("scope", fl.scope)
    new_zones = data.get("zone_ids", fl.zone_ids)
    new_server = data.get("server_id", fl.server_id)
    _validate_scope(session, new_scope, new_zones, new_server)
    if new_scope != ConfigScope.zone:
        data["zone_ids"] = []
    elif "zone_ids" in data:
        data["zone_ids"] = sorted(set(data["zone_ids"]))
    if new_scope != ConfigScope.server:
        data["server_id"] = None
    if "url" in data and data["url"]:
        data["url"] = data["url"].strip()
    if "name" in data and data["name"]:
        data["name"] = data["name"].strip()
    for key, value in data.items():
        setattr(fl, key, value)
    session.add(fl)
    session.commit()
    session.refresh(fl)
    return fl


@router.delete("/{filter_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_filter(filter_id: int, _: RequireEditor, session: SessionDep):
    fl = session.get(FilterList, filter_id)
    if not fl:
        raise HTTPException(status_code=404, detail="Filter list not found")
    session.delete(fl)
    session.commit()
