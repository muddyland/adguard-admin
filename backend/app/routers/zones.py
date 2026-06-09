import re

from fastapi import APIRouter, HTTPException, status
from sqlmodel import func, select

from ..deps import CurrentUser, RequireEditor, SessionDep
from ..models import DNSRecord, Server, Zone
from ..schemas import ZoneCreate, ZoneRead, ZoneUpdate

router = APIRouter(prefix="/api/zones", tags=["zones"])


def slugify(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower())
    return re.sub(r"-+", "-", value).strip("-") or "zone"


def _to_read(session, zone: Zone) -> ZoneRead:
    server_count = session.exec(
        select(func.count()).select_from(Server).where(Server.zone_id == zone.id)
    ).one()
    record_count = session.exec(
        select(func.count()).select_from(DNSRecord).where(DNSRecord.zone_id == zone.id)
    ).one()
    return ZoneRead(
        id=zone.id, name=zone.name, slug=zone.slug, description=zone.description,
        created_at=zone.created_at, server_count=server_count, record_count=record_count,
    )


@router.get("", response_model=list[ZoneRead])
def list_zones(_: CurrentUser, session: SessionDep):
    return [_to_read(session, z) for z in session.exec(select(Zone)).all()]


@router.post("", response_model=ZoneRead, status_code=status.HTTP_201_CREATED)
def create_zone(payload: ZoneCreate, _: RequireEditor, session: SessionDep):
    slug = slugify(payload.slug or payload.name)
    if session.exec(select(Zone).where((Zone.name == payload.name) | (Zone.slug == slug))).first():
        raise HTTPException(status_code=409, detail="Zone name or slug already exists")
    zone = Zone(name=payload.name, slug=slug, description=payload.description)
    session.add(zone)
    session.commit()
    session.refresh(zone)
    return _to_read(session, zone)


@router.patch("/{zone_id}", response_model=ZoneRead)
def update_zone(zone_id: int, payload: ZoneUpdate, _: RequireEditor, session: SessionDep):
    zone = session.get(Zone, zone_id)
    if not zone:
        raise HTTPException(status_code=404, detail="Zone not found")
    data = payload.model_dump(exclude_unset=True)
    if "slug" in data and data["slug"]:
        data["slug"] = slugify(data["slug"])
    for key, value in data.items():
        setattr(zone, key, value)
    session.add(zone)
    session.commit()
    session.refresh(zone)
    return _to_read(session, zone)


@router.delete("/{zone_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_zone(zone_id: int, _: RequireEditor, session: SessionDep):
    zone = session.get(Zone, zone_id)
    if not zone:
        raise HTTPException(status_code=404, detail="Zone not found")
    if session.exec(select(Server).where(Server.zone_id == zone_id)).first():
        raise HTTPException(status_code=400, detail="Zone has servers; reassign or remove them first")
    # Detach any zone-scoped records (set them to no zone) is risky — require cleanup.
    if session.exec(select(DNSRecord).where(DNSRecord.zone_id == zone_id)).first():
        raise HTTPException(status_code=400, detail="Zone has DNS records; remove them first")
    session.delete(zone)
    session.commit()
