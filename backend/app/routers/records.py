from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, status
from sqlmodel import select

from ..deps import CurrentUser, RequireEditor, SessionDep
from ..models import DNSRecord, RecordScope, Zone
from ..schemas import RecordCreate, RecordRead, RecordUpdate

router = APIRouter(prefix="/api/records", tags=["records"])


def _validate_scope(session, scope: RecordScope, zone_id):
    if scope == RecordScope.zone:
        if zone_id is None:
            raise HTTPException(status_code=400, detail="zone-scoped records require a zone_id")
        if not session.get(Zone, zone_id):
            raise HTTPException(status_code=400, detail="zone_id does not exist")


@router.get("", response_model=list[RecordRead])
def list_records(
    _: CurrentUser,
    session: SessionDep,
    scope: RecordScope | None = Query(default=None),
    zone_id: int | None = Query(default=None),
):
    stmt = select(DNSRecord)
    if scope is not None:
        stmt = stmt.where(DNSRecord.scope == scope)
    if zone_id is not None:
        stmt = stmt.where(DNSRecord.zone_id == zone_id)
    return session.exec(stmt.order_by(DNSRecord.domain)).all()


@router.post("", response_model=RecordRead, status_code=status.HTTP_201_CREATED)
def create_record(payload: RecordCreate, _: RequireEditor, session: SessionDep):
    _validate_scope(session, payload.scope, payload.zone_id)
    zone_id = payload.zone_id if payload.scope == RecordScope.zone else None
    record = DNSRecord(
        domain=payload.domain.strip().lower(),
        answer=payload.answer.strip(),
        scope=payload.scope,
        zone_id=zone_id,
        enabled=payload.enabled,
        description=payload.description,
    )
    session.add(record)
    session.commit()
    session.refresh(record)
    return record


@router.patch("/{record_id}", response_model=RecordRead)
def update_record(record_id: int, payload: RecordUpdate, _: RequireEditor, session: SessionDep):
    record = session.get(DNSRecord, record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    data = payload.model_dump(exclude_unset=True)
    new_scope = data.get("scope", record.scope)
    new_zone = data.get("zone_id", record.zone_id)
    _validate_scope(session, new_scope, new_zone)
    if new_scope == RecordScope.global_:
        data["zone_id"] = None
    if "domain" in data and data["domain"]:
        data["domain"] = data["domain"].strip().lower()
    if "answer" in data and data["answer"]:
        data["answer"] = data["answer"].strip()
    for key, value in data.items():
        setattr(record, key, value)
    record.updated_at = datetime.now(timezone.utc)
    session.add(record)
    session.commit()
    session.refresh(record)
    return record


@router.delete("/{record_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_record(record_id: int, _: RequireEditor, session: SessionDep):
    record = session.get(DNSRecord, record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    session.delete(record)
    session.commit()
