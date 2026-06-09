from fastapi import APIRouter, HTTPException, status
from sqlmodel import select

from ..adguard_client import AdGuardClient, AdGuardError
from ..certs import verify_for
from ..deps import CurrentUser, RequireEditor, SessionDep
from ..models import DNSRecord, RecordScope, Server, Zone
from ..schemas import ServerCreate, ServerRead, ServerUpdate
from ..security import decrypt_secret, encrypt_secret

router = APIRouter(prefix="/api/servers", tags=["servers"])


def _validate_zone(session, zone_id):
    if zone_id is not None and not session.get(Zone, zone_id):
        raise HTTPException(status_code=400, detail="zone_id does not exist")


@router.get("", response_model=list[ServerRead])
def list_servers(_: CurrentUser, session: SessionDep):
    return session.exec(select(Server)).all()


@router.post("", response_model=ServerRead, status_code=status.HTTP_201_CREATED)
def create_server(payload: ServerCreate, _: RequireEditor, session: SessionDep):
    _validate_zone(session, payload.zone_id)
    server = Server(
        name=payload.name,
        url=payload.url.rstrip("/"),
        username=payload.username,
        password_enc=encrypt_secret(payload.password),
        zone_id=payload.zone_id,
        enabled=payload.enabled,
        prune=payload.prune,
    )
    session.add(server)
    session.commit()
    session.refresh(server)
    return server


@router.patch("/{server_id}", response_model=ServerRead)
def update_server(server_id: int, payload: ServerUpdate, _: RequireEditor, session: SessionDep):
    server = session.get(Server, server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    data = payload.model_dump(exclude_unset=True)
    if "zone_id" in data:
        _validate_zone(session, data["zone_id"])
    if "password" in data:
        # Only rotate when a non-empty password is supplied.
        pw = data.pop("password")
        if pw:
            server.password_enc = encrypt_secret(pw)
    if "url" in data and data["url"]:
        data["url"] = data["url"].rstrip("/")
    for key, value in data.items():
        setattr(server, key, value)
    session.add(server)
    session.commit()
    session.refresh(server)
    return server


@router.delete("/{server_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_server(server_id: int, _: RequireEditor, session: SessionDep):
    server = session.get(Server, server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    session.delete(server)
    session.commit()


@router.post("/{server_id}/import")
async def import_records(
    server_id: int,
    _: RequireEditor,
    session: SessionDep,
    scope: RecordScope = RecordScope.global_,
):
    """Pull a server's existing DNS rewrites into the admin DB as records.

    Useful when onboarding a server that already has rewrites: import them so the
    admin app becomes the source of truth without losing what's there. Existing
    records (same domain+answer+scope+zone) are skipped, so it's safe to re-run.
    """
    server = session.get(Server, server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    if scope == RecordScope.zone and server.zone_id is None:
        raise HTTPException(status_code=400, detail="Server has no zone; import as global instead")

    zone_id = server.zone_id if scope == RecordScope.zone else None
    client = AdGuardClient(server.url, server.username, decrypt_secret(server.password_enc), verify=verify_for(server.tls_cert))
    try:
        rewrites = await client.list_rewrites()
    except AdGuardError as exc:
        raise HTTPException(status_code=502, detail=f"Could not read records from server: {exc}")
    finally:
        await client.aclose()

    imported, skipped = 0, 0
    for rw in rewrites:
        domain = rw.domain.strip().lower()
        answer = rw.answer.strip()
        exists = session.exec(
            select(DNSRecord).where(
                DNSRecord.domain == domain,
                DNSRecord.answer == answer,
                DNSRecord.scope == scope,
                DNSRecord.zone_id == zone_id,
            )
        ).first()
        if exists:
            skipped += 1
            continue
        session.add(
            DNSRecord(
                domain=domain,
                answer=answer,
                scope=scope,
                zone_id=zone_id,
                description=f"Imported from {server.name}",
            )
        )
        imported += 1
    session.commit()
    return {"imported": imported, "skipped": skipped, "total": len(rewrites), "scope": scope.value}


@router.post("/{server_id}/test")
async def test_connection(server_id: int, _: CurrentUser, session: SessionDep):
    """Probe an AdGuard Home instance without changing anything."""
    server = session.get(Server, server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    client = AdGuardClient(server.url, server.username, decrypt_secret(server.password_enc), verify=verify_for(server.tls_cert))
    try:
        status_data = await client.status()
        rewrites = await client.list_rewrites()
        return {
            "ok": True,
            "version": status_data.get("version"),
            "running": status_data.get("running"),
            "rewrite_count": len(rewrites),
        }
    except AdGuardError as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        await client.aclose()
