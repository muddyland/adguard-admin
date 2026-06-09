import re

from fastapi import APIRouter, HTTPException, status
from sqlmodel import select

from ..adguard_client import AdGuardClient, AdGuardError
from ..certs import verify_for
from ..deps import CurrentUser, RequireEditor, SessionDep
from ..models import ConfigScope, DNSRecord, ForwardZone, RecordScope, Server, Upstream, Zone
from ..schemas import ServerCreate, ServerRead, ServerUpdate
from ..security import decrypt_secret, encrypt_secret

router = APIRouter(prefix="/api/servers", tags=["servers"])

# Matches AdGuard's per-domain upstream syntax: [/domain1/domain2/]upstream
_FORWARD_RE = re.compile(r"^\[/(?P<domains>.+?)/\]\s*(?P<addrs>.+)$")


def _parse_upstreams(entries: list[str]) -> tuple[list[str], dict[tuple[str, ...], list[str]]]:
    """Split an upstream_dns list into plain upstreams and forward-zone groups."""
    plain: list[str] = []
    forwards: dict[tuple[str, ...], list[str]] = {}
    for raw in entries:
        line = (raw or "").strip()
        if not line or line.startswith("#"):
            continue
        m = _FORWARD_RE.match(line)
        if m:
            domains = tuple(d for d in m.group("domains").split("/") if d)
            for addr in m.group("addrs").split():
                forwards.setdefault(domains, [])
                if addr not in forwards[domains]:
                    forwards[domains].append(addr)
        else:
            for addr in line.split():
                if addr not in plain:
                    plain.append(addr)
    return plain, forwards


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
        manage_upstreams=payload.manage_upstreams,
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

    rec_zone_ids = [server.zone_id] if scope == RecordScope.zone else []
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
        candidates = session.exec(
            select(DNSRecord).where(
                DNSRecord.domain == domain,
                DNSRecord.answer == answer,
                DNSRecord.scope == scope,
            )
        ).all()
        # For zone scope, "exists" means an equivalent record already targets this zone.
        exists = any(
            scope != RecordScope.zone or server.zone_id in (r.zone_ids or [])
            for r in candidates
        )
        if exists:
            skipped += 1
            continue
        session.add(
            DNSRecord(
                domain=domain,
                answer=answer,
                scope=scope,
                zone_ids=rec_zone_ids,
                description=f"Imported from {server.name}",
            )
        )
        imported += 1
    session.commit()
    return {"imported": imported, "skipped": skipped, "total": len(rewrites), "scope": scope.value}


@router.post("/{server_id}/import-settings")
async def import_settings(
    server_id: int,
    _: RequireEditor,
    session: SessionDep,
    scope: ConfigScope = ConfigScope.global_,
):
    """Pull a server's existing upstream DNS config into the admin DB.

    Plain upstreams become Upstream rows; AdGuard per-domain entries
    ([/domain/]addr) are grouped into ForwardZone rows. Existing equivalents
    (same scope/target) are skipped, so it's safe to re-run.
    """
    server = session.get(Server, server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    if scope == ConfigScope.zone and server.zone_id is None:
        raise HTTPException(status_code=400, detail="Server has no zone; import as global or server scope")

    cfg_zone_ids = [server.zone_id] if scope == ConfigScope.zone else []
    target_server_id = server.id if scope == ConfigScope.server else None

    client = AdGuardClient(server.url, server.username, decrypt_secret(server.password_enc), verify=verify_for(server.tls_cert))
    try:
        info = await client.dns_info()
    except AdGuardError as exc:
        raise HTTPException(status_code=502, detail=f"Could not read settings from server: {exc}")
    finally:
        await client.aclose()

    plain, forwards = _parse_upstreams(info.get("upstream_dns") or [])
    up_imported = up_skipped = fz_imported = fz_skipped = 0

    def _zone_exists(row) -> bool:
        return scope != ConfigScope.zone or server.zone_id in (row.zone_ids or [])

    for addr in plain:
        candidates = session.exec(
            select(Upstream).where(
                Upstream.address == addr,
                Upstream.scope == scope,
                Upstream.server_id == target_server_id,
            )
        ).all()
        if any(_zone_exists(u) for u in candidates):
            up_skipped += 1
            continue
        session.add(Upstream(
            address=addr, scope=scope, zone_ids=cfg_zone_ids, server_id=target_server_id,
            description=f"Imported from {server.name}",
        ))
        up_imported += 1

    for domains, addrs in forwards.items():
        domains_str = " ".join(domains)
        candidates = session.exec(
            select(ForwardZone).where(
                ForwardZone.domains == domains_str,
                ForwardZone.scope == scope,
                ForwardZone.server_id == target_server_id,
            )
        ).all()
        if any(_zone_exists(f) for f in candidates):
            fz_skipped += 1
            continue
        session.add(ForwardZone(
            domains=domains_str, upstreams="\n".join(addrs), scope=scope,
            zone_ids=cfg_zone_ids, server_id=target_server_id,
            description=f"Imported from {server.name}",
        ))
        fz_imported += 1

    session.commit()
    return {
        "upstreams_imported": up_imported, "upstreams_skipped": up_skipped,
        "forward_zones_imported": fz_imported, "forward_zones_skipped": fz_skipped,
        "scope": scope.value,
    }


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
