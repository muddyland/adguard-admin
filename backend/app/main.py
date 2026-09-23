import logging
import mimetypes
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlmodel import Session, func, select
from starlette.middleware.sessions import SessionMiddleware

from .config import config_problems, settings
from .database import engine, init_db
from .deps import CurrentUser
from .models import DNSRecord, Role, Server, SyncStatus, User, Zone
from .oidc import oidc_configured
from .routers import (
    auth,
    blocked_services,
    filters,
    forward_zones,
    metrics,
    provision,
    proxy,
    querylog,
    records,
    servers,
    sync,
    updates,
    upstreams,
    users,
    zones,
)
from .security import hash_password
from .sync import sync_manager
from .updater import update_manager

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("adguard_admin")

# Correct content types for the PWA static files.
mimetypes.add_type("application/manifest+json", ".webmanifest")
mimetypes.add_type("image/svg+xml", ".svg")


class InsecureConfiguration(RuntimeError):
    """Raised at startup when the app would run with unsafe defaults."""


def check_configuration() -> None:
    """Refuse to start with placeholder secrets or a wide-open CORS policy.

    Previously the app happily booted with the shipped SECRET_KEY, which lets
    anyone who has read the repository forge an admin token. Set
    ALLOW_INSECURE_CONFIG=true to downgrade these to warnings for local work.
    """
    problems = config_problems(settings)
    if not problems:
        return
    if settings.allow_insecure_config:
        for p in problems:
            logger.warning("INSECURE CONFIG (allowed by ALLOW_INSECURE_CONFIG): %s", p)
        return
    listing = "\n".join(f"  - {p}" for p in problems)
    raise InsecureConfiguration(
        f"Refusing to start with an insecure configuration:\n{listing}\n"
        "Fix these, or set ALLOW_INSECURE_CONFIG=true for local development only."
    )


def bootstrap_admin() -> None:
    with Session(engine) as session:
        if session.exec(select(User)).first() is None:
            admin = User(
                username=settings.admin_username,
                hashed_password=hash_password(settings.admin_password),
                role=Role.admin,
                is_active=True,
            )
            session.add(admin)
            session.commit()
            logger.warning(
                "Created bootstrap admin '%s' — change the password immediately.",
                settings.admin_username,
            )


def warn_about_ui_proxy_isolation() -> None:
    """Say plainly that the embedded UI is not origin-isolated.

    Sandboxing it into an opaque origin was tried and does not work: AdGuard
    Home's dashboard reads localStorage and document.cookie, both of which throw
    in an opaque origin, so its UI fails to start.
    """
    if not settings.ui_proxy_enabled:
        return
    logger.warning(
        "Embedded AdGuard UI proxy is ENABLED. AdGuard's own UI requires "
        "localStorage and document.cookie, so the frame must run same-origin: a "
        "compromised managed server could read this app's session token. Set "
        "UI_PROXY_ENABLED=false if you do not trust every managed server."
    )


def log_oidc_configuration() -> None:
    """Say what was negotiated, so a provider swap is diagnosable from the log."""
    if not oidc_configured():
        return
    logger.info(
        "OIDC enabled: issuer=%s client_id=%s pkce=%s scopes=%r label=%r",
        settings.oidc_issuer,
        settings.oidc_client_id,
        "S256" if settings.oidc_pkce else "off",
        settings.oidc_scopes,
        settings.oidc_button_label,
    )
    if settings.oidc_admin_group and "groups" not in settings.oidc_scopes.split():
        logger.warning(
            "OIDC_ADMIN_GROUP=%r is set but OIDC_SCOPES does not request 'groups'. "
            "Some providers (Kanidm) only emit the groups claim for that scope, and "
            "nobody will be promoted to admin. Others (Authentik) fold groups into "
            "'profile' and need no change.",
            settings.oidc_admin_group,
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    check_configuration()
    warn_about_ui_proxy_isolation()
    log_oidc_configuration()
    init_db()
    bootstrap_admin()
    sync_manager.start()
    update_manager.start()
    logger.info("AdGuard Admin started")
    yield
    await update_manager.stop()
    await sync_manager.stop()


app = FastAPI(title=settings.app_name, lifespan=lifespan)

# SessionMiddleware is required by Authlib to hold OIDC state/nonce across the redirect.
# It only ever holds transient OIDC state, so keep it short-lived and, when we're
# reachable over HTTPS, HTTPS-only.
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    session_cookie="adguard_admin_session",
    https_only=settings.secure_cookies,
    same_site="lax",
    max_age=600,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# The API is JSON-only and the SPA loads no third-party resources, so a strict
# policy costs nothing. The UI proxy needs its own rules (it renders a remote
# app's HTML), so it opts out here and is isolated by iframe sandboxing instead.
_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "form-action 'self'; "
    "base-uri 'none'; "
    "object-src 'none'"
)

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    is_proxy = bool(proxy.UI_PROXY_PATH_RE.match(request.url.path))

    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")

    if not is_proxy:
        # The proxied AdGuard UI must stay frameable by us and keeps its own
        # (stripped) headers; everything else gets the strict treatment.
        response.headers.setdefault("Content-Security-Policy", _CSP)
        response.headers.setdefault("X-Frame-Options", "DENY")

    if settings.secure_cookies:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return response


# Registered last, so it is the OUTERMOST middleware and runs before
# CORSMiddleware. The sandboxed UI-proxy iframe has an opaque origin and sends
# `Origin: null`, which CORSMiddleware would reject with a 400 before routing.
# Only the proxy prefix is handled here; the rest of /api keeps the strict
# app-wide policy.
@app.middleware("http")
async def ui_proxy_preflight(request: Request, call_next):
    if proxy.is_ui_proxy_preflight(request):
        return proxy.preflight_response(request)
    return await call_next(request)

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(zones.router)
app.include_router(servers.router)
app.include_router(records.router)
app.include_router(sync.router)
app.include_router(provision.router)
app.include_router(metrics.router)
app.include_router(upstreams.router)
app.include_router(forward_zones.router)
app.include_router(filters.router)
app.include_router(blocked_services.router)
app.include_router(proxy.router)
app.include_router(querylog.router)
app.include_router(updates.router)


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/stats")
def stats(_: CurrentUser):
    with Session(engine) as session:
        servers = session.exec(select(Server)).all()
        return {
            "zones": session.exec(select(func.count()).select_from(Zone)).one(),
            "servers": len(servers),
            "servers_online": sum(1 for s in servers if s.status == SyncStatus.online),
            "servers_in_sync": sum(1 for s in servers if s.in_sync),
            "records": session.exec(select(func.count()).select_from(DNSRecord)).one(),
            "records_global": session.exec(
                select(func.count()).select_from(DNSRecord).where(DNSRecord.scope == "global")
            ).one(),
            "users": session.exec(select(func.count()).select_from(User)).one(),
            "last_sync": sync_manager.last_run,
        }


# --------------------------------------------------------------------------- #
# Serve the built Vue SPA from the same container (single-image deployment).
# Mounted LAST so all /api routes and /docs take precedence. Only active when a
# built frontend is present (i.e. in the Docker image); in dev the SPA is served
# by Vite, so this is skipped and the API runs stand-alone.
# --------------------------------------------------------------------------- #
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

if STATIC_DIR.is_dir():
    assets_dir = STATIC_DIR / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    index_file = STATIC_DIR / "index.html"

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa(full_path: str):
        # Never let the catch-all swallow API/doc routes.
        if full_path.startswith(("api/", "docs", "redoc", "openapi.json")):
            raise HTTPException(status_code=404, detail="Not found")
        # Serve a real static file if it exists (favicon, etc.), guarding against
        # path traversal; otherwise fall back to index.html for client-side routes.
        candidate = (STATIC_DIR / full_path).resolve()
        if candidate.is_file() and candidate.is_relative_to(STATIC_DIR.resolve()):
            return FileResponse(candidate)
        return FileResponse(index_file)

else:
    logger.info("No static/ directory found — running API-only (frontend served separately).")
