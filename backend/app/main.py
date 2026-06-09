import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session, func, select
from starlette.middleware.sessions import SessionMiddleware

from .config import settings
from .database import engine, init_db
from .deps import CurrentUser
from .models import DNSRecord, Role, Server, SyncStatus, User, Zone
from .routers import auth, provision, records, servers, sync, users, zones
from .security import hash_password
from .sync import sync_manager

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("adguard_admin")


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


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    bootstrap_admin()
    sync_manager.start()
    logger.info("AdGuard Admin started")
    yield
    await sync_manager.stop()


app = FastAPI(title=settings.app_name, lifespan=lifespan)

# SessionMiddleware is required by Authlib to hold OIDC state/nonce across the redirect.
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, https_only=False)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(zones.router)
app.include_router(servers.router)
app.include_router(records.router)
app.include_router(sync.router)
app.include_router(provision.router)


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
