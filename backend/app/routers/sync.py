from fastapi import APIRouter

from ..deps import CurrentUser, RequireEditor
from ..schemas import SyncResultRead
from ..sync import reconcile_all, sync_manager

router = APIRouter(prefix="/api/sync", tags=["sync"])


@router.get("/status")
def sync_status(_: CurrentUser):
    return {
        "last_run": sync_manager.last_run,
        "results": [r.__dict__ for r in sync_manager.last_results],
    }


@router.post("/run", response_model=list[SyncResultRead])
async def run_sync(_: RequireEditor, dry_run: bool = False):
    """Trigger an immediate reconcile of all enabled servers."""
    results = await reconcile_all(dry_run=dry_run)
    return [r.__dict__ for r in results]


@router.post("/run/{server_id}", response_model=list[SyncResultRead])
async def run_sync_server(server_id: int, _: RequireEditor, dry_run: bool = False):
    results = await reconcile_all(dry_run=dry_run, only_server_id=server_id)
    return [r.__dict__ for r in results]
