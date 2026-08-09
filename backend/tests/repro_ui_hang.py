"""Diagnostic harness: can the API still be served while a reconcile cycle runs?

    python -m tests.repro_ui_hang
"""
from __future__ import annotations

import asyncio
import os
import tempfile
import time

from cryptography.fernet import Fernet

_TMP = tempfile.mkdtemp(prefix="agh-repro2-")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_TMP}/repro.db")
os.environ.setdefault("SECRET_KEY", "x" * 48)
os.environ.setdefault("FERNET_KEY", Fernet.generate_key().decode())
os.environ.setdefault("ADMIN_PASSWORD", "not-admin")
os.environ.setdefault("SYNC_INTERVAL_SECONDS", "3600")

from sqlmodel import Session  # noqa: E402

from app import sync as sync_mod  # noqa: E402
from app.config import settings  # noqa: E402
from app.database import engine, init_db  # noqa: E402
from app.models import Server  # noqa: E402
from app.sync import sync_manager  # noqa: E402

N_SERVERS = int(os.environ.get("N_SERVERS", "5"))
# Simulates an unreachable server: every call burns the full timeout.
STALL = float(os.environ.get("STALL", "10"))


class StallingClient:
    def __init__(self, *a, **k):
        pass

    async def status(self):
        await asyncio.sleep(STALL)
        from app.adguard_client import AdGuardError
        raise AdGuardError("GET /control/status failed: ")

    async def aclose(self):
        pass


def seed() -> None:
    init_db()
    with Session(engine) as s:
        for i in range(N_SERVERS):
            s.add(Server(name=f"agh-{i}", url=f"https://agh-{i}.test:443"))
        s.commit()


def pool_status() -> str:
    p = engine.pool
    return (f"size={p.size()} checkedout={p.checkedout()} "
            f"overflow={p.overflow()} class={type(p).__name__}")


async def probe_api(label: str, results: dict) -> None:
    """Stand-in for an inbound `GET /api/servers`: it needs a pooled connection."""
    began = time.perf_counter()
    def _query():
        with Session(engine) as s:
            return len(s.exec(__import__("sqlmodel").select(Server)).all())
    try:
        await asyncio.wait_for(asyncio.to_thread(_query), timeout=45)
        results[label] = (time.perf_counter() - began) * 1000
    except asyncio.TimeoutError:
        results[label] = float("inf")


async def main() -> None:
    seed()
    sync_mod.AdGuardClient = StallingClient
    print(f"servers={N_SERVERS} stall={STALL}s concurrency={settings.sync_max_concurrency}")
    print(f"pool before        : {pool_status()}")

    results: dict = {}

    async def watcher():
        await asyncio.sleep(2)
        print(f"pool mid-cycle     : {pool_status()}")
        await probe_api("api_during_cycle_ms", results)

    async def manual_sync():
        # What the UI does when you press "Sync now".
        await asyncio.sleep(2)
        began = time.perf_counter()
        await sync_manager.run_once(force=True)
        results["manual_sync_ms"] = (time.perf_counter() - began) * 1000

    began = time.perf_counter()
    await asyncio.gather(sync_manager.run_once(force=True), watcher(), manual_sync())
    total = (time.perf_counter() - began) * 1000

    print(f"pool after         : {pool_status()}")
    print()
    print(f"background cycle   : {total:.0f} ms")
    print(f"GET /api/servers   : {results.get('api_during_cycle_ms', -1):.0f} ms  "
          f"(during the cycle)")
    print(f"POST /api/sync/run : {results.get('manual_sync_ms', -1):.0f} ms  "
          f"(pressed 2s into the cycle)")


if __name__ == "__main__":
    asyncio.run(main())
