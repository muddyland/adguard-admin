"""Diagnostic harness: measure event-loop responsiveness during a reconcile cycle.

Not part of the test suite — run it directly:
    python -m tests.repro_loop_lag
"""
from __future__ import annotations

import asyncio
import os
import statistics
import tempfile
import time

from cryptography.fernet import Fernet

_TMP = tempfile.mkdtemp(prefix="agh-repro-")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_TMP}/repro.db")
os.environ.setdefault("SECRET_KEY", "x" * 48)
os.environ.setdefault("FERNET_KEY", Fernet.generate_key().decode())
os.environ.setdefault("ADMIN_PASSWORD", "not-admin")
os.environ.setdefault("SYNC_INTERVAL_SECONDS", "3600")

from sqlmodel import Session  # noqa: E402

from app import sync as sync_mod  # noqa: E402
from app.config import settings  # noqa: E402
from app.database import engine, init_db  # noqa: E402
from app.models import DNSRecord, RecordScope, Server  # noqa: E402

N_SERVERS = int(os.environ.get("N_SERVERS", "5"))
RESPONSE_DELAY = float(os.environ.get("RESPONSE_DELAY", "0.4"))


class SlowClient:
    """An AdGuard instance that answers, but not instantly."""

    def __init__(self, *a, **k):
        pass

    async def _slow(self, value):
        await asyncio.sleep(RESPONSE_DELAY)
        return value

    async def status(self):
        return await self._slow({"version": "0.107.0", "running": True})

    async def version_check(self, recheck: bool = False):
        return await self._slow({"new_version": ""})

    async def list_rewrites(self):
        return await self._slow([])

    async def add_rewrite(self, r):
        return await self._slow(None)

    async def delete_rewrite(self, r):
        return await self._slow(None)

    async def dns_info(self):
        return await self._slow({})

    async def aclose(self):
        pass


async def ticker(stop: asyncio.Event, lags: list[float]) -> None:
    """Wake every 50ms and record how late we actually were.

    This is exactly what an inbound HTTP request experiences: if the loop is
    blocked by synchronous work, the request waits.
    """
    interval = 0.05
    while not stop.is_set():
        start = time.perf_counter()
        await asyncio.sleep(interval)
        lags.append((time.perf_counter() - start - interval) * 1000)


def seed() -> None:
    init_db()
    with Session(engine) as s:
        for i in range(N_SERVERS):
            s.add(Server(name=f"agh-{i}", url=f"https://agh-{i}.test:443"))
        for i in range(200):
            s.add(DNSRecord(domain=f"host-{i}.lan", answer=f"10.0.0.{i % 250}",
                            scope=RecordScope.global_, enabled=True))
        s.commit()


async def main() -> None:
    seed()
    sync_mod.AdGuardClient = SlowClient

    lags: list[float] = []
    stop = asyncio.Event()
    t = asyncio.create_task(ticker(stop, lags))

    began = time.perf_counter()
    results = await sync_mod.reconcile_all(force=True)
    elapsed = time.perf_counter() - began

    stop.set()
    await t

    lags_sorted = sorted(lags)
    p50 = statistics.median(lags_sorted)
    p99 = lags_sorted[int(len(lags_sorted) * 0.99)] if lags_sorted else 0
    print(f"servers            : {N_SERVERS} (per-call delay {RESPONSE_DELAY}s)")
    print(f"concurrency        : {settings.sync_max_concurrency}")
    print(f"cycle wall clock   : {elapsed:.2f}s  ({len(results)} results)")
    print(f"event-loop lag p50 : {p50:.1f} ms")
    print(f"event-loop lag p99 : {p99:.1f} ms")
    print(f"event-loop lag max : {max(lags_sorted):.1f} ms")


if __name__ == "__main__":
    asyncio.run(main())
