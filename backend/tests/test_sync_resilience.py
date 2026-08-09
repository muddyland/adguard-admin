"""T1/T2/T3/T6: one bad server must not stop the fleet, cycles must not race,
and shutdown must not block on slow servers."""
from __future__ import annotations

import asyncio
import ssl

import pytest
from sqlmodel import Session

from app import sync as sync_mod
from app.adguard_client import AdGuardError, Rewrite
from app.config import settings
from app.database import engine
from app.models import DNSRecord, RecordScope, Server, SyncStatus
from app.sync import SyncManager, reconcile_all, reconcile_server


class FakeClient:
    """Stands in for AdGuardClient. Records the calls the engine makes."""

    def __init__(self, *, version="0.107.0", rewrites=None, fail_with=None):
        self._version = version
        self._rewrites = list(rewrites or [])
        self._fail_with = fail_with
        self.added: list[Rewrite] = []
        self.deleted: list[Rewrite] = []
        self.closed = False

    async def status(self):
        if self._fail_with:
            raise self._fail_with
        return {"version": self._version, "running": True}

    async def version_check(self, recheck: bool = False):
        return {"new_version": ""}

    async def list_rewrites(self):
        return list(self._rewrites)

    async def add_rewrite(self, r):
        self.added.append(r)
        self._rewrites.append(r)

    async def delete_rewrite(self, r):
        self.deleted.append(r)

    async def dns_info(self):
        return {}

    async def filtering_status(self):
        return {"enabled": True, "filters": [], "whitelist_filters": []}

    async def aclose(self):
        self.closed = True


def _add_server(session, name, url="http://10.0.0.2:3000", **kw):
    s = Server(name=name, url=url, **kw)
    session.add(s)
    session.commit()
    session.refresh(s)
    return s


def _add_record(session, domain, answer="10.0.0.1"):
    r = DNSRecord(domain=domain, answer=answer, scope=RecordScope.global_, enabled=True)
    session.add(r)
    session.commit()
    return r


# --------------------------------------------------------------------------- #
# T1 — a server that cannot even be constructed must not abort the cycle
# --------------------------------------------------------------------------- #
@pytest.mark.anyio
async def test_unbuildable_client_does_not_abort_the_cycle(session, monkeypatch):
    """A malformed pinned cert used to raise ssl.SSLError *outside* the try, so
    it escaped reconcile_all and every server ordered after it stopped syncing."""
    broken = _add_server(session, "broken", tls_cert="-----BEGIN CERTIFICATE-----\nnope\n")
    healthy = _add_server(session, "healthy", url="http://10.0.0.3:3000")
    _add_record(session, "nas.home.lan")

    real_verify_for = sync_mod.verify_for

    def fake_verify_for(cert):
        if cert:
            raise ssl.SSLError("malformed PEM")
        return real_verify_for(cert)

    monkeypatch.setattr(sync_mod, "verify_for", fake_verify_for)
    fake = FakeClient()
    monkeypatch.setattr(sync_mod, "AdGuardClient", lambda *a, **k: fake)

    results = await reconcile_all(force=True)

    by_id = {r.server_id: r for r in results}
    assert set(by_id) == {broken.id, healthy.id}, "every server must be reported"
    assert by_id[broken.id].status == SyncStatus.error
    assert by_id[healthy.id].status == SyncStatus.online, "healthy server still reconciled"
    assert fake.added, "the healthy server received its record"


@pytest.mark.anyio
async def test_undecryptable_password_does_not_abort_the_cycle(session, monkeypatch):
    """The same shape of bug via decrypt_secret (raised on a malformed FERNET_KEY)."""
    broken = _add_server(session, "broken", password_enc="not-a-fernet-token")
    healthy = _add_server(session, "healthy", url="http://10.0.0.3:3000")

    def fake_decrypt(token):
        if token:
            raise ValueError("Fernet key must be 32 url-safe base64-encoded bytes")
        return None

    monkeypatch.setattr(sync_mod, "decrypt_secret", fake_decrypt)
    monkeypatch.setattr(sync_mod, "AdGuardClient", lambda *a, **k: FakeClient())

    results = await reconcile_all(force=True)
    by_id = {r.server_id: r for r in results}
    assert by_id[broken.id].status == SyncStatus.error
    assert by_id[healthy.id].status == SyncStatus.online


@pytest.mark.anyio
async def test_unexpected_exception_mid_reconcile_is_contained(session, monkeypatch):
    boom = _add_server(session, "boom")
    healthy = _add_server(session, "healthy", url="http://10.0.0.3:3000")

    class Exploding(FakeClient):
        async def status(self):
            raise RuntimeError("kaboom")

    def factory(url, *a, **k):
        return Exploding() if "10.0.0.2" in url else FakeClient()

    monkeypatch.setattr(sync_mod, "AdGuardClient", factory)

    results = await reconcile_all(force=True)
    by_id = {r.server_id: r for r in results}
    assert by_id[boom.id].status == SyncStatus.error
    assert by_id[healthy.id].status == SyncStatus.online


@pytest.mark.anyio
async def test_server_deleted_mid_cycle_is_skipped(session, monkeypatch):
    s = _add_server(session, "vanishing")
    monkeypatch.setattr(sync_mod, "AdGuardClient", lambda *a, **k: FakeClient())

    real = sync_mod._reconcile_one

    async def delete_then_reconcile(server_id, *, dry_run):
        with Session(engine) as inner:
            row = inner.get(Server, server_id)
            if row:
                inner.delete(row)
                inner.commit()
        return await real(server_id, dry_run=dry_run)

    monkeypatch.setattr(sync_mod, "_reconcile_one", delete_then_reconcile)
    results = await reconcile_all(force=True)
    assert results == []
    assert s.id is not None


# --------------------------------------------------------------------------- #
# T2 — bounded concurrency
# --------------------------------------------------------------------------- #
@pytest.mark.anyio
async def test_servers_reconcile_concurrently(session, monkeypatch):
    for i in range(6):
        _add_server(session, f"agh-{i}", url=f"http://10.0.1.{i}:3000")

    in_flight = 0
    peak = 0

    class SlowClient(FakeClient):
        async def status(self):
            nonlocal in_flight, peak
            in_flight += 1
            peak = max(peak, in_flight)
            try:
                await asyncio.sleep(0.05)
                return {"version": "0.107.0", "running": True}
            finally:
                in_flight -= 1

    monkeypatch.setattr(sync_mod, "AdGuardClient", lambda *a, **k: SlowClient())
    monkeypatch.setattr(settings, "sync_max_concurrency", 4)

    results = await reconcile_all(force=True)
    assert len(results) == 6
    assert peak > 1, "reconciliation is still strictly sequential"


@pytest.mark.anyio
async def test_concurrency_limit_is_respected(session, monkeypatch):
    for i in range(8):
        _add_server(session, f"agh-{i}", url=f"http://10.0.2.{i}:3000")

    in_flight = 0
    peak = 0

    class SlowClient(FakeClient):
        async def status(self):
            nonlocal in_flight, peak
            in_flight += 1
            peak = max(peak, in_flight)
            try:
                await asyncio.sleep(0.05)
                return {"version": "0.107.0", "running": True}
            finally:
                in_flight -= 1

    monkeypatch.setattr(sync_mod, "AdGuardClient", lambda *a, **k: SlowClient())
    monkeypatch.setattr(settings, "sync_max_concurrency", 3)

    await reconcile_all(force=True)
    assert peak <= 3, f"semaphore breached: {peak} concurrent"


# --------------------------------------------------------------------------- #
# T3 — the same server is never reconciled twice at once, but a slow fleet must
# not stall unrelated work. A single global lock satisfied the first and broke
# the second: "Sync now" queued behind every timing-out server in the fleet.
# --------------------------------------------------------------------------- #
@pytest.mark.anyio
async def test_same_server_is_never_reconciled_concurrently(session, monkeypatch):
    server = _add_server(session, "agh-1")

    in_flight = 0
    peak = 0

    class TrackingClient(FakeClient):
        async def status(self):
            nonlocal in_flight, peak
            in_flight += 1
            peak = max(peak, in_flight)
            try:
                await asyncio.sleep(0.05)
                return {"version": "0.107.0", "running": True}
            finally:
                in_flight -= 1

    monkeypatch.setattr(sync_mod, "AdGuardClient", lambda *a, **k: TrackingClient())

    await asyncio.gather(*(
        sync_mod._reconcile_one(server.id, dry_run=False) for _ in range(5)
    ))
    assert peak == 1, "the same server was reconciled concurrently"


@pytest.mark.anyio
async def test_busy_server_reports_instead_of_queueing(session, monkeypatch):
    server = _add_server(session, "agh-1")

    class SlowClient(FakeClient):
        async def status(self):
            await asyncio.sleep(0.3)
            return {"version": "0.107.0", "running": True}

    monkeypatch.setattr(sync_mod, "AdGuardClient", lambda *a, **k: SlowClient())

    first = asyncio.create_task(sync_mod._reconcile_one(server.id, dry_run=False))
    await asyncio.sleep(0.05)

    began = asyncio.get_running_loop().time()
    second = await sync_mod._reconcile_one(server.id, dry_run=False)
    waited = asyncio.get_running_loop().time() - began

    assert waited < 0.1, f"second pass queued for {waited:.2f}s instead of reporting"
    assert "already in progress" in (second.error or "")
    await first


@pytest.mark.anyio
async def test_manual_sync_does_not_queue_behind_a_stalled_fleet(session, monkeypatch):
    """The reported UI hang: pressing Sync now waited out every timing-out
    server in the fleet before responding."""
    slow_ids = [_add_server(session, f"slow-{i}", url=f"http://10.0.9.{i}:3000").id
                for i in range(6)]
    fast = _add_server(session, "fast", url="http://10.0.8.1:3000")

    class Client(FakeClient):
        def __init__(self, url):
            super().__init__()
            self._slow = "10.0.9." in url

        async def status(self):
            if self._slow:
                await asyncio.sleep(5)  # stands in for a connection timeout
            return {"version": "0.107.0", "running": True}

    monkeypatch.setattr(sync_mod, "AdGuardClient", lambda url, *a, **k: Client(url))
    monkeypatch.setattr(settings, "sync_max_concurrency", 8)

    manager = SyncManager()
    fleet = asyncio.create_task(manager.run_once(force=True))
    await asyncio.sleep(0.2)  # let the stalled servers get going

    began = asyncio.get_running_loop().time()
    results = await manager.run_once(only_server_id=fast.id, force=True)
    waited = asyncio.get_running_loop().time() - began

    assert waited < 1.0, f"manual single-server sync blocked for {waited:.2f}s"
    assert len(results) == 1 and results[0].server_id == fast.id

    await fleet
    assert len(slow_ids) == 6


@pytest.mark.anyio
async def test_periodic_cycle_skips_when_the_previous_one_overruns(session, monkeypatch):
    _add_server(session, "agh-1")

    starts = 0

    async def slow_reconcile_all(**kwargs):
        nonlocal starts
        starts += 1
        await asyncio.sleep(0.3)
        return []

    monkeypatch.setattr(sync_mod, "reconcile_all", slow_reconcile_all)
    manager = SyncManager()

    # Two ticks land while the first cycle is still running; they must be
    # dropped rather than queued up behind it.
    await asyncio.gather(*(manager._run_periodic_cycle() for _ in range(3)))
    assert starts == 1, f"overlapping ticks queued instead of being skipped ({starts})"


# --------------------------------------------------------------------------- #
# T6 — shutdown must be bounded
# --------------------------------------------------------------------------- #
@pytest.mark.anyio
async def test_stop_cancels_a_wedged_cycle():
    manager = SyncManager()
    manager.SHUTDOWN_GRACE_SECONDS = 0.1
    started = asyncio.Event()

    async def never_finishes(**kwargs):
        started.set()
        await asyncio.sleep(3600)

    original = sync_mod.reconcile_all
    sync_mod.reconcile_all = never_finishes
    try:
        manager.start()
        await asyncio.wait_for(started.wait(), timeout=2)
        await asyncio.wait_for(manager.stop(), timeout=2)
    finally:
        sync_mod.reconcile_all = original

    assert manager._task is None


@pytest.mark.anyio
async def test_stop_is_safe_when_never_started():
    await SyncManager().stop()


# --------------------------------------------------------------------------- #
# Reconcile correctness that must survive the refactor
# --------------------------------------------------------------------------- #
@pytest.mark.anyio
async def test_missing_rewrites_are_added(session, monkeypatch):
    server = _add_server(session, "agh-1")
    _add_record(session, "nas.home.lan", "10.0.0.10")

    fake = FakeClient()
    monkeypatch.setattr(sync_mod, "AdGuardClient", lambda *a, **k: fake)

    result = await reconcile_server(session, session.get(Server, server.id))
    assert result.status == SyncStatus.online
    assert [r.domain for r in fake.added] == ["nas.home.lan"]
    assert fake.closed


@pytest.mark.anyio
async def test_extra_rewrites_kept_unless_prune(session, monkeypatch):
    server = _add_server(session, "agh-1", prune=False)
    fake = FakeClient(rewrites=[Rewrite("stray.lan", "1.2.3.4")])
    monkeypatch.setattr(sync_mod, "AdGuardClient", lambda *a, **k: fake)

    await reconcile_server(session, session.get(Server, server.id))
    assert fake.deleted == []


@pytest.mark.anyio
async def test_extra_rewrites_pruned_when_enabled(session, monkeypatch):
    server = _add_server(session, "agh-1", prune=True)
    fake = FakeClient(rewrites=[Rewrite("stray.lan", "1.2.3.4")])
    monkeypatch.setattr(sync_mod, "AdGuardClient", lambda *a, **k: fake)

    await reconcile_server(session, session.get(Server, server.id))
    assert [r.domain for r in fake.deleted] == ["stray.lan"]


@pytest.mark.anyio
async def test_dry_run_changes_nothing(session, monkeypatch):
    server = _add_server(session, "agh-1")
    _add_record(session, "nas.home.lan")
    fake = FakeClient()
    monkeypatch.setattr(sync_mod, "AdGuardClient", lambda *a, **k: fake)

    result = await reconcile_server(session, session.get(Server, server.id), dry_run=True)
    assert result.added == ["nas.home.lan -> 10.0.0.1"]
    assert fake.added == []


@pytest.mark.anyio
async def test_auth_failure_sets_a_cooldown(session, monkeypatch):
    server = _add_server(session, "agh-1")
    fake = FakeClient(fail_with=AdGuardError("nope", status_code=401))
    monkeypatch.setattr(sync_mod, "AdGuardClient", lambda *a, **k: fake)

    result = await reconcile_server(session, session.get(Server, server.id))
    assert result.status == SyncStatus.error
    refreshed = session.get(Server, server.id)
    assert refreshed.cooldown_until is not None


@pytest.mark.anyio
async def test_cooldown_is_honoured_then_bypassed_by_force(session, monkeypatch):
    from datetime import datetime, timedelta, timezone

    server = _add_server(session, "agh-1")
    server.cooldown_until = datetime.now(timezone.utc) + timedelta(hours=1)
    session.add(server)
    session.commit()

    monkeypatch.setattr(sync_mod, "AdGuardClient", lambda *a, **k: FakeClient())

    assert await reconcile_all(force=False) == []
    assert len(await reconcile_all(force=True)) == 1


@pytest.mark.anyio
async def test_disabled_servers_are_skipped(session, monkeypatch):
    _add_server(session, "off", enabled=False)
    monkeypatch.setattr(sync_mod, "AdGuardClient", lambda *a, **k: FakeClient())
    assert await reconcile_all(force=True) == []


# --------------------------------------------------------------------------- #
# Database connections must not be held across network I/O. Holding one for the
# duration of every server's round-trips drained the pool once a few servers
# were slow, and API requests then blocked waiting for a free connection.
# --------------------------------------------------------------------------- #
@pytest.mark.anyio
async def test_no_db_connection_is_held_during_network_io(session, monkeypatch):
    for i in range(6):
        _add_server(session, f"agh-{i}", url=f"http://10.0.7.{i}:3000")
    _add_record(session, "nas.home.lan")

    peak_checked_out = 0

    class ObservingClient(FakeClient):
        async def status(self):
            nonlocal peak_checked_out
            # Sampled while every server is mid-request.
            peak_checked_out = max(peak_checked_out, engine.pool.checkedout())
            await asyncio.sleep(0.1)
            return {"version": "0.107.0", "running": True}

    monkeypatch.setattr(sync_mod, "AdGuardClient", lambda *a, **k: ObservingClient())
    monkeypatch.setattr(settings, "sync_max_concurrency", 6)

    session.commit()  # release this test's own connection
    results = await reconcile_all(force=True)

    assert len(results) == 6
    assert peak_checked_out == 0, (
        f"{peak_checked_out} pooled connection(s) held during network I/O"
    )


@pytest.mark.anyio
async def test_plan_is_snapshotted_before_the_network_phase(session, monkeypatch):
    """apply_plan must not touch the database, so a mid-flight edit can't half-apply."""
    server = _add_server(session, "agh-1", manage_upstreams=True, manage_filtering=True)
    _add_record(session, "nas.home.lan")

    plan = sync_mod.build_plan(session, session.get(Server, server.id))
    assert plan.rewrites
    assert set(plan.upstream_lists) == {
        "upstream_dns", "bootstrap_dns", "fallback_dns", "local_ptr_upstreams"
    }
    assert set(plan.filters) == {"filters", "whitelist_filters"}

    fake = FakeClient()
    monkeypatch.setattr(sync_mod, "AdGuardClient", lambda *a, **k: fake)

    checked_out_during = []
    orig = fake.list_rewrites

    async def watching_list():
        checked_out_during.append(engine.pool.checkedout())
        return await orig()

    fake.list_rewrites = watching_list
    session.commit()

    result, updates = await sync_mod.apply_plan(plan)
    assert result.status == SyncStatus.online
    assert updates.status == SyncStatus.online
    assert checked_out_during == [0]
