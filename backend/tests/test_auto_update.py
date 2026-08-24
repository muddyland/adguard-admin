"""Automatic AdGuard Home upgrades: eligibility, the upgrade itself, and the API.

The three things worth pinning down here are (1) that nothing is ever upgraded
without an explicit opt-in and inside its maintenance window, (2) that a box
which cannot upgrade itself is handed to the on-box updater instead of being
retried forever, and (3) that a restart which never completes is reported as a
failure rather than silently recorded as success.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app import updater as updater_mod
from app.adguard_client import AdGuardError
from app.config import Settings, config_problems, parse_window
from app.models import InstallMethod, Server, UpdateState
from app.security import encrypt_secret
from app.updater import (
    UpdateManager,
    in_maintenance_window,
    run_updates,
    skip_reason,
    update_server,
)

NOW = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)


class FakeClient:
    """Stands in for AdGuardClient during an upgrade.

    `versions` is the sequence /control/status returns on successive polls, so a
    test can model a box that restarts slowly, or never comes back at all.
    """

    def __init__(
        self,
        *,
        version="0.107.60",
        new_version="0.107.61",
        can_autoupdate=True,
        versions_after_update=None,
        update_error=None,
    ):
        self._version = version
        self._new_version = new_version
        self._can_autoupdate = can_autoupdate
        self._after = list(versions_after_update or [])
        self._update_error = update_error
        self.update_calls = 0
        self.closed = False

    async def version_check(self, recheck: bool = False):
        return {"new_version": self._new_version, "can_autoupdate": self._can_autoupdate}

    async def status(self):
        if self.update_calls and self._after:
            self._version = self._after.pop(0)
        return {"version": self._version, "running": True}

    async def update_now(self):
        self.update_calls += 1
        if self._update_error:
            raise self._update_error

    async def aclose(self):
        self.closed = True


@pytest.fixture
def no_sleep(monkeypatch):
    """Poll instantly; the loop's own deadline still governs how long it runs."""
    async def _sleep(_seconds):
        return None

    monkeypatch.setattr(updater_mod.asyncio, "sleep", _sleep)


def use_client(monkeypatch, client) -> None:
    monkeypatch.setattr(updater_mod, "AdGuardClient", lambda *a, **kw: client)


def make_server(session, **kw) -> Server:
    defaults = dict(
        name="agh-1",
        url="http://10.0.0.2:3000",
        username="admin",
        password_enc=encrypt_secret("pw"),
        enabled=True,
        auto_update=True,
        version="0.107.60",
        latest_version="0.107.61",
        update_available=True,
    )
    defaults.update(kw)
    server = Server(**defaults)
    session.add(server)
    session.commit()
    session.refresh(server)
    return server


# --------------------------------------------------------------------------- #
# Maintenance window
# --------------------------------------------------------------------------- #
def test_empty_window_means_any_time():
    assert parse_window("") is None
    assert in_maintenance_window(NOW, "") is True


@pytest.mark.parametrize(
    "hour,window,expected",
    [
        (3, "02:00-05:00", True),
        (1, "02:00-05:00", False),
        (5, "02:00-05:00", False),   # end is exclusive
        (2, "02:00-05:00", True),    # start is inclusive
        (23, "23:00-02:00", True),   # wraps midnight
        (1, "23:00-02:00", True),
        (12, "23:00-02:00", False),
    ],
)
def test_window_boundaries(hour, window, expected):
    when = NOW.replace(hour=hour, minute=0)
    assert in_maintenance_window(when, window) is expected


def test_malformed_window_refuses_to_update_rather_than_guessing():
    # Startup rejects this, so reaching it means something is badly wrong; the
    # safe reading is "not now", never "any time".
    assert in_maintenance_window(NOW, "not-a-window") is False


@pytest.mark.parametrize("bad", ["25:00-02:00", "02:00", "02:00-02:00", "2-3"])
def test_startup_rejects_a_malformed_window(bad):
    settings = Settings(
        secret_key="k" * 40,
        fernet_key="",  # unrelated problem; we only assert on the window one
        admin_password="not-admin",
        auto_update_window=bad,
    )
    problems = config_problems(settings)
    assert any("AUTO_UPDATE_WINDOW" in p for p in problems), problems


def test_startup_accepts_a_valid_window():
    settings = Settings(secret_key="k" * 40, admin_password="not-admin",
                        auto_update_window="03:00-05:00")
    assert not [p for p in config_problems(settings) if "AUTO_UPDATE_WINDOW" in p]


# --------------------------------------------------------------------------- #
# Eligibility
# --------------------------------------------------------------------------- #
def test_server_with_an_update_and_the_flag_set_is_due(session):
    assert skip_reason(make_server(session), NOW) is None


def test_opt_in_is_required(session):
    reason = skip_reason(make_server(session, auto_update=False), NOW)
    assert reason and "automatic updates are off" in reason


def test_disabled_server_is_never_updated(session):
    reason = skip_reason(make_server(session, enabled=False), NOW)
    assert reason and "disabled" in reason


def test_up_to_date_server_is_skipped(session):
    reason = skip_reason(
        make_server(session, update_available=False, latest_version=None), NOW
    )
    assert reason and "latest version" in reason


def test_auth_cooldown_is_honoured(session):
    """An upgrade means more authenticated calls — exactly what a lockout wants less of."""
    server = make_server(session, cooldown_until=NOW + timedelta(minutes=10))
    reason = skip_reason(server, NOW)
    assert reason and "cooldown" in reason


def test_delegated_server_is_not_retried_for_the_same_version(session):
    server = make_server(
        session,
        update_state=UpdateState.delegated,
        update_attempted_version="0.107.61",
        update_attempted_at=NOW - timedelta(days=30),
        install_method=InstallMethod.docker,
    )
    reason = skip_reason(server, NOW)
    assert reason and "on-box updater" in reason


def test_delegated_server_is_reconsidered_for_a_newer_version(session):
    server = make_server(
        session,
        latest_version="0.107.62",          # a newer release than the delegated one
        update_state=UpdateState.delegated,
        update_attempted_version="0.107.61",
        update_attempted_at=NOW - timedelta(days=30),
    )
    assert skip_reason(server, NOW) is None


def test_failed_attempt_backs_off_then_retries(session):
    server = make_server(
        session,
        update_state=UpdateState.failed,
        update_attempted_version="0.107.61",
        update_attempted_at=NOW - timedelta(minutes=5),
    )
    reason = skip_reason(server, NOW)
    assert reason and "last attempt failed" in reason
    # ...and once the backoff has elapsed it is due again.
    assert skip_reason(server, NOW + timedelta(hours=24)) is None


def test_due_ids_respect_the_window(session, monkeypatch):
    make_server(session)
    monkeypatch.setattr(updater_mod.settings, "auto_update_window", "03:00-04:00")
    monkeypatch.setattr(updater_mod, "in_maintenance_window", lambda *a, **kw: False)
    assert updater_mod.due_server_ids() == []
    # A human pressing "Update now" is not bound by the window.
    assert updater_mod.due_server_ids(force=True) != []


# --------------------------------------------------------------------------- #
# The upgrade itself
# --------------------------------------------------------------------------- #
@pytest.mark.anyio
async def test_successful_upgrade_records_the_new_version(session, monkeypatch, no_sleep):
    server = make_server(session)
    client = FakeClient(versions_after_update=["0.107.61"])
    use_client(monkeypatch, client)

    outcome = await update_server(server.id)

    assert outcome.state == UpdateState.succeeded
    assert outcome.to_version == "0.107.61"
    assert client.update_calls == 1
    assert client.closed is True

    session.refresh(server)
    assert server.version == "0.107.61"
    assert server.update_state == UpdateState.succeeded
    assert server.update_error is None
    # Don't leave a stale "update available" badge behind after installing it.
    assert server.update_available is False


@pytest.mark.anyio
async def test_a_container_is_delegated_not_retried(session, monkeypatch, no_sleep):
    """A container cannot replace its own image, so this app must not try."""
    server = make_server(session, install_method=InstallMethod.docker)
    client = FakeClient(can_autoupdate=False)
    use_client(monkeypatch, client)

    outcome = await update_server(server.id)

    assert outcome.state == UpdateState.delegated
    assert client.update_calls == 0
    assert "on-box updater" in outcome.message

    session.refresh(server)
    assert server.update_state == UpdateState.delegated
    assert server.update_attempted_version == "0.107.61"


@pytest.mark.anyio
async def test_server_that_never_comes_back_is_a_failure(session, monkeypatch, no_sleep):
    server = make_server(session)
    # Reports the same version forever: the restart never completed.
    client = FakeClient(versions_after_update=[])
    use_client(monkeypatch, client)
    monkeypatch.setattr(updater_mod.settings, "auto_update_restart_timeout_seconds", 0.05)

    outcome = await update_server(server.id)

    assert outcome.state == UpdateState.failed
    assert "did not come back" in outcome.message
    session.refresh(server)
    assert server.update_state == UpdateState.failed
    assert server.update_error


@pytest.mark.anyio
async def test_connection_dropping_mid_update_is_expected_not_an_error(
    session, monkeypatch, no_sleep
):
    """AdGuard restarts while answering POST /control/update, so the reply is lost."""
    server = make_server(session)
    client = FakeClient(
        versions_after_update=["0.107.61"],
        update_error=AdGuardError("connection dropped"),  # no status_code
    )
    use_client(monkeypatch, client)

    outcome = await update_server(server.id)
    assert outcome.state == UpdateState.succeeded


@pytest.mark.anyio
async def test_refused_update_request_is_a_failure(session, monkeypatch, no_sleep):
    """An HTTP status, unlike a dropped connection, means it never started."""
    server = make_server(session)
    client = FakeClient(
        versions_after_update=["0.107.61"],
        update_error=AdGuardError("forbidden", status_code=403),
    )
    use_client(monkeypatch, client)

    outcome = await update_server(server.id)
    assert outcome.state == UpdateState.failed
    session.refresh(server)
    assert server.update_state == UpdateState.failed


@pytest.mark.anyio
async def test_nothing_to_install_is_not_an_attempt(session, monkeypatch, no_sleep):
    server = make_server(session)
    client = FakeClient(new_version="")
    use_client(monkeypatch, client)

    outcome = await update_server(server.id)
    assert outcome.state == UpdateState.idle
    assert client.update_calls == 0


@pytest.mark.anyio
async def test_a_server_being_reconciled_is_left_alone(session, monkeypatch, no_sleep):
    """Restarting a box mid-reconcile would fail the sync that is talking to it."""
    server = make_server(session)
    client = FakeClient()
    use_client(monkeypatch, client)

    from app.sync import lock_for

    async with lock_for(server.id):
        outcome = await update_server(server.id)

    assert outcome.state == UpdateState.idle
    assert client.update_calls == 0


@pytest.mark.anyio
async def test_master_switch_off_stops_every_upgrade(session, monkeypatch, no_sleep):
    make_server(session)
    monkeypatch.setattr(updater_mod.settings, "auto_update_enabled", False)
    assert await run_updates() == []


@pytest.mark.anyio
async def test_run_updates_skips_servers_that_did_not_opt_in(session, monkeypatch, no_sleep):
    make_server(session, name="opted-out", auto_update=False)
    client = FakeClient()
    use_client(monkeypatch, client)
    assert await run_updates() == []
    assert client.update_calls == 0


@pytest.mark.anyio
async def test_one_failing_server_does_not_stop_the_pass(session, monkeypatch, no_sleep):
    good = make_server(session, name="good")
    bad = make_server(session, name="bad")

    clients = {
        good.id: FakeClient(versions_after_update=["0.107.61"]),
        bad.id: FakeClient(update_error=AdGuardError("nope", status_code=500)),
    }
    calls = iter([clients[good.id], clients[bad.id]])
    monkeypatch.setattr(updater_mod, "AdGuardClient", lambda *a, **kw: next(calls))
    monkeypatch.setattr(updater_mod.settings, "auto_update_restart_timeout_seconds", 0.05)

    outcomes = await run_updates()
    assert len(outcomes) == 2
    assert {o.state for o in outcomes} == {UpdateState.succeeded, UpdateState.failed}


@pytest.mark.anyio
async def test_manager_stop_is_safe_when_never_started():
    await UpdateManager().stop()  # must not raise


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
def test_overview_requires_authentication(client):
    assert client.get("/api/updates").status_code == 401


def test_viewer_can_read_the_overview(client, viewer_headers, session):
    make_server(session)
    resp = client.get("/api/updates", headers=viewer_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["servers"][0]["auto_update"] is True
    assert body["servers"][0]["skip_reason"] is None
    assert body["enabled"] is True
    assert "docker-agent.sh" in body["docker_agent_command"]


def test_viewer_cannot_trigger_updates(client, viewer_headers, session):
    server = make_server(session)
    assert client.post("/api/updates/run", headers=viewer_headers).status_code == 403
    assert client.post(f"/api/updates/{server.id}/run", headers=viewer_headers).status_code == 403
    assert client.post("/api/updates/check", headers=viewer_headers).status_code == 403


def test_updating_an_unknown_server_is_404(client, editor_headers):
    assert client.post("/api/updates/999/run", headers=editor_headers).status_code == 404


def test_updating_a_server_with_nothing_to_install_is_409(client, editor_headers, session):
    server = make_server(session, update_available=False, latest_version=None)
    resp = client.post(f"/api/updates/{server.id}/run", headers=editor_headers)
    assert resp.status_code == 409


def test_editor_can_update_one_server(client, editor_headers, session, monkeypatch, no_sleep):
    server = make_server(session)
    use_client(monkeypatch, FakeClient(versions_after_update=["0.107.61"]))
    resp = client.post(f"/api/updates/{server.id}/run", headers=editor_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "succeeded"
    assert resp.json()["to_version"] == "0.107.61"


def test_forced_run_ignores_the_window(client, editor_headers, session, monkeypatch, no_sleep):
    make_server(session)
    monkeypatch.setattr(updater_mod, "in_maintenance_window", lambda *a, **kw: False)
    use_client(monkeypatch, FakeClient(versions_after_update=["0.107.61"]))

    assert client.post("/api/updates/run", headers=editor_headers).json() == []
    forced = client.post("/api/updates/run?force=true", headers=editor_headers).json()
    assert [o["state"] for o in forced] == ["succeeded"]


def test_check_refreshes_the_cached_version_view(client, editor_headers, session, monkeypatch):
    server = make_server(session, latest_version=None, update_available=False)
    use_client(monkeypatch, FakeClient(new_version="0.107.99"))
    # The router builds its own client, so patch the one it imports.
    import app.routers.updates as updates_router
    monkeypatch.setattr(updates_router, "AdGuardClient", lambda *a, **kw: FakeClient(new_version="0.107.99"))

    resp = client.post("/api/updates/check", headers=editor_headers)
    assert resp.status_code == 200
    assert resp.json()[0]["latest_version"] == "0.107.99"
    session.refresh(server)
    assert server.update_available is True


def test_check_survives_an_unreachable_server(client, editor_headers, session, monkeypatch):
    make_server(session)
    import app.routers.updates as updates_router

    class Dead:
        async def version_check(self, recheck: bool = False):
            raise AdGuardError("offline")

        async def aclose(self):
            return None

    monkeypatch.setattr(updates_router, "AdGuardClient", lambda *a, **kw: Dead())
    resp = client.post("/api/updates/check", headers=editor_headers)
    assert resp.status_code == 200
    assert resp.json()[0]["update_available"] is False


# --------------------------------------------------------------------------- #
# The on-box updater script
# --------------------------------------------------------------------------- #
def test_docker_agent_script_is_public_and_secretless(client):
    """It is fetched by `curl | bash` on a box that holds no credentials."""
    resp = client.get("/api/updates/docker-agent.sh")
    assert resp.status_code == 200
    assert resp.text.startswith("#!/usr/bin/env bash")
    assert "adguard-home-update" in resp.text
    # Nothing installation-specific, so it can be cached and shared freely.
    for secret in ("FERNET", "SECRET_KEY", "Authorization", "password"):
        assert secret not in resp.text


def test_docker_agent_script_rolls_back_and_keeps_volumes():
    from app.update_agent import render_agent_script

    script = render_agent_script()
    assert "rollback" in script
    # Recreating must reuse the container's mounts, never re-declare storage.
    assert "docker rename" in script
    assert "docker compose up -d" in script  # compose-managed boxes stay with compose


# --------------------------------------------------------------------------- #
# Provisioning carries the choice through to the box and the Server record
# --------------------------------------------------------------------------- #
def _create_token(client, headers, **overrides):
    payload = {"name": "edge-1", "method": "docker"}
    payload.update(overrides)
    return client.post("/api/provision/tokens", json=payload, headers=headers)


def test_provisioned_docker_box_installs_the_on_box_updater(client, editor_headers):
    token = _create_token(client, editor_headers, auto_update=True).json()
    assert token["auto_update"] is True

    config = client.get(f"/api/provision/{token['token']}/config").text
    assert "AUTO_UPDATE=true" in config

    script = client.get(f"/api/provision/{token['token']}/install.sh").text
    assert "/api/updates/docker-agent.sh" in script


def test_provisioning_without_auto_update_installs_nothing_extra(client, editor_headers):
    token = _create_token(client, editor_headers).json()
    assert token["auto_update"] is False
    assert "AUTO_UPDATE=false" in client.get(f"/api/provision/{token['token']}/config").text


def test_completed_provisioning_records_how_the_box_was_installed(
    client, editor_headers, session
):
    """install_method is what decides who performs later upgrades."""
    token = _create_token(client, editor_headers, auto_update=True, method="bare_metal").json()
    resp = client.post(
        f"/api/provision/{token['token']}/complete", json={"address": "10.0.0.9"}
    )
    assert resp.status_code == 200

    server = session.get(Server, resp.json()["server_id"])
    assert server.auto_update is True
    assert server.install_method == InstallMethod.bare_metal


def test_auto_update_default_applies_to_new_servers(client, editor_headers, monkeypatch):
    import app.routers.servers as servers_router

    monkeypatch.setattr(servers_router.settings, "auto_update_default", True)
    created = client.post(
        "/api/servers",
        json={"name": "new-box", "url": "http://10.0.0.3:3000"},
        headers=editor_headers,
    ).json()
    assert created["auto_update"] is True


def test_explicit_choice_beats_the_default(client, editor_headers, monkeypatch):
    import app.routers.servers as servers_router

    monkeypatch.setattr(servers_router.settings, "auto_update_default", True)
    created = client.post(
        "/api/servers",
        json={"name": "opted-out", "url": "http://10.0.0.4:3000", "auto_update": False},
        headers=editor_headers,
    ).json()
    assert created["auto_update"] is False


def test_auto_update_can_be_toggled_per_server(client, editor_headers, session):
    server = make_server(session, auto_update=False)
    resp = client.patch(
        f"/api/servers/{server.id}",
        json={"auto_update": True, "install_method": "docker"},
        headers=editor_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["auto_update"] is True
    assert resp.json()["install_method"] == "docker"


# --------------------------------------------------------------------------- #
# A server whose own update check is off is not the same as an up-to-date one
# --------------------------------------------------------------------------- #
class ChecksOff(FakeClient):
    """A server whose version check is off: AdGuard answers {"disabled": true}."""

    async def version_check(self, recheck: bool = False):
        return {"new_version": None, "can_autoupdate": None, "disabled": True}


@pytest.mark.anyio
async def test_disabled_update_check_is_reported_not_mistaken_for_current(
    session, monkeypatch, no_sleep
):
    server = make_server(session, update_check_disabled=True)
    use_client(monkeypatch, ChecksOff())

    outcome = await update_server(server.id)

    assert outcome.state == UpdateState.idle
    assert "update check is switched off" in outcome.message
    assert "Already on the latest version" not in outcome.message
    session.refresh(server)
    # Nothing went wrong, so the row must not show a red error.
    assert server.update_error is None


@pytest.mark.anyio
async def test_docker_is_not_told_to_flip_a_switch_it_does_not_have(
    session, monkeypatch, no_sleep
):
    """The official image bakes --no-check-update into its command.

    That flag overrides `check_update` in the config, so the setting is absent
    from the container's UI and cannot be turned on there at all. Advising it
    sends operators looking for a control that does not exist; for a container
    the disabled check is the expected state and the on-box updater is the
    answer.
    """
    server = make_server(session, install_method=InstallMethod.docker,
                         update_check_disabled=True)
    use_client(monkeypatch, ChecksOff())

    outcome = await update_server(server.id)

    assert outcome.state == UpdateState.idle
    assert "on-box updater" in outcome.message
    assert "Automatically check for updates" not in outcome.message
    assert "Settings" not in outcome.message


def test_skip_reason_names_a_disabled_update_check(session):
    server = make_server(
        session, update_available=False, latest_version=None, update_check_disabled=True
    )
    reason = skip_reason(server, NOW)
    assert reason and "update check is switched off" in reason


def test_skip_reason_for_docker_points_at_the_on_box_updater(session):
    server = make_server(
        session, update_available=False, latest_version=None,
        update_check_disabled=True, install_method=InstallMethod.docker,
    )
    reason = skip_reason(server, NOW)
    assert reason and "on-box updater" in reason
    assert "Settings" not in reason


def test_check_records_a_disabled_update_check(client, editor_headers, session, monkeypatch):
    server = make_server(session, update_available=False, latest_version=None)
    import app.routers.updates as updates_router

    class ChecksOff:
        async def version_check(self, recheck: bool = False):
            return {"new_version": None, "disabled": True}

        async def aclose(self):
            return None

    monkeypatch.setattr(updates_router, "AdGuardClient", lambda *a, **kw: ChecksOff())
    resp = client.post("/api/updates/check", headers=editor_headers)
    assert resp.status_code == 200
    assert resp.json()[0]["update_check_disabled"] is True
    session.refresh(server)
    assert server.update_check_disabled is True


@pytest.mark.anyio
async def test_a_docker_server_is_delegated_even_if_it_claims_otherwise(
    session, monkeypatch, no_sleep
):
    """AdGuard <=0.107.60 answers can_autoupdate: true inside Docker, then 500s.

    Knowing it is a container is a stronger signal than what it reports, so the
    upgrade is never attempted and no failed attempt is recorded.
    """
    server = make_server(session, install_method=InstallMethod.docker)
    client = FakeClient(can_autoupdate=True)
    use_client(monkeypatch, client)

    outcome = await update_server(server.id)

    assert outcome.state == UpdateState.delegated
    assert client.update_calls == 0


@pytest.mark.anyio
async def test_a_refused_upgrade_explains_itself(session, monkeypatch, no_sleep):
    server = make_server(session)  # install method unknown
    use_client(monkeypatch, FakeClient(update_error=AdGuardError("boom", status_code=500)))

    outcome = await update_server(server.id)
    assert outcome.state == UpdateState.failed
    assert "refused to upgrade itself" in outcome.message
    assert "install method" in outcome.message
