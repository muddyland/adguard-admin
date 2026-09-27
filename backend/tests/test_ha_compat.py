"""The AdGuard-compatible /control API that Home Assistant talks to.

Two things are load-bearing here and easy to break by accident: the exact
response shapes python-adguardhome unpacks, and the fact that this is a second
authentication surface that must behave like the first one.
"""
from __future__ import annotations

import pytest
from sqlmodel import select

from app import fleet
from app.config import settings
from app.models import (
    ConfigScope,
    DNSRecord,
    FilterKind,
    FilterList,
    RecordScope,
    Role,
    Server,
)
from app.routers import ha_compat
from app.routers.ha_compat import cache as compat_cache
from conftest import make_user

PASSWORD = "pw-for-tests-123"


# --------------------------------------------------------------------------- #
# Fixtures & fakes
# --------------------------------------------------------------------------- #
class FakeAGH:
    """Stands in for one AdGuard Home box. Records every call it is asked to make."""

    def __init__(self, url, *_a, payloads=None, fail=None, calls=None, **_k):
        self.url = url
        self._payloads = payloads or {}
        self._fail = fail
        self.calls = calls if calls is not None else []

    def _answer(self, name):
        self.calls.append((self.url, name))
        if self._fail:
            raise self._fail
        return self._payloads.get(name, {})

    async def status(self):
        return self._answer("status")

    async def stats(self):
        return self._answer("stats")

    async def filtering_status(self):
        return self._answer("filtering_status")

    async def safety_status(self, service):
        return self._answer(f"{service}_status")

    async def querylog_info(self):
        return self._answer("querylog_info")

    async def set_protection(self, enabled, duration_ms=None):
        self.calls.append((self.url, f"set_protection={enabled}"))
        if self._fail:
            raise self._fail

    async def set_safety(self, service, enabled):
        self.calls.append((self.url, f"{service}={enabled}"))
        if self._fail:
            raise self._fail

    async def filtering_config(self, enabled, interval):
        self.calls.append((self.url, f"filtering_config={enabled},{interval}"))
        if self._fail:
            raise self._fail

    async def querylog_config(self, enabled, interval):
        self.calls.append((self.url, f"querylog_config={enabled},{interval}"))
        if self._fail:
            raise self._fail

    async def filtering_refresh(self, whitelist=False, force=False):
        self.calls.append((self.url, f"refresh(whitelist={whitelist},force={force})"))
        if self._fail:
            raise self._fail
        return {"updated": 2}

    async def aclose(self):
        pass


def install_fleet(monkeypatch, per_url: dict, fail_urls: tuple[str, ...] = ()):
    """Point the fan-out at fakes, and hand back the shared call log."""
    calls: list[tuple[str, str]] = []

    def factory(url, *a, **k):
        fail = RuntimeError("box is down") if any(f in url for f in fail_urls) else None
        return FakeAGH(url, payloads=per_url.get(url, {}), fail=fail, calls=calls)

    monkeypatch.setattr(fleet, "AdGuardClient", factory)
    return calls


def add_server(session, name, url, **kwargs):
    server = Server(name=name, url=url, **kwargs)
    session.add(server)
    session.commit()
    session.refresh(server)
    return server


@pytest.fixture(autouse=True)
def no_read_cache(monkeypatch):
    """Off by default so each test sees its own fan-out; the cache has its own test."""
    monkeypatch.setattr(settings, "ha_compat_cache_seconds", 0)


@pytest.fixture
def editor(session):
    return make_user(session, "ha-editor", Role.editor)


@pytest.fixture
def viewer(session):
    return make_user(session, "ha-viewer", Role.viewer)


@pytest.fixture
def ha(editor):
    return (editor.username, PASSWORD)


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #
def test_anonymous_gets_a_basic_challenge(client):
    """python-adguardhome only sends credentials when it is asked to."""
    resp = client.get("/control/status")
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == 'Basic realm="AdGuard Admin"'


def test_wrong_password_is_rejected(client, editor):
    assert client.get("/control/status", auth=(editor.username, "nope")).status_code == 401


def test_oidc_only_account_cannot_be_used(client, session):
    """No local password means nothing to check with Basic auth."""
    user = make_user(session, "sso-only", Role.admin, password=None, oidc_sub="sub-1")
    assert client.get("/control/status", auth=(user.username, "anything")).status_code == 401


def test_disabled_account_is_rejected_as_a_plain_401(client, session):
    """Same answer as a bad password: a distinct one is a password-testing oracle."""
    user = make_user(session, "retired", Role.admin, is_active=False)
    resp = client.get("/control/status", auth=(user.username, PASSWORD))
    assert resp.status_code == 401


def test_repeated_failures_are_throttled(client, editor):
    for _ in range(settings.login_max_attempts):
        client.get("/control/status", auth=(editor.username, "nope"))
    resp = client.get("/control/status", auth=(editor.username, "nope"))
    assert resp.status_code == 429
    assert int(resp.headers["retry-after"]) > 0


def test_throttling_does_not_lock_the_web_ui_out(client, editor):
    """The compat limiter is separate on purpose: a stale Home Assistant password
    polls every 30s, and a shared budget would take the UI down with it."""
    for _ in range(settings.login_max_attempts + 1):
        client.get("/control/status", auth=(editor.username, "nope"))
    resp = client.post(
        "/api/auth/token", data={"username": editor.username, "password": PASSWORD}
    )
    assert resp.status_code == 200


def test_disabled_by_configuration_is_a_404(client, ha, monkeypatch):
    monkeypatch.setattr(settings, "ha_compat_enabled", False)
    assert client.get("/control/status", auth=ha).status_code == 404


def test_viewer_may_read_but_not_write(client, viewer, monkeypatch, session):
    add_server(session, "agh-1", "http://10.0.0.2:3000")
    install_fleet(monkeypatch, {})
    creds = (viewer.username, PASSWORD)
    assert client.get("/control/status", auth=creds).status_code == 200
    resp = client.post("/control/protection", json={"enabled": True}, auth=creds)
    assert resp.status_code == 403


# --------------------------------------------------------------------------- #
# Aggregated reads
# --------------------------------------------------------------------------- #
def test_status_answers_with_no_servers_at_all(client, ha):
    """The config flow calls this first; a fresh install must not look broken."""
    resp = client.get("/control/status", auth=ha)
    assert resp.status_code == 200
    body = resp.json()
    assert body["protection_enabled"] is False
    assert body["servers_total"] == 0
    assert body["version"].startswith("AdGuard Admin")


def test_protection_is_on_only_when_every_server_agrees(client, ha, session, monkeypatch):
    add_server(session, "a", "http://10.0.0.2:3000")
    add_server(session, "b", "http://10.0.0.3:3000")
    install_fleet(monkeypatch, {
        "http://10.0.0.2:3000": {"status": {"protection_enabled": True}},
        "http://10.0.0.3:3000": {"status": {"protection_enabled": False}},
    })
    assert client.get("/control/status", auth=ha).json()["protection_enabled"] is False


def test_an_unreachable_server_does_not_vote(client, ha, session, monkeypatch):
    add_server(session, "a", "http://10.0.0.2:3000")
    add_server(session, "down", "http://10.0.0.9:3000")
    install_fleet(
        monkeypatch,
        {"http://10.0.0.2:3000": {"status": {"protection_enabled": True}}},
        fail_urls=("10.0.0.9",),
    )
    body = client.get("/control/status", auth=ha).json()
    assert body["protection_enabled"] is True
    assert (body["servers_total"], body["servers_reporting"]) == (2, 1)


def test_stats_are_summed_and_the_average_is_weighted(client, ha, session, monkeypatch):
    add_server(session, "busy", "http://10.0.0.2:3000")
    add_server(session, "quiet", "http://10.0.0.3:3000")
    install_fleet(monkeypatch, {
        "http://10.0.0.2:3000": {"stats": {
            "num_dns_queries": 900,
            "num_blocked_filtering": 100,
            "avg_processing_time": 0.01,
            "dns_queries": [1, 2, 3],
        }},
        "http://10.0.0.3:3000": {"stats": {
            "num_dns_queries": 100,
            "num_blocked_filtering": 10,
            "avg_processing_time": 0.1,
            "dns_queries": [10],
        }},
    })
    body = client.get("/control/stats", auth=ha).json()
    assert body["num_dns_queries"] == 1000
    assert body["num_blocked_filtering"] == 110
    # (0.01*900 + 0.1*100) / 1000 — not the flat mean of 0.055.
    assert body["avg_processing_time"] == pytest.approx(0.019)
    assert body["dns_queries"] == [11, 2, 3]


def test_stats_keep_adguards_own_top_list_shape(client, ha, session, monkeypatch):
    """The dashboard uses {"name", "count"}; a client here expects {domain: count}."""
    add_server(session, "a", "http://10.0.0.2:3000")
    add_server(session, "b", "http://10.0.0.3:3000")
    install_fleet(monkeypatch, {
        "http://10.0.0.2:3000": {"stats": {"top_clients": [{"10.0.0.50": 5}]}},
        "http://10.0.0.3:3000": {"stats": {"top_clients": [{"10.0.0.50": 7}]}},
    })
    assert client.get("/control/stats", auth=ha).json()["top_clients"] == [{"10.0.0.50": 12}]


def test_filter_lists_merge_by_url_without_multiplying_the_rule_count(
    client, ha, session, monkeypatch
):
    add_server(session, "a", "http://10.0.0.2:3000")
    add_server(session, "b", "http://10.0.0.3:3000")
    same = {"url": "https://lists.test/ads.txt", "name": "Ads", "rules_count": 50_000}
    install_fleet(monkeypatch, {
        "http://10.0.0.2:3000": {"filtering_status": {
            "enabled": True, "interval": 24, "filters": [{**same, "enabled": True}],
        }},
        "http://10.0.0.3:3000": {"filtering_status": {
            "enabled": True, "interval": 72, "filters": [{**same, "enabled": False}],
        }},
    })
    body = client.get("/control/filtering/status", auth=ha).json()
    assert len(body["filters"]) == 1
    merged = body["filters"][0]
    # 50k rules on two servers is still 50k rules, and "off on one box" is not "on".
    assert merged["rules_count"] == 50_000
    assert merged["enabled"] is False
    assert body["interval"] == 72


@pytest.mark.parametrize("service", ["safebrowsing", "parental", "safesearch"])
def test_safety_services_report_and_aggregate(client, ha, session, monkeypatch, service):
    add_server(session, "a", "http://10.0.0.2:3000")
    add_server(session, "b", "http://10.0.0.3:3000")
    install_fleet(monkeypatch, {
        "http://10.0.0.2:3000": {f"{service}_status": {"enabled": True}},
        "http://10.0.0.3:3000": {f"{service}_status": {"enabled": True}},
    })
    resp = client.get(f"/control/{service}/status", auth=ha)
    assert resp.status_code == 200
    assert resp.json() == {"enabled": True}


def test_reads_inside_the_cache_window_hit_the_fleet_once(
    client, ha, session, monkeypatch
):
    """Seven Home Assistant sensors read /control/stats in the same poll cycle."""
    monkeypatch.setattr(settings, "ha_compat_cache_seconds", 60)
    add_server(session, "a", "http://10.0.0.2:3000")
    calls = install_fleet(monkeypatch, {"http://10.0.0.2:3000": {"stats": {"num_dns_queries": 5}}})

    for _ in range(3):
        assert client.get("/control/stats", auth=ha).json()["num_dns_queries"] == 5
    assert [c for c in calls if c[1] == "stats"] == [("http://10.0.0.2:3000", "stats")]


def test_a_write_invalidates_the_cache(client, ha, session, monkeypatch):
    monkeypatch.setattr(settings, "ha_compat_cache_seconds", 60)
    add_server(session, "a", "http://10.0.0.2:3000")
    calls = install_fleet(monkeypatch, {
        "http://10.0.0.2:3000": {"status": {"protection_enabled": True}}
    })

    client.get("/control/status", auth=ha)
    client.post("/control/protection", json={"enabled": False}, auth=ha)
    client.get("/control/status", auth=ha)
    assert len([c for c in calls if c[1] == "status"]) == 2


# --------------------------------------------------------------------------- #
# Writes that fan out
# --------------------------------------------------------------------------- #
def test_protection_reaches_every_server(client, ha, session, monkeypatch):
    add_server(session, "a", "http://10.0.0.2:3000")
    add_server(session, "b", "http://10.0.0.3:3000")
    calls = install_fleet(monkeypatch, {})
    assert client.post("/control/protection", json={"enabled": False}, auth=ha).status_code == 200
    assert sorted(calls) == [
        ("http://10.0.0.2:3000", "set_protection=False"),
        ("http://10.0.0.3:3000", "set_protection=False"),
    ]


def test_one_unreachable_server_does_not_fail_the_toggle(client, ha, session, monkeypatch):
    add_server(session, "up", "http://10.0.0.2:3000")
    add_server(session, "down", "http://10.0.0.9:3000")
    install_fleet(monkeypatch, {}, fail_urls=("10.0.0.9",))
    assert client.post("/control/protection", json={"enabled": True}, auth=ha).status_code == 200


def test_a_toggle_that_reaches_nobody_is_a_502(client, ha, session, monkeypatch):
    add_server(session, "down", "http://10.0.0.9:3000")
    install_fleet(monkeypatch, {}, fail_urls=("10.0.0.9",))
    assert client.post("/control/protection", json={"enabled": True}, auth=ha).status_code == 502


def test_a_toggle_with_no_servers_in_scope_is_a_502(client, ha):
    """Better an error than a switch that silently flips and changes nothing."""
    resp = client.post("/control/protection", json={"enabled": True}, auth=ha)
    assert resp.status_code == 502
    assert "No enabled AdGuard servers" in resp.json()["detail"]


def test_protection_also_works_the_old_way_through_dns_config(
    client, ha, session, monkeypatch
):
    """python-adguardhome 0.8.1 — the version Home Assistant pins — toggles
    protection with POST /control/dns_config, not /control/protection. Only the
    library's unreleased successor uses the newer path, so both must work."""
    add_server(session, "a", "http://10.0.0.2:3000")
    calls = install_fleet(monkeypatch, {})
    resp = client.post("/control/dns_config", json={"protection_enabled": False}, auth=ha)
    assert resp.status_code == 200, resp.text
    assert calls == [("http://10.0.0.2:3000", "set_protection=False")]


def test_dns_config_refuses_settings_reconciliation_owns(client, ha, session, monkeypatch):
    """Taking an upstream write here would look like it worked until the next
    reconcile quietly reverted it."""
    add_server(session, "a", "http://10.0.0.2:3000")
    install_fleet(monkeypatch, {})
    resp = client.post(
        "/control/dns_config",
        json={"protection_enabled": False, "upstream_dns": ["1.1.1.1"]},
        auth=ha,
    )
    assert resp.status_code == 400
    assert "upstream_dns" in resp.json()["detail"]


def test_dns_config_needs_protection_enabled(client, ha):
    assert client.post("/control/dns_config", json={}, auth=ha).status_code == 400


def test_protection_takes_a_timed_disable(client, ha, session, monkeypatch):
    """The newer path carries a duration in milliseconds; it must reach the client."""
    add_server(session, "a", "http://10.0.0.2:3000")
    seen = {}

    class Recorder(FakeAGH):
        async def set_protection(self, enabled, duration_ms=None):
            seen["args"] = (enabled, duration_ms)

    monkeypatch.setattr(fleet, "AdGuardClient", lambda url, *a, **k: Recorder(url))
    resp = client.post(
        "/control/protection", json={"enabled": False, "duration": 60_000}, auth=ha
    )
    assert resp.status_code == 200, resp.text
    assert seen["args"] == (False, 60_000)


@pytest.mark.parametrize(
    "path,payload,expected",
    [
        ("/control/filtering/config", {"enabled": False, "interval": 24}, "filtering_config=False,24"),
        ("/control/querylog_config", {"enabled": True, "interval": 90}, "querylog_config=True,90.0"),
        ("/control/safebrowsing/enable", None, "safebrowsing=True"),
        ("/control/parental/disable", None, "parental=False"),
        ("/control/safesearch/enable", None, "safesearch=True"),
    ],
)
def test_the_remaining_switches_fan_out(
    client, ha, session, monkeypatch, path, payload, expected
):
    add_server(session, "a", "http://10.0.0.2:3000")
    calls = install_fleet(monkeypatch, {})
    resp = client.post(path, json=payload, auth=ha) if payload else client.post(path, auth=ha)
    assert resp.status_code == 200, resp.text
    assert ("http://10.0.0.2:3000", expected) in calls


def test_filter_refresh_sums_what_each_server_updated(client, ha, session, monkeypatch):
    add_server(session, "a", "http://10.0.0.2:3000")
    add_server(session, "b", "http://10.0.0.3:3000")
    calls = install_fleet(monkeypatch, {})
    resp = client.post("/control/filtering/refresh?force=true", json={"whitelist": False}, auth=ha)
    assert resp.status_code == 200
    assert resp.json() == {"updated": 4}
    assert ("http://10.0.0.2:3000", "refresh(whitelist=False,force=True)") in calls


# --------------------------------------------------------------------------- #
# Writes that land in the database (the source of truth)
# --------------------------------------------------------------------------- #
def test_add_url_records_a_global_filter_list(client, ha, session):
    """It must not go straight onto the servers: reconciliation owns that, and a
    server with prune on would delete anything written behind its back."""
    resp = client.post(
        "/control/filtering/add_url",
        json={"name": "Ads", "url": "https://lists.test/ads.txt"},
        auth=ha,
    )
    assert resp.status_code == 200, resp.text
    rows = session.exec(select(FilterList)).all()
    assert len(rows) == 1
    assert (rows[0].url, rows[0].kind, rows[0].scope, rows[0].enabled) == (
        "https://lists.test/ads.txt", FilterKind.blocklist, ConfigScope.global_, True,
    )


def test_add_url_honours_the_allowlist_flag(client, ha, session):
    client.post(
        "/control/filtering/add_url",
        json={"name": "Allow", "url": "https://lists.test/allow.txt", "whitelist": True},
        auth=ha,
    )
    assert session.exec(select(FilterList)).one().kind == FilterKind.allowlist


def test_add_url_refuses_a_duplicate(client, ha):
    body = {"name": "Ads", "url": "https://lists.test/ads.txt"}
    assert client.post("/control/filtering/add_url", json=body, auth=ha).status_code == 200
    assert client.post("/control/filtering/add_url", json=body, auth=ha).status_code == 400


def test_add_url_refuses_a_local_path(client, ha):
    """A path means something different on every server in a fleet."""
    resp = client.post(
        "/control/filtering/add_url", json={"name": "Local", "url": "/etc/hosts.txt"}, auth=ha
    )
    assert resp.status_code == 400


def test_remove_url_deletes_the_row_and_is_lenient_about_strangers(client, ha, session):
    client.post(
        "/control/filtering/add_url",
        json={"name": "Ads", "url": "https://lists.test/ads.txt"},
        auth=ha,
    )
    assert client.post(
        "/control/filtering/remove_url", json={"url": "https://lists.test/ads.txt"}, auth=ha
    ).status_code == 200
    assert session.exec(select(FilterList)).all() == []
    # AdGuard Home shrugs at an unknown URL here, so an idempotent retry works.
    assert client.post(
        "/control/filtering/remove_url", json={"url": "https://lists.test/gone.txt"}, auth=ha
    ).status_code == 200


def test_set_url_disables_a_list_it_knows(client, ha, session):
    url = "https://lists.test/ads.txt"
    client.post("/control/filtering/add_url", json={"name": "Ads", "url": url}, auth=ha)
    resp = client.post(
        "/control/filtering/set_url",
        json={"url": url, "data": {"enabled": False, "name": "Ads", "url": url}},
        auth=ha,
    )
    assert resp.status_code == 200, resp.text
    session.expire_all()
    assert session.exec(select(FilterList)).one().enabled is False


def test_set_url_on_an_unknown_list_is_a_404(client, ha):
    resp = client.post(
        "/control/filtering/set_url",
        json={"url": "https://lists.test/nope.txt", "data": {"enabled": True}},
        auth=ha,
    )
    assert resp.status_code == 404


def test_rewrites_round_trip_through_the_database(client, ha, session):
    resp = client.post(
        "/control/rewrite/add", json={"domain": "NAS.home.lan", "answer": "10.0.0.5"}, auth=ha
    )
    assert resp.status_code == 200, resp.text
    record = session.exec(select(DNSRecord)).one()
    assert (record.domain, record.answer, record.scope) == (
        "nas.home.lan", "10.0.0.5", RecordScope.global_,
    )
    assert client.get("/control/rewrite/list", auth=ha).json() == [
        {"domain": "nas.home.lan", "answer": "10.0.0.5"}
    ]
    assert client.post(
        "/control/rewrite/delete", json={"domain": "nas.home.lan", "answer": "10.0.0.5"}, auth=ha
    ).status_code == 200
    assert session.exec(select(DNSRecord)).all() == []


def test_an_auto_managed_rewrite_cannot_be_deleted(client, ha, session):
    session.add(DNSRecord(domain="agh-1.lan", answer="10.0.0.2", managed=True))
    session.commit()
    resp = client.post(
        "/control/rewrite/delete", json={"domain": "agh-1.lan", "answer": "10.0.0.2"}, auth=ha
    )
    assert resp.status_code == 409
    assert session.exec(select(DNSRecord)).one().managed is True


# --------------------------------------------------------------------------- #
# Scoped trees
# --------------------------------------------------------------------------- #
def test_a_zone_tree_only_touches_that_zones_servers(client, ha, session, monkeypatch, zone):
    add_server(session, "in-zone", "http://10.0.0.2:3000", zone_id=zone.id)
    add_server(session, "elsewhere", "http://10.0.0.3:3000")
    calls = install_fleet(monkeypatch, {})
    resp = client.post(
        f"/zone/{zone.slug}/control/protection", json={"enabled": False}, auth=ha
    )
    assert resp.status_code == 200
    assert calls == [("http://10.0.0.2:3000", "set_protection=False")]


def test_a_zone_tree_records_zone_scoped_filter_lists(client, ha, session, zone):
    resp = client.post(
        f"/zone/{zone.slug}/control/filtering/add_url",
        json={"name": "Ads", "url": "https://lists.test/ads.txt"},
        auth=ha,
    )
    assert resp.status_code == 200, resp.text
    row = session.exec(select(FilterList)).one()
    assert (row.scope, row.zone_ids) == (ConfigScope.zone, [zone.id])


def test_a_server_tree_narrows_to_one_box_by_name(client, ha, session, monkeypatch):
    add_server(session, "agh-1", "http://10.0.0.2:3000")
    add_server(session, "agh-2", "http://10.0.0.3:3000")
    calls = install_fleet(monkeypatch, {})
    resp = client.post("/server/agh-1/control/protection", json={"enabled": True}, auth=ha)
    assert resp.status_code == 200
    assert calls == [("http://10.0.0.2:3000", "set_protection=True")]


def test_an_unknown_scope_is_a_404(client, ha):
    assert client.get("/zone/nope/control/status", auth=ha).status_code == 404
    assert client.get("/server/nope/control/status", auth=ha).status_code == 404


def test_the_default_scope_can_be_configured(client, ha, session, monkeypatch, zone):
    """HA_COMPAT_SCOPE lets the bare /control tree mean one zone, which is the only
    way to narrow it: Home Assistant's config flow cannot set a base path."""
    add_server(session, "in-zone", "http://10.0.0.2:3000", zone_id=zone.id)
    add_server(session, "elsewhere", "http://10.0.0.3:3000")
    monkeypatch.setattr(settings, "ha_compat_scope", f"zone:{zone.slug}")
    calls = install_fleet(monkeypatch, {})
    assert client.post("/control/protection", json={"enabled": True}, auth=ha).status_code == 200
    assert calls == [("http://10.0.0.2:3000", "set_protection=True")]


# --------------------------------------------------------------------------- #
# Updates
# --------------------------------------------------------------------------- #
def test_version_json_returns_only_the_keys_the_client_can_unpack(client, ha):
    """python-adguardhome does AdGuardHomeAvailableUpdate(**response), so an extra
    key is a TypeError inside Home Assistant rather than an ignored field."""
    body = client.post("/control/version.json", auth=ha).json()
    assert set(body) <= {
        "disabled", "new_version", "announcement", "announcement_url", "can_autoupdate",
    }
    # "disabled" is what makes Home Assistant skip creating an update entity.
    assert body["disabled"] is True


def test_installing_an_update_is_not_offered_here(client, ha):
    resp = client.post("/control/update", auth=ha)
    assert resp.status_code == 501
    assert "one server at a time" in resp.json()["detail"]


# --------------------------------------------------------------------------- #
# Cache unit behaviour
# --------------------------------------------------------------------------- #
@pytest.mark.anyio
async def test_cache_collapses_concurrent_loads(monkeypatch, anyio_backend):
    """Home Assistant's entities update in parallel, so the misses arrive together."""
    import asyncio

    monkeypatch.setattr(settings, "ha_compat_cache_seconds", 60)
    compat_cache.clear()
    loads = 0

    async def loader():
        nonlocal loads
        loads += 1
        await asyncio.sleep(0.01)
        return loads

    results = await asyncio.gather(*(compat_cache.get("k", loader) for _ in range(5)))
    assert results == [1, 1, 1, 1, 1]
    assert loads == 1


def test_scope_parsing_rejects_nonsense():
    from app.config import parse_compat_scope

    assert parse_compat_scope("") == ("fleet", "")
    assert parse_compat_scope("fleet") == ("fleet", "")
    assert parse_compat_scope("zone:iot") == ("zone", "iot")
    assert parse_compat_scope("server:3") == ("server", "3")
    for bad in ["zone", "zone:", "nonsense:x", "cluster:a"]:
        with pytest.raises(ValueError):
            parse_compat_scope(bad)


def test_ha_compat_module_exposes_its_limiter_for_resetting():
    """conftest clears this between tests; a rename would silently leak lockouts."""
    assert hasattr(ha_compat, "compat_limiter")
