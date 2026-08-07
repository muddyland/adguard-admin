"""T1/T9/T10: the dashboard and query log must survive one misbehaving server."""
from __future__ import annotations

import pytest

from app.models import Server
from app.routers import metrics as metrics_mod
from app.routers import querylog as querylog_mod
from app.routers.metrics import _as_number, _merge_top
from app.routers.querylog import _parse_time


def _add_server(session, name, url):
    s = Server(name=name, url=url)
    session.add(s)
    session.commit()
    session.refresh(s)
    return s


class StatsClient:
    def __init__(self, stats=None, raise_on_init=None, raise_on_call=None):
        if raise_on_init:
            raise raise_on_init
        self._stats = stats or {}
        self._raise = raise_on_call

    async def stats(self):
        if self._raise:
            raise self._raise
        return self._stats

    async def query_log(self, params):
        if self._raise:
            raise self._raise
        return self._stats

    async def aclose(self):
        pass


# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #
def test_metrics_survives_a_server_whose_client_cannot_be_built(
    client, admin_headers, session, monkeypatch
):
    """Client construction used to sit outside the try, so one bad pinned cert
    turned the whole dashboard into a 500."""
    _add_server(session, "broken", "http://10.0.0.2:3000")
    _add_server(session, "healthy", "http://10.0.0.3:3000")

    def factory(url, *a, **k):
        if "10.0.0.2" in url:
            raise ValueError("malformed pinned certificate")
        return StatsClient({"num_dns_queries": 10, "num_blocked_filtering": 4})

    monkeypatch.setattr(metrics_mod, "AdGuardClient", factory)

    resp = client.get("/api/metrics", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["reporting"] == 1
    assert body["selected"] == 2
    assert body["totals"]["num_dns_queries"] == 10
    offline = [s for s in body["servers"] if not s["online"]]
    assert len(offline) == 1 and "malformed" in offline[0]["error"]


def test_metrics_tolerates_unexpected_payload_shapes(
    client, admin_headers, session, monkeypatch
):
    _add_server(session, "weird", "http://10.0.0.4:3000")
    monkeypatch.setattr(
        metrics_mod, "AdGuardClient",
        lambda *a, **k: StatsClient({
            "num_dns_queries": "120",              # string instead of int
            "num_blocked_filtering": None,
            "avg_processing_time": "0.05",
            "top_queried_domains": [{"a.test": "5"}, "not-a-dict"],
            "top_clients": None,
        }),
    )
    resp = client.get("/api/metrics", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["totals"]["num_dns_queries"] == 120
    assert resp.json()["top_queried"] == [{"name": "a.test", "count": 5}]


def test_metrics_requires_auth(client):
    assert client.get("/api/metrics").status_code == 401


@pytest.mark.parametrize("value,expected", [
    (5, 5), (5.5, 5.5), ("7", 7.0), (None, 0.0), ("abc", 0.0), ([], 0.0),
])
def test_as_number(value, expected):
    assert _as_number(value) == expected


def test_merge_top_sums_across_servers():
    merged = _merge_top([[{"a": 3}, {"b": 1}], [{"a": 2}]])
    assert merged == [{"name": "a", "count": 5}, {"name": "b", "count": 1}]


def test_merge_top_ignores_garbage():
    assert _merge_top([None, "nope", [1, 2], [{"a": "x"}]]) == [{"name": "a", "count": 0}]


# --------------------------------------------------------------------------- #
# Query log
# --------------------------------------------------------------------------- #
def test_querylog_survives_a_broken_server(client, admin_headers, session, monkeypatch):
    _add_server(session, "broken", "http://10.0.0.2:3000")
    _add_server(session, "healthy", "http://10.0.0.3:3000")

    def factory(url, *a, **k):
        if "10.0.0.2" in url:
            raise ValueError("malformed pinned certificate")
        return StatsClient({"data": [
            {"time": "2026-08-07T10:00:00Z", "question": {"name": "a.test", "type": "A"}},
        ]})

    monkeypatch.setattr(querylog_mod, "AdGuardClient", factory)

    resp = client.get("/api/querylog", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["servers_queried"] == 2
    assert len(resp.json()["entries"]) == 1


def test_querylog_sorts_across_timezone_offsets(client, admin_headers, session, monkeypatch):
    """Sorting the raw strings put +02:00 entries in the wrong place."""
    _add_server(session, "utc", "http://10.0.0.2:3000")
    _add_server(session, "cest", "http://10.0.0.3:3000")

    def factory(url, *a, **k):
        if "10.0.0.2" in url:
            # 09:30 UTC
            return StatsClient({"data": [
                {"time": "2026-08-07T09:30:00Z", "question": {"name": "utc.test"}},
            ]})
        # 11:00+02:00 == 09:00 UTC, i.e. genuinely older despite sorting later
        # as a string.
        return StatsClient({"data": [
            {"time": "2026-08-07T11:00:00+02:00", "question": {"name": "cest.test"}},
        ]})

    monkeypatch.setattr(querylog_mod, "AdGuardClient", factory)

    entries = client.get("/api/querylog", headers=admin_headers).json()["entries"]
    assert [e["question"] for e in entries] == ["utc.test", "cest.test"]


def test_querylog_tolerates_unparseable_timestamps(client, admin_headers, session, monkeypatch):
    _add_server(session, "s", "http://10.0.0.2:3000")
    monkeypatch.setattr(
        querylog_mod, "AdGuardClient",
        lambda *a, **k: StatsClient({"data": [
            {"time": "not-a-time", "question": {"name": "bad.test"}},
            {"time": "2026-08-07T10:00:00Z", "question": {"name": "good.test"}},
            {"question": {"name": "missing.test"}},
            "not-a-dict",
        ]}),
    )
    resp = client.get("/api/querylog", headers=admin_headers)
    assert resp.status_code == 200
    entries = resp.json()["entries"]
    assert entries[0]["question"] == "good.test"
    assert len(entries) == 3


@pytest.mark.parametrize("raw", ["2026-08-07T10:00:00Z", "2026-08-07T12:00:00+02:00"])
def test_parse_time_normalises_to_utc(raw):
    assert _parse_time(raw).utctimetuple()[:5] == (2026, 8, 7, 10, 0)


@pytest.mark.parametrize("raw", [None, "", "garbage", 12345, {}])
def test_parse_time_never_raises(raw):
    assert _parse_time(raw) is not None


def test_querylog_requires_auth(client):
    assert client.get("/api/querylog").status_code == 401
