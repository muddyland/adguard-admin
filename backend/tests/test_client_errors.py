"""Every httpx timeout class stringifies to '', which produced the unactionable
'GET /control/status failed:' shown in the UI. Errors must always name a cause."""
from __future__ import annotations

import httpx
import pytest

from app.adguard_client import AdGuardClient, AdGuardError, describe_transport_error


@pytest.mark.parametrize("exc", [
    httpx.ConnectTimeout(""), httpx.ReadTimeout(""), httpx.WriteTimeout(""),
    httpx.PoolTimeout(""), httpx.ConnectError(""), httpx.ReadError(""),
    httpx.RemoteProtocolError(""), httpx.TooManyRedirects(""),
    httpx.HTTPError(""),
])
def test_description_is_never_empty(exc):
    described = describe_transport_error(exc, 10.0)
    assert described.strip(), f"{type(exc).__name__} produced an empty description"


@pytest.mark.parametrize("exc,expected", [
    (httpx.ConnectTimeout(""), "TCP/TLS connection"),
    (httpx.ReadTimeout(""), "no response in time"),
    (httpx.PoolTimeout(""), "free connection"),
    (httpx.ConnectError("refused"), "could not connect"),
    (httpx.RemoteProtocolError("bad"), "invalid HTTP"),
])
def test_description_names_the_failure_mode(exc, expected):
    assert expected in describe_transport_error(exc, 10.0)


def test_timeouts_report_the_budget_that_elapsed():
    assert "after 10s" in describe_transport_error(httpx.ConnectTimeout(""), 10.0)
    assert "after 2.5s" in describe_transport_error(httpx.ReadTimeout(""), 2.5)


def test_non_timeouts_do_not_claim_a_timeout():
    assert "after" not in describe_transport_error(httpx.ConnectError("refused"), 10.0)


def test_underlying_detail_is_preserved():
    described = describe_transport_error(
        httpx.ConnectError("[Errno -2] Name or service not known"), 10.0
    )
    assert "Name or service not known" in described


@pytest.mark.anyio
async def test_client_surfaces_a_useful_timeout_message(monkeypatch):
    """End to end through AdGuardClient, which is what reaches server.last_error."""
    client = AdGuardClient("http://10.255.255.1:3000", timeout=0.25)

    async def always_timeout(*a, **k):
        raise httpx.ConnectTimeout("")

    monkeypatch.setattr(client._client, "request", always_timeout)
    with pytest.raises(AdGuardError) as exc:
        await client.status()
    await client.aclose()

    message = str(exc.value)
    assert message.rstrip().endswith("s"), message
    assert not message.rstrip().endswith("failed:"), "bare message regressed"
    assert "timed out establishing a TCP/TLS connection after 0.25s" in message
