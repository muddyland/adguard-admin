"""The OIDC client's wire behaviour, which is what a provider swap breaks.

These assert against Authlib rather than against our own constants: the failures
they catch (no PKCE challenge, the secret posted in the body) look like a wrong
client secret at the provider, not like a client bug.
"""
from __future__ import annotations

import pytest
from authlib.integrations.starlette_client import OAuth
from authlib.integrations.httpx_client import AsyncOAuth2Client
from starlette.requests import Request

from app.config import settings
from app.oidc import OIDC_CLIENT_NAME, _client_kwargs, oidc_configured

ISSUER = "https://idm.example.com/oauth2/openid/adguard-admin"
REDIRECT_URI = "https://adguard.example.com/api/auth/oidc/callback"

METADATA = {
    "issuer": ISSUER,
    "authorization_endpoint": "https://idm.example.com/ui/oauth2",
    "token_endpoint": "https://idm.example.com/oauth2/token",
    "jwks_uri": f"{ISSUER}/public_key.jwk",
}


def _app():
    """A client registered exactly as app.oidc registers the real one."""
    oauth = OAuth()
    oauth.register(
        name=OIDC_CLIENT_NAME,
        client_id="adguard-admin",
        client_secret="s3cret",
        server_metadata_url=ISSUER + "/.well-known/openid-configuration",
        client_kwargs=_client_kwargs(),
    )
    client = getattr(oauth, OIDC_CLIENT_NAME)

    async def _metadata():  # never touch the network
        return METADATA

    client.load_server_metadata = _metadata
    return client


def _request():
    return Request({
        "type": "http", "method": "GET", "path": "/api/auth/oidc/login",
        "headers": [], "query_string": b"", "session": {},
        "scheme": "https", "server": ("testserver", 443), "root_path": "",
    })


@pytest.mark.anyio
async def test_authorization_request_carries_a_pkce_challenge(monkeypatch):
    """Kanidm refuses the authorization request without one."""
    monkeypatch.setattr(settings, "oidc_pkce", True)
    request = _request()
    response = await _app().authorize_redirect(request, REDIRECT_URI)

    location = response.headers["location"]
    assert "code_challenge=" in location
    assert "code_challenge_method=S256" in location

    # The verifier must be stashed for the callback, or the token exchange fails.
    state = next(iter(request.session.values()))
    assert state["data"]["code_verifier"]


@pytest.mark.anyio
async def test_pkce_can_be_turned_off_for_providers_that_choke(monkeypatch):
    monkeypatch.setattr(settings, "oidc_pkce", False)
    response = await _app().authorize_redirect(_request(), REDIRECT_URI)
    assert "code_challenge" not in response.headers["location"]


def test_client_secret_is_sent_as_http_basic():
    """Kanidm's token endpoint accepts only Basic; posting the secret in the body
    comes back as a 401 that reads like a bad secret. Authlib defaults to Basic
    whenever a secret is set, so the requirement is that we never override it."""
    assert "token_endpoint_auth_method" not in _client_kwargs()
    client = AsyncOAuth2Client(client_id="adguard-admin", client_secret="s3cret")
    assert client.token_endpoint_auth_method == "client_secret_basic"


def test_oidc_is_off_until_issuer_and_client_id_are_set(monkeypatch):
    monkeypatch.setattr(settings, "oidc_enabled", True)
    monkeypatch.setattr(settings, "oidc_issuer", "")
    monkeypatch.setattr(settings, "oidc_client_id", "adguard-admin")
    assert oidc_configured() is False

    monkeypatch.setattr(settings, "oidc_issuer", ISSUER)
    assert oidc_configured() is True

    monkeypatch.setattr(settings, "oidc_enabled", False)
    assert oidc_configured() is False
