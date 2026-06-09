"""Authentik / generic OIDC integration via Authlib.

OIDC is only wired up when settings.oidc_enabled is true and an issuer is set.
We use Authlib's Starlette client which handles discovery, PKCE, state, and
nonce validation for us.
"""
from authlib.integrations.starlette_client import OAuth

from .config import settings

oauth = OAuth()

if settings.oidc_enabled and settings.oidc_issuer:
    oauth.register(
        name="authentik",
        client_id=settings.oidc_client_id,
        client_secret=settings.oidc_client_secret,
        server_metadata_url=settings.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration",
        client_kwargs={"scope": settings.oidc_scopes},
    )


def oidc_configured() -> bool:
    return bool(settings.oidc_enabled and settings.oidc_issuer and settings.oidc_client_id)
