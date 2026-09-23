"""Generic OpenID Connect integration via Authlib.

Nothing here is tied to a particular identity provider: the endpoints, the
supported response modes and the signing keys all come from the issuer's
discovery document. Tested against Kanidm and Authentik.

OIDC is only wired up when settings.oidc_enabled is true and an issuer is set.
Authlib's Starlette client handles discovery, state, nonce and PKCE for us.
"""
from authlib.integrations.starlette_client import OAuth

from .config import settings

oauth = OAuth()

# The registration name is an internal handle, not a provider name — the client
# is reached as `oauth.oidc` regardless of who the IdP is.
OIDC_CLIENT_NAME = "oidc"


def _client_kwargs() -> dict:
    kwargs: dict = {"scope": settings.oidc_scopes}
    if settings.oidc_pkce:
        # Authlib only sends a code_challenge when a method is configured here.
        # Kanidm refuses the authorization request without one.
        kwargs["code_challenge_method"] = "S256"
    return kwargs


if settings.oidc_enabled and settings.oidc_issuer:
    oauth.register(
        name=OIDC_CLIENT_NAME,
        client_id=settings.oidc_client_id,
        client_secret=settings.oidc_client_secret,
        server_metadata_url=settings.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration",
        client_kwargs=_client_kwargs(),
    )


def oidc_configured() -> bool:
    return bool(settings.oidc_enabled and settings.oidc_issuer and settings.oidc_client_id)
