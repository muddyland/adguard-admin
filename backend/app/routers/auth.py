import logging
import re
from typing import Annotated

from authlib.integrations.starlette_client import OAuthError
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import select

from ..config import settings
from ..deps import CurrentUser, SessionDep
from ..models import Role, User
from ..oidc import oauth, oidc_configured
from ..ratelimit import RateLimiter
from ..schemas import Token, UserRead
from ..security import create_access_token, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])

logger = logging.getLogger("adguard_admin.auth")

# Brute-force protection for local logins. Keyed by client IP *and* by username
# so that neither a single source hammering many accounts nor a distributed
# attempt against one account slips through.
login_limiter = RateLimiter(
    max_attempts=settings.login_max_attempts,
    window_seconds=settings.login_window_seconds,
    lockout_seconds=settings.login_lockout_seconds,
)


def client_ip(request: Request) -> str:
    """Best-effort client address.

    X-Forwarded-For is only honoured when uvicorn is running with
    --proxy-headers behind a trusted proxy; we read request.client, which
    uvicorn has already populated from that header in that case.
    """
    return request.client.host if request.client else "unknown"


@router.post("/token", response_model=Token)
def login(
    request: Request,
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: SessionDep,
):
    ip = client_ip(request)
    keys = [f"ip:{ip}", f"user:{form.username.lower()}"]

    for key in keys:
        retry_after = login_limiter.retry_after(key)
        if retry_after:
            logger.warning("Login throttled for %s (retry in %ss)", key, retry_after)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed login attempts. Try again later.",
                headers={"Retry-After": str(retry_after)},
            )

    user = session.exec(select(User).where(User.username == form.username)).first()
    if not user or not user.hashed_password or not verify_password(form.password, user.hashed_password):
        for key in keys:
            login_limiter.record_failure(key)
        logger.info("Failed login for username=%r from %s", form.username, ip)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    if not user.is_active:
        # Counts as a failure: otherwise a disabled account is an unlimited
        # oracle for testing passwords.
        for key in keys:
            login_limiter.record_failure(key)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")

    for key in keys:
        login_limiter.record_success(key)
    token = create_access_token(str(user.id), {"role": user.role.value, "username": user.username})
    return Token(access_token=token)


@router.get("/me", response_model=UserRead)
def me(user: CurrentUser):
    return user


@router.get("/config")
def auth_config():
    """Public endpoint so the SPA can decide whether to show the OIDC button."""
    return {
        "oidc_enabled": oidc_configured(),
        "oidc_label": settings.oidc_button_label,
        "oidc_display_name": settings.oidc_display_name,
    }


# --------------------------------------------------------------------------- #
# OIDC
# --------------------------------------------------------------------------- #
@router.get("/oidc/login")
async def oidc_login(request: Request):
    if not oidc_configured():
        raise HTTPException(status_code=404, detail="OIDC not configured")
    return await oauth.oidc.authorize_redirect(request, settings.oidc_redirect_uri)


def _claim_groups(raw) -> list[str]:
    """Normalise whatever the provider put in the `groups` claim into names.

    Most providers send a JSON array; some send one delimited string. Splitting
    that string keeps matching *exact* — a plain substring test would make
    OIDC_ADMIN_GROUP="admins" match a group called "not-admins".
    """
    if isinstance(raw, str):
        return [g for g in re.split(r"[,\s]+", raw) if g]
    if isinstance(raw, (list, tuple)):
        return [g.strip() for g in raw if isinstance(g, str) and g.strip()]
    return []


def _in_admin_group(groups: list[str]) -> bool:
    """True when OIDC_ADMIN_GROUP names one of the groups the IdP sent.

    Kanidm identifies groups by SPN ("adguard-admins@idm.example.com") and also
    sends their UUIDs, so an operator who configured the bare name would never
    match. A bare name therefore also matches an SPN's local part; a configured
    SPN is compared whole, so "ops@a.example.com" never matches
    "ops@b.example.com". Matching stays case-sensitive and exact per component.
    """
    wanted = settings.oidc_admin_group.strip()
    if not wanted:
        return False
    wanted_is_bare = "@" not in wanted
    for group in groups:
        if group == wanted:
            return True
        if wanted_is_bare and group.split("@", 1)[0] == wanted:
            return True
    return False


def _resolve_oidc_user(session, sub: str, username: str, email: str | None) -> User | None:
    """Find the account this OIDC subject already owns, if any.

    Matching on `sub` is always safe — it is the provider's stable identifier and
    we set it ourselves. Matching on a *username* is not: `preferred_username` is
    attacker-controlled at many IdPs, so claiming an existing local account by
    naming yourself after it would be account takeover. Username linking is
    therefore opt-in (OIDC_ALLOW_USERNAME_LINKING) and still refuses any account
    that has a local password, which is the case that actually matters.
    """
    user = session.exec(select(User).where(User.oidc_sub == sub)).first()
    if user:
        return user

    if not settings.oidc_allow_username_linking:
        return None

    candidate = session.exec(select(User).where(User.username == username)).first()
    if candidate is None:
        return None
    if candidate.oidc_sub and candidate.oidc_sub != sub:
        logger.warning(
            "OIDC sub %r tried to link to account %r already bound to a different subject",
            sub, username,
        )
        return None
    if candidate.hashed_password:
        logger.warning(
            "OIDC sub %r matched local account %r by username; refusing to adopt an "
            "account that has a local password.", sub, username,
        )
        return None
    return candidate


@router.get("/oidc/callback")
async def oidc_callback(request: Request, session: SessionDep):
    if not oidc_configured():
        raise HTTPException(status_code=404, detail="OIDC not configured")
    try:
        token = await oauth.oidc.authorize_access_token(request)
    except OAuthError as exc:
        raise HTTPException(status_code=400, detail=f"OIDC error: {exc.error}")

    claims = token.get("userinfo") or {}
    sub = claims.get("sub")
    if not sub:
        raise HTTPException(status_code=400, detail="OIDC response missing subject")

    # Only trust an address the provider says it verified — an unverified email
    # is self-asserted and must not become an identity we key anything on.
    email = claims.get("email") if claims.get("email_verified") else None
    username = claims.get("preferred_username") or email or sub
    groups = _claim_groups(claims.get("groups"))

    is_admin_group = _in_admin_group(groups)

    user = _resolve_oidc_user(session, sub, username, email)

    if not user:
        # Never silently collide with an existing local account.
        if session.exec(select(User).where(User.username == username)).first():
            logger.warning("OIDC login for %r blocked: username already taken locally", username)
            raise HTTPException(
                status_code=409,
                detail=(
                    "An account with this username already exists. An administrator must "
                    "link it to your identity provider."
                ),
            )
        role = Role.admin if is_admin_group else Role(settings.oidc_default_role)
        user = User(username=username, email=email, oidc_sub=sub, role=role, is_active=True)
        session.add(user)
    else:
        user.oidc_sub = sub
        if email:
            user.email = email
        # Promote to admin if they're in the admin group; never auto-demote.
        if is_admin_group:
            user.role = Role.admin
        session.add(user)
    session.commit()
    session.refresh(user)

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")

    access = create_access_token(str(user.id), {"role": user.role.value, "username": user.username})
    # Hand the token to the SPA via fragment so it never hits server logs.
    return RedirectResponse(url=f"{settings.frontend_url}/login#token={access}")
