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
from ..schemas import Token, UserRead
from ..security import create_access_token, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/token", response_model=Token)
def login(form: Annotated[OAuth2PasswordRequestForm, Depends()], session: SessionDep):
    user = session.exec(select(User).where(User.username == form.username)).first()
    if not user or not user.hashed_password or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")
    token = create_access_token(str(user.id), {"role": user.role.value, "username": user.username})
    return Token(access_token=token)


@router.get("/me", response_model=UserRead)
def me(user: CurrentUser):
    return user


@router.get("/config")
def auth_config():
    """Public endpoint so the SPA can decide whether to show the OIDC button."""
    return {"oidc_enabled": oidc_configured(), "oidc_label": "Sign in with Authentik"}


# --------------------------------------------------------------------------- #
# OIDC (Authentik)
# --------------------------------------------------------------------------- #
@router.get("/oidc/login")
async def oidc_login(request: Request):
    if not oidc_configured():
        raise HTTPException(status_code=404, detail="OIDC not configured")
    return await oauth.authentik.authorize_redirect(request, settings.oidc_redirect_uri)


@router.get("/oidc/callback")
async def oidc_callback(request: Request, session: SessionDep):
    if not oidc_configured():
        raise HTTPException(status_code=404, detail="OIDC not configured")
    try:
        token = await oauth.authentik.authorize_access_token(request)
    except OAuthError as exc:
        raise HTTPException(status_code=400, detail=f"OIDC error: {exc.error}")

    claims = token.get("userinfo") or {}
    sub = claims.get("sub")
    if not sub:
        raise HTTPException(status_code=400, detail="OIDC response missing subject")

    email = claims.get("email")
    username = claims.get("preferred_username") or email or sub
    groups = claims.get("groups") or []

    # Match an existing user by oidc_sub, then by username, else provision one.
    user = session.exec(select(User).where(User.oidc_sub == sub)).first()
    if not user:
        user = session.exec(select(User).where(User.username == username)).first()

    role = Role.admin if (settings.oidc_admin_group and settings.oidc_admin_group in groups) else Role(settings.oidc_default_role)

    if not user:
        user = User(username=username, email=email, oidc_sub=sub, role=role, is_active=True)
        session.add(user)
    else:
        user.oidc_sub = sub
        if email:
            user.email = email
        # Promote to admin if they're in the admin group; never auto-demote.
        if settings.oidc_admin_group and settings.oidc_admin_group in groups:
            user.role = Role.admin
        session.add(user)
    session.commit()
    session.refresh(user)

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")

    access = create_access_token(str(user.id), {"role": user.role.value, "username": user.username})
    # Hand the token to the SPA via fragment so it never hits server logs.
    return RedirectResponse(url=f"{settings.frontend_url}/login#token={access}")
