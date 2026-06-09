from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import Session

from .database import get_session
from .models import Role, User
from .security import decode_access_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token", auto_error=True)

SessionDep = Annotated[Session, Depends(get_session)]


def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    session: SessionDep,
) -> User:
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_access_token(token)
        user_id = payload.get("sub")
        if user_id is None:
            raise credentials_exc
    except jwt.PyJWTError:
        raise credentials_exc

    user = session.get(User, int(user_id))
    if user is None or not user.is_active:
        raise credentials_exc
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]

# Role hierarchy: admin > editor > viewer
_ROLE_RANK = {Role.viewer: 0, Role.editor: 1, Role.admin: 2}


def require_role(minimum: Role):
    def checker(user: CurrentUser) -> User:
        if _ROLE_RANK[user.role] < _ROLE_RANK[minimum]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires {minimum.value} role or higher",
            )
        return user

    return checker


RequireEditor = Annotated[User, Depends(require_role(Role.editor))]
RequireAdmin = Annotated[User, Depends(require_role(Role.admin))]
