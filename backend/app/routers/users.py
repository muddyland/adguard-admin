from fastapi import APIRouter, HTTPException, status
from sqlmodel import select

from ..deps import RequireAdmin, SessionDep
from ..models import User
from ..schemas import UserCreate, UserRead, UserUpdate
from ..security import hash_password

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("", response_model=list[UserRead])
def list_users(_: RequireAdmin, session: SessionDep):
    return session.exec(select(User)).all()


@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(payload: UserCreate, _: RequireAdmin, session: SessionDep):
    if session.exec(select(User).where(User.username == payload.username)).first():
        raise HTTPException(status_code=409, detail="Username already exists")
    user = User(
        username=payload.username,
        email=payload.email,
        role=payload.role,
        hashed_password=hash_password(payload.password),
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@router.patch("/{user_id}", response_model=UserRead)
def update_user(user_id: int, payload: UserUpdate, admin: RequireAdmin, session: SessionDep):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    data = payload.model_dump(exclude_unset=True)
    if "password" in data and data["password"]:
        user.hashed_password = hash_password(data.pop("password"))
    else:
        data.pop("password", None)
    # Guard against an admin locking themselves out.
    if user.id == admin.id and ("role" in data and data["role"] != user.role.value or data.get("is_active") is False):
        raise HTTPException(status_code=400, detail="You cannot change your own role or disable yourself")
    for key, value in data.items():
        setattr(user, key, value)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int, admin: RequireAdmin, session: SessionDep):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="You cannot delete yourself")
    session.delete(user)
    session.commit()
