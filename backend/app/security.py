import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import jwt
from cryptography.fernet import Fernet, InvalidToken
from pwdlib import PasswordHash

from .config import settings

# pwdlib's recommended scheme is Argon2 (memory-hard) with a bcrypt fallback.
_pwd = PasswordHash.recommended()


# --------------------------------------------------------------------------- #
# Password hashing (local accounts)
# --------------------------------------------------------------------------- #
def hash_password(password: str) -> str:
    return _pwd.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return _pwd.verify(password, hashed)
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# JWT access tokens
# --------------------------------------------------------------------------- #
def create_access_token(subject: str, extra: Optional[dict[str, Any]] = None) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    payload: dict[str, Any] = {"sub": subject, "exp": expire, "iat": datetime.now(timezone.utc)}
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict[str, Any]:
    # algorithms is pinned explicitly to avoid algorithm-confusion attacks.
    return jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])


def generate_token(nbytes: int = 32) -> str:
    """URL-safe random secret (provisioning tokens, generated passwords)."""
    return secrets.token_urlsafe(nbytes)


def create_proxy_token(server_id: int, user_id: int, minutes: Optional[int] = None) -> str:
    """Short-lived token (carried in a path-scoped cookie) authorizing the UI proxy."""
    ttl = settings.proxy_token_ttl_minutes if minutes is None else minutes
    expire = datetime.now(timezone.utc) + timedelta(minutes=ttl)
    payload = {"typ": "proxy", "psrv": server_id, "sub": str(user_id), "exp": expire}
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_proxy_token(token: str, server_id: int) -> Optional[int]:
    """Validate a proxy cookie and return the user id it was minted for.

    Returns None when the token is invalid, expired, not a proxy token, or was
    issued for a different server. The caller must still re-check that the user
    exists, is active and still holds the required role — the token alone is not
    proof of current authorization.
    """
    try:
        claims = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
    except jwt.PyJWTError:
        return None
    if claims.get("typ") != "proxy" or claims.get("psrv") != server_id:
        return None
    try:
        return int(claims["sub"])
    except (KeyError, TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# Fernet encryption for AdGuard server passwords at rest
# --------------------------------------------------------------------------- #
def _fernet() -> Optional[Fernet]:
    if not settings.fernet_key:
        return None
    return Fernet(settings.fernet_key.encode())


def encrypt_secret(plaintext: Optional[str]) -> Optional[str]:
    if plaintext is None or plaintext == "":
        return None
    f = _fernet()
    if f is None:
        # No key configured — refuse to silently store plaintext.
        raise RuntimeError(
            "FERNET_KEY is not set; cannot store server credentials securely. "
            "Generate one with: python -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\""
        )
    return f.encrypt(plaintext.encode()).decode()


def decrypt_secret(token: Optional[str]) -> Optional[str]:
    if not token:
        return None
    f = _fernet()
    if f is None:
        return None
    try:
        return f.decrypt(token.encode()).decode()
    except InvalidToken:
        return None
