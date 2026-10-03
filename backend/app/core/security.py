"""Security utilities for password hashing and JWT access token management (Phase 9)."""

from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Dict, Optional, Union
import bcrypt
import jwt

from backend.app.core.config import settings
from backend.app.core.errors import UnauthorizedException

logger = logging.getLogger("nids.core.security")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain-text password against a stored bcrypt password hash."""
    if not plain_password or not hashed_password:
        return False
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except Exception as exc:
        logger.warning("Error verifying password hash: %s", exc)
        return False


def get_password_hash(password: str) -> str:
    """Generate a secure salted bcrypt hash for a plain-text password."""
    if not password:
        raise ValueError("Password cannot be empty.")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def create_access_token(
    subject: Union[str, int],
    username: str,
    role: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Encode a standardized JWT access token containing subject identity and claims."""
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode: Dict[str, Any] = {
        "sub": str(subject),
        "username": username,
        "role": role,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }

    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )
    return encoded_jwt


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT access token.
    
    Raises:
        UnauthorizedException if token is expired, invalid, or malformed.
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={"require": ["exp", "sub", "type"]},
        )
        if payload.get("type") != "access":
            raise UnauthorizedException("Invalid token type.")
        return payload
    except jwt.ExpiredSignatureError:
        raise UnauthorizedException("Authentication token has expired. Please log in again.")
    except (jwt.InvalidTokenError, jwt.DecodeError) as exc:
        logger.debug("Failed JWT decode: %s", exc)
        raise UnauthorizedException("Invalid authentication credentials.")
