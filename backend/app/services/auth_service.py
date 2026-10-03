"""Domain service managing user authentication and credential validation (Phase 9)."""

import logging
from typing import Optional
from sqlalchemy.orm import Session

from backend.app.core.errors import ConflictException, UnauthorizedException
from backend.app.core.security import create_access_token, get_password_hash, verify_password
from backend.app.models.user import UserRecord
from backend.app.repositories.user_repository import UserRepository

logger = logging.getLogger("nids.services.auth")


class AuthService:
    """Encapsulates authentication logic, user provisioning, and token generation."""

    @classmethod
    def authenticate_user(cls, db: Session, username: str, password: str) -> UserRecord:
        """Authenticate user by username and password.
        
        Guarantees:
        - Constant-time style failure without revealing whether username or password was incorrect.
        - Checks account active status.
        """
        user = UserRepository.get_by_username(db, username)
        if not user:
            logger.warning("Authentication failed: user '%s' not found.", username)
            raise UnauthorizedException("Invalid username or password.")

        if not verify_password(password, user.password_hash):
            logger.warning("Authentication failed: invalid credentials for user '%s'.", username)
            raise UnauthorizedException("Invalid username or password.")

        if not user.is_active:
            logger.warning("Authentication rejected: user '%s' account is deactivated.", username)
            raise UnauthorizedException("User account is inactive. Please contact an administrator.")

        logger.info("User '%s' authenticated successfully (role: %s).", user.username, user.role)
        return user

    @classmethod
    def create_access_token_for_user(cls, user: UserRecord) -> str:
        """Issue a signed JWT access token for an authenticated user."""
        return create_access_token(
            subject=user.id,
            username=user.username,
            role=user.role,
        )

    @classmethod
    def create_user(
        cls,
        db: Session,
        username: str,
        password: str,
        role: str = "VIEWER",
        is_active: bool = True,
    ) -> UserRecord:
        """Create a new user account with hashed credentials and committed transaction."""
        norm_username = username.strip()
        existing = UserRepository.get_by_username(db, norm_username)
        if existing:
            raise ConflictException(f"Username '{norm_username}' is already registered.")

        norm_role = role.upper().strip()
        if norm_role not in ("ADMIN", "ANALYST", "VIEWER"):
            raise ValueError(f"Invalid user role: {role}. Must be ADMIN, ANALYST, or VIEWER.")

        password_hash = get_password_hash(password)
        new_user = UserRecord(
            username=norm_username,
            password_hash=password_hash,
            role=norm_role,
            is_active=is_active,
        )

        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        logger.info("Created user account '%s' with role %s.", new_user.username, new_user.role)
        return new_user
