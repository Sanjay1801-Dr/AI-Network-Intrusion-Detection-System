"""Reusable FastAPI dependencies for authentication and RBAC authorization (Phase 9)."""

import logging
from typing import Callable, List, Optional
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from backend.app.core.errors import ForbiddenException, UnauthorizedException
from backend.app.core.security import decode_access_token
from backend.app.db.session import get_db
from backend.app.models.user import UserRecord
from backend.app.repositories.user_repository import UserRepository
from backend.app.schemas.audit import AuditAction, AuditOutcome, AuditResourceType
from backend.app.services.audit_service import AuditService

logger = logging.getLogger("nids.core.dependencies")

# Bearer token extractor without auto_error so we can return sanitized JSON errors
http_bearer = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(http_bearer),
    db: Session = Depends(get_db),
) -> UserRecord:
    """Validate Bearer JWT access token and return active authenticated user entity.
    
    Raises:
        UnauthorizedException (HTTP 401) on missing, expired, or invalid tokens.
    """
    if credentials is None or not credentials.credentials:
        raise UnauthorizedException("Authentication required. Missing Bearer access token.")

    token = credentials.credentials.strip()
    payload = decode_access_token(token)

    user_id_str = payload.get("sub")
    if not user_id_str:
        raise UnauthorizedException("Invalid token: missing subject identity.")

    try:
        user_id = int(user_id_str)
    except (ValueError, TypeError):
        raise UnauthorizedException("Invalid token subject format.")

    user = UserRepository.get_by_id(db, user_id)
    if not user:
        raise UnauthorizedException("User account does not exist.")

    if not user.is_active:
        raise UnauthorizedException("User account is inactive.")

    return user


def require_authenticated_user(
    current_user: UserRecord = Depends(get_current_user),
) -> UserRecord:
    """Dependency verifying that the caller is authenticated and active."""
    return current_user


def require_role(*allowed_roles: str) -> Callable[..., UserRecord]:
    """Dependency factory restricting endpoint execution to designated RBAC roles.
    
    Raises:
        ForbiddenException (HTTP 403) if caller does not possess an authorized role.
    """
    normalized_allowed = {role.upper().strip() for role in allowed_roles}

    def role_verifier(
        request: Request,
        current_user: UserRecord = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> UserRecord:
        user_role = str(current_user.role).upper().strip()
        if user_role not in normalized_allowed:
            logger.warning(
                "Access denied for user '%s' (role: %s). Required roles: %s",
                current_user.username,
                user_role,
                normalized_allowed,
            )
            client_ip = request.client.host if request.client else None
            AuditService.log_event(
                db=db,
                action=AuditAction.ACCESS_DENIED,
                resource_type=AuditResourceType.ACCESS_CONTROL,
                outcome=AuditOutcome.DENIED,
                username=current_user.username,
                user_role=user_role,
                ip_address=client_ip,
                request_method=request.method,
                request_path=request.url.path,
                status_code=403,
                details={
                    "required_roles": list(sorted(normalized_allowed)),
                    "message": "Insufficient permissions for requested operation",
                },
            )
            raise ForbiddenException(
                f"Insufficient permissions. This operation requires one of: {', '.join(sorted(normalized_allowed))}."
            )
        return current_user

    return role_verifier
