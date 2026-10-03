"""Authentication and operator session management endpoints (Phase 9)."""

import logging
from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.dependencies import get_current_user
from backend.app.core.errors import UnauthorizedException
from backend.app.core.limiter import limiter
from backend.app.db.session import get_db
from backend.app.models.user import UserRecord
from backend.app.schemas.audit import AuditAction, AuditOutcome, AuditResourceType
from backend.app.schemas.auth import LoginRequest, TokenResponse, UserResponse
from backend.app.services.audit_service import AuditService
from backend.app.services.auth_service import AuthService

logger = logging.getLogger("nids.api.auth")

router = APIRouter(prefix="/auth", tags=["Authentication & Access Control"])


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Operator Login",
    description="Authenticate an operator with username and password, returning a signed JWT access token.",
    responses={
        200: {"description": "Authentication successful.", "model": TokenResponse},
        401: {"description": "Invalid username or password."},
        429: {"description": "Rate limit exceeded: Too many rapid login attempts."},
    },
)
@limiter.limit(lambda: settings.RATE_LIMIT_LOGIN)
def login(
    request: Request,
    payload: LoginRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Authenticate operator credentials and issue a signed Bearer access token."""
    client_ip = request.client.host if request.client else None
    try:
        user = AuthService.authenticate_user(
            db=db,
            username=payload.username,
            password=payload.password,
        )
        token = AuthService.create_access_token_for_user(user)

        AuditService.log_event(
            db=db,
            action=AuditAction.LOGIN_SUCCESS,
            resource_type=AuditResourceType.AUTH,
            outcome=AuditOutcome.SUCCESS,
            username=user.username,
            user_role=user.role,
            ip_address=client_ip,
            request_method=request.method,
            request_path=request.url.path,
            status_code=200,
            details={"status": "Authentication successful"},
        )

        return TokenResponse(
            access_token=token,
            token_type="bearer",
            user=UserResponse.model_validate(user),
        )
    except UnauthorizedException as exc:
        AuditService.log_event(
            db=db,
            action=AuditAction.LOGIN_FAILURE,
            resource_type=AuditResourceType.AUTH,
            outcome=AuditOutcome.FAILURE,
            username=payload.username,
            ip_address=client_ip,
            request_method=request.method,
            request_path=request.url.path,
            status_code=401,
            details={"reason": "Invalid credentials or inactive account"},
        )
        raise exc


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Current User Profile",
    description="Retrieve the profile and role claims of the currently authenticated operator.",
    responses={
        200: {"description": "Current user profile.", "model": UserResponse},
        401: {"description": "Authentication credentials missing or expired."},
        429: {"description": "Rate limit exceeded: Too many read requests."},
    },
)
@limiter.limit(lambda: settings.RATE_LIMIT_READ)
def get_current_user_profile(
    request: Request,
    current_user: UserRecord = Depends(get_current_user),
) -> UserResponse:
    """Return the profile and role of the currently authenticated caller."""
    return UserResponse.model_validate(current_user)


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Operator Logout",
    description="Acknowledge operator logout and instruct client to invalidate local session state.",
    responses={
        200: {"description": "Operator logged out successfully."},
        401: {"description": "Unauthenticated caller."},
    },
)
def logout(
    request: Request,
    current_user: UserRecord = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Acknowledge operator logout session termination."""
    client_ip = request.client.host if request.client else None
    AuditService.log_event(
        db=db,
        action=AuditAction.LOGOUT,
        resource_type=AuditResourceType.AUTH,
        outcome=AuditOutcome.SUCCESS,
        username=current_user.username,
        user_role=current_user.role,
        ip_address=client_ip,
        request_method=request.method,
        request_path=request.url.path,
        status_code=200,
        details={"status": "Operator logged out"},
    )
    logger.info("Operator '%s' logged out.", current_user.username)
    return {
        "status": "success",
        "message": f"Session for user '{current_user.username}' terminated.",
    }
