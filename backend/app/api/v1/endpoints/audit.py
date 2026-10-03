"""Security audit log query and summary telemetry endpoints (Phase 12)."""

from datetime import datetime
import logging
from typing import Optional
from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.dependencies import require_authenticated_user
from backend.app.core.limiter import limiter
from backend.app.db.session import get_db
from backend.app.models.user import UserRecord
from backend.app.schemas.audit import AuditLogHistoryResponse, SecurityMonitoringSummary
from backend.app.services.audit_service import AuditService

logger = logging.getLogger("nids.api.audit")

router = APIRouter(prefix="/audit-logs", tags=["Security Audit & Monitoring"])


@router.get(
    "",
    response_model=AuditLogHistoryResponse,
    status_code=status.HTTP_200_OK,
    summary="Query Security Audit Logs",
    description=(
        "Returns paginated, chronologically ordered (newest-first) security audit trail logs. "
        "Allows authorized security operators to audit authentication, authorization, predictions, "
        "alert lifecycle state changes, and rate limiting occurrences."
    ),
    responses={
        200: {
            "description": "Paginated list of security audit trail entries.",
            "model": AuditLogHistoryResponse,
        },
        401: {
            "description": "Unauthenticated: Missing or invalid Bearer access token.",
        },
        422: {
            "description": "Validation error: Invalid query parameters or pagination range.",
        },
        429: {
            "description": "Rate limit exceeded: Too many read requests.",
        },
    },
)
@limiter.limit(lambda: settings.RATE_LIMIT_READ)
def get_audit_logs(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100, description="Maximum number of logs to return (1-100)"),
    offset: int = Query(default=0, ge=0, description="Number of logs to skip (>=0)"),
    username: Optional[str] = Query(None, description="Filter by operator username"),
    action: Optional[str] = Query(None, description="Filter by audit action (e.g. LOGIN_SUCCESS, ACCESS_DENIED)"),
    outcome: Optional[str] = Query(None, description="Filter by outcome: SUCCESS | FAILURE | DENIED"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type: AUTH | ALERT | etc."),
    start_time: Optional[datetime] = Query(None, description="Filter for events after start timestamp"),
    end_time: Optional[datetime] = Query(None, description="Filter for events before end timestamp"),
    current_user: UserRecord = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
) -> AuditLogHistoryResponse:
    """Retrieve security audit records with multi-dimensional filtering and bounded pagination."""
    records, total_count = AuditService.query_audit_logs(
        db=db,
        limit=limit,
        offset=offset,
        username=username,
        action=action,
        outcome=outcome,
        resource_type=resource_type,
        start_time=start_time,
        end_time=end_time,
    )

    return AuditLogHistoryResponse(
        total=total_count,
        limit=limit,
        offset=offset,
        items=records,
    )


@router.get(
    "/summary",
    response_model=SecurityMonitoringSummary,
    status_code=status.HTTP_200_OK,
    summary="Get Security Monitoring Telemetry Summary",
    description="Returns aggregate counts of critical security events (failed logins, access denials, rate limits) for SOC overview.",
    responses={
        200: {
            "description": "Aggregate security summary metrics.",
            "model": SecurityMonitoringSummary,
        },
        401: {
            "description": "Unauthenticated: Missing or invalid Bearer access token.",
        },
        429: {
            "description": "Rate limit exceeded: Too many read requests.",
        },
    },
)
@limiter.limit(lambda: settings.RATE_LIMIT_READ)
def get_security_summary(
    request: Request,
    current_user: UserRecord = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
) -> SecurityMonitoringSummary:
    """Return lightweight summary counts of security monitoring events."""
    summary_data = AuditService.get_security_summary(db=db)
    return SecurityMonitoringSummary(**summary_data)
