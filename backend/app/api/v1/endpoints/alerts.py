from datetime import datetime, timezone
import logging
from typing import Optional
from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.dependencies import require_authenticated_user, require_role
from backend.app.core.errors import ValidationException
from backend.app.core.limiter import limiter
from backend.app.db.session import get_db
from backend.app.models.user import UserRecord
from backend.app.repositories.alert_repository import AlertRepository
from backend.app.schemas.history import AlertHistoryResponse, AlertResponse
from backend.app.schemas.audit import AuditAction, AuditOutcome, AuditResourceType
from backend.app.services.audit_service import AuditService
from backend.app.services.alert_service import AlertService
from backend.app.services.websocket_manager import websocket_manager

logger = logging.getLogger("nids.api.alerts")

router = APIRouter(prefix="/alerts", tags=["Security Alerts"])

ALLOWED_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
ALLOWED_STATUSES = {"NEW", "ACKNOWLEDGED", "RESOLVED"}


@router.get(
    "",
    response_model=AlertHistoryResponse,
    status_code=status.HTTP_200_OK,
    summary="List Security Alerts",
    description="Returns recent security incident alerts queued for SOC triage with optional severity and status filtering.",
    responses={
        200: {
            "description": "Paginated list of security alert records.",
            "model": AlertHistoryResponse,
        },
        401: {
            "description": "Unauthenticated: Missing or invalid Bearer access token.",
        },
        422: {
            "description": "Validation error for invalid pagination, invalid severity, or invalid status.",
        },
        429: {
            "description": "Rate limit exceeded: Too many read requests.",
        },
    },
)
@limiter.limit(lambda: settings.RATE_LIMIT_READ)
def list_alerts(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100, description="Maximum number of alerts to return (1-100)"),
    offset: int = Query(default=0, ge=0, description="Number of alerts to skip (>=0)"),
    severity: Optional[str] = Query(None, description="Filter by severity: LOW | MEDIUM | HIGH | CRITICAL"),
    status: Optional[str] = Query(None, description="Filter by alert status: NEW | ACKNOWLEDGED | RESOLVED"),
    current_user: UserRecord = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
) -> AlertHistoryResponse:
    """Retrieve paginated security alerts with defensive input validation and parameterized filtering."""
    if severity is not None and severity.upper().strip() not in ALLOWED_SEVERITIES:
        raise ValidationException(
            message=f"Invalid severity filter '{severity}'. Allowed values: {', '.join(sorted(ALLOWED_SEVERITIES))}.",
            details={"field": "severity", "value": severity},
        )

    if status is not None and status.upper().strip() not in ALLOWED_STATUSES:
        raise ValidationException(
            message=f"Invalid status filter '{status}'. Allowed values: {', '.join(sorted(ALLOWED_STATUSES))}.",
            details={"field": "status", "value": status},
        )

    alerts, total_count = AlertRepository.list(
        db=db,
        limit=limit,
        offset=offset,
        severity=severity,
        status=status,
    )

    return AlertHistoryResponse(
        total=total_count,
        limit=limit,
        offset=offset,
        items=alerts,
    )


@router.get(
    "/{alert_id}",
    response_model=AlertResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Alert Details",
    description="Retrieve complete details and linked prediction metadata for a specific security alert.",
    responses={
        200: {
            "description": "Detailed security alert record with optional prediction telemetry.",
            "model": AlertResponse,
        },
        401: {
            "description": "Unauthenticated: Missing or invalid Bearer access token.",
        },
        404: {
            "description": "Alert with the given identifier was not found.",
        },
        429: {
            "description": "Rate limit exceeded: Too many read requests.",
        },
    },
)
@limiter.limit(lambda: settings.RATE_LIMIT_READ)
def get_alert_details(
    request: Request,
    alert_id: int,
    current_user: UserRecord = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
) -> AlertResponse:
    """Retrieve a single security alert by primary identifier for SOC incident investigation."""
    alert = AlertService.get_alert(db=db, alert_id=alert_id)
    return alert


@router.patch(
    "/{alert_id}/acknowledge",
    response_model=AlertResponse,
    status_code=status.HTTP_200_OK,
    summary="Acknowledge Security Alert",
    description="Transition alert lifecycle status from NEW to ACKNOWLEDGED.",
    responses={
        200: {
            "description": "Alert successfully transitioned to ACKNOWLEDGED.",
            "model": AlertResponse,
        },
        401: {
            "description": "Unauthenticated: Missing or invalid Bearer access token.",
        },
        403: {
            "description": "Forbidden: Requires ANALYST or ADMIN role.",
        },
        404: {
            "description": "Alert with the given identifier was not found.",
        },
        409: {
            "description": "Lifecycle transition conflict (e.g. alert already acknowledged or resolved).",
        },
        429: {
            "description": "Rate limit exceeded: Too many mutation requests.",
        },
    },
)
@limiter.limit(lambda: settings.RATE_LIMIT_MUTATION)
async def acknowledge_alert(
    request: Request,
    alert_id: int,
    current_user: UserRecord = Depends(require_role("ADMIN", "ANALYST")),
    db: Session = Depends(get_db),
) -> AlertResponse:
    """Acknowledge an alert, persist timestamp, and broadcast alert_acknowledged WebSocket event."""
    updated_alert = AlertService.acknowledge_alert(db=db, alert_id=alert_id)

    # Broadcast WebSocket lifecycle event (only after database commit has succeeded)
    try:
        ack_event = {
            "event_type": "alert_acknowledged",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {
                "alert_id": updated_alert.id,
                "prediction_id": updated_alert.prediction_id,
                "severity": updated_alert.severity,
                "status": updated_alert.status,
                "acknowledged_at": updated_alert.acknowledged_at.isoformat() if updated_alert.acknowledged_at else None,
            },
        }
        await websocket_manager.broadcast(ack_event)
    except Exception as ws_exc:
        logger.warning("Non-fatal error broadcasting alert_acknowledged WebSocket event: %s", ws_exc)

    # Record Security Audit Log
    AuditService.log_event(
        db=db,
        action=AuditAction.ALERT_ACKNOWLEDGED,
        resource_type=AuditResourceType.ALERT,
        outcome=AuditOutcome.SUCCESS,
        username=current_user.username,
        user_role=current_user.role,
        resource_id=str(updated_alert.id),
        ip_address=request.client.host if request.client else None,
        request_method=request.method,
        request_path=request.url.path,
        status_code=200,
        details={
            "alert_id": updated_alert.id,
            "previous_status": "NEW",
            "new_status": "ACKNOWLEDGED",
            "severity": updated_alert.severity,
            "timestamp": updated_alert.acknowledged_at.isoformat() if updated_alert.acknowledged_at else None,
        },
    )

    return updated_alert


@router.patch(
    "/{alert_id}/resolve",
    response_model=AlertResponse,
    status_code=status.HTTP_200_OK,
    summary="Resolve Security Alert",
    description="Transition alert lifecycle status from NEW or ACKNOWLEDGED to RESOLVED.",
    responses={
        200: {
            "description": "Alert successfully transitioned to RESOLVED.",
            "model": AlertResponse,
        },
        401: {
            "description": "Unauthenticated: Missing or invalid Bearer access token.",
        },
        403: {
            "description": "Forbidden: Requires ANALYST or ADMIN role.",
        },
        404: {
            "description": "Alert with the given identifier was not found.",
        },
        409: {
            "description": "Lifecycle transition conflict (e.g. alert already in terminal status RESOLVED).",
        },
        429: {
            "description": "Rate limit exceeded: Too many mutation requests.",
        },
    },
)
@limiter.limit(lambda: settings.RATE_LIMIT_MUTATION)
async def resolve_alert(
    request: Request,
    alert_id: int,
    current_user: UserRecord = Depends(require_role("ADMIN", "ANALYST")),
    db: Session = Depends(get_db),
) -> AlertResponse:
    """Resolve an alert, persist timestamp, and broadcast alert_resolved WebSocket event."""
    existing = AlertRepository.get_by_id(db, alert_id)
    prev_status = existing.status if existing else "NEW"

    updated_alert = AlertService.resolve_alert(db=db, alert_id=alert_id)

    # Broadcast WebSocket lifecycle event (only after database commit has succeeded)
    try:
        res_event = {
            "event_type": "alert_resolved",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {
                "alert_id": updated_alert.id,
                "prediction_id": updated_alert.prediction_id,
                "severity": updated_alert.severity,
                "status": updated_alert.status,
                "resolved_at": updated_alert.resolved_at.isoformat() if updated_alert.resolved_at else None,
            },
        }
        await websocket_manager.broadcast(res_event)
    except Exception as ws_exc:
        logger.warning("Non-fatal error broadcasting alert_resolved WebSocket event: %s", ws_exc)

    # Record Security Audit Log
    AuditService.log_event(
        db=db,
        action=AuditAction.ALERT_RESOLVED,
        resource_type=AuditResourceType.ALERT,
        outcome=AuditOutcome.SUCCESS,
        username=current_user.username,
        user_role=current_user.role,
        resource_id=str(updated_alert.id),
        ip_address=request.client.host if request.client else None,
        request_method=request.method,
        request_path=request.url.path,
        status_code=200,
        details={
            "alert_id": updated_alert.id,
            "previous_status": prev_status,
            "new_status": "RESOLVED",
            "severity": updated_alert.severity,
            "timestamp": updated_alert.resolved_at.isoformat() if updated_alert.resolved_at else None,
        },
    )

    return updated_alert


