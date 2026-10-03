"""FastAPI router endpoints for Phase 16 Advanced Threat Hunting & Investigation Workbench."""

from datetime import datetime, timezone
import ipaddress
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.dependencies import require_authenticated_user
from backend.app.core.errors import ValidationException
from backend.app.core.limiter import limiter
from backend.app.db.session import get_db
from backend.app.models.user import UserRecord
from backend.app.schemas.audit import AuditAction, AuditOutcome, AuditResourceType
from backend.app.schemas.threat_hunting import (
    HuntQueryHistoryItem,
    SourceInvestigationResponse,
    ThreatHuntSearchRequest,
    ThreatHuntSearchResponse,
    ThreatHuntingSummaryResponse,
)
from backend.app.services.audit_service import AuditService
from backend.app.services.threat_hunting_service import ThreatHuntingService

logger = logging.getLogger("nids.api.hunting")

router = APIRouter(prefix="/hunting", tags=["Threat Hunting & Investigation"])


@router.post(
    "/search",
    response_model=ThreatHuntSearchResponse,
    summary="Execute Threat Hunt Search",
    description="Execute structured, parameterized queries across predictions, alerts, and incidents with correlation analysis.",
)
@limiter.limit(lambda: settings.RATE_LIMIT_READ)
def search_threat_hunt(
    request: Request,
    payload: ThreatHuntSearchRequest,
    current_user: UserRecord = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
) -> ThreatHuntSearchResponse:
    """Execute bounded threat hunting search and return correlated insights."""
    response = ThreatHuntingService.execute_hunt_search(
        db=db,
        req=payload,
        username=current_user.username,
    )

    # Centralized Audit Logging
    filter_summary_items = []
    if payload.source_ip:
        filter_summary_items.append(f"src:{payload.source_ip}")
    if payload.destination_ip:
        filter_summary_items.append(f"dst:{payload.destination_ip}")
    if payload.threat_category:
        filter_summary_items.append(f"threat:{payload.threat_category}")
    if payload.severity:
        filter_summary_items.append(f"sev:{payload.severity}")
    if payload.query_text:
        filter_summary_items.append(f"q:{payload.query_text}")
    safe_summary = ", ".join(filter_summary_items) if filter_summary_items else f"range:{response.time_range_label}"

    AuditService.log_event(
        db=db,
        action=AuditAction.THREAT_HUNT_SEARCHED,
        resource_type=AuditResourceType.HUNTING,
        outcome=AuditOutcome.SUCCESS,
        username=current_user.username,
        user_role=current_user.role,
        resource_id="HUNT_SEARCH",
        ip_address=request.client.host if request.client else None,
        request_method=request.method,
        request_path=request.url.path,
        status_code=200,
        details={
            "filters": safe_summary,
            "total_predictions": response.total_predictions,
            "total_alerts": response.total_alerts,
            "total_incidents": response.total_incidents,
            "correlation_count": len(response.correlations),
        },
    )

    return response


@router.get(
    "/summary",
    response_model=ThreatHuntingSummaryResponse,
    summary="Threat Hunting Workbench Summary",
    description="Get aggregate metrics and telemetry distribution for the threat hunting workbench header.",
)
@limiter.limit(lambda: settings.RATE_LIMIT_READ)
def get_hunting_summary(
    request: Request,
    current_user: UserRecord = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
) -> ThreatHuntingSummaryResponse:
    """Return top-level telemetry metrics for investigation dashboard."""
    return ThreatHuntingService.get_hunting_summary(db=db)


@router.get(
    "/source/{ip_address}",
    response_model=SourceInvestigationResponse,
    summary="Source IP Forensic Investigation",
    description="Deep-dive forensic profile of a specific source IP, including first/last seen, threat distribution, destinations, and timeline.",
)
@limiter.limit(lambda: settings.RATE_LIMIT_READ)
def investigate_source(
    request: Request,
    ip_address: str,
    current_user: UserRecord = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
) -> SourceInvestigationResponse:
    """Conduct source-centric forensic analysis with strict IP validation."""
    cleaned_ip = ip_address.strip()
    try:
        ipaddress.ip_address(cleaned_ip)
    except ValueError:
        raise ValidationException(f"Invalid IPv4 or IPv6 address format: '{cleaned_ip}'")

    response = ThreatHuntingService.investigate_source_ip(db=db, ip_address=cleaned_ip)

    # Centralized Audit Logging
    AuditService.log_event(
        db=db,
        action=AuditAction.SOURCE_INVESTIGATION_VIEWED,
        resource_type=AuditResourceType.HUNTING,
        outcome=AuditOutcome.SUCCESS,
        username=current_user.username,
        user_role=current_user.role,
        resource_id=cleaned_ip,
        ip_address=request.client.host if request.client else None,
        request_method=request.method,
        request_path=request.url.path,
        status_code=200,
        details={
            "investigated_ip": cleaned_ip,
            "total_observations": response.total_observations,
            "destinations_count": len(response.observed_destinations),
            "timeline_events": len(response.timeline),
        },
    )

    return response


@router.get(
    "/history",
    response_model=List[HuntQueryHistoryItem],
    summary="Threat Hunt Query History",
    description="Retrieve sanitized recent query history for the authenticated user.",
)
@limiter.limit(lambda: settings.RATE_LIMIT_READ)
def get_query_history(
    request: Request,
    limit: int = Query(default=20, ge=1, le=50, description="Max history items to retrieve (1-50)"),
    current_user: UserRecord = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
) -> List[HuntQueryHistoryItem]:
    """Retrieve bounded query history for operator workflow continuity."""
    history = ThreatHuntingService.get_query_history(
        db=db,
        username=current_user.username,
        limit=limit,
    )

    # Centralized Audit Logging
    AuditService.log_event(
        db=db,
        action=AuditAction.THREAT_HUNT_HISTORY_VIEWED,
        resource_type=AuditResourceType.HUNTING,
        outcome=AuditOutcome.SUCCESS,
        username=current_user.username,
        user_role=current_user.role,
        resource_id="QUERY_HISTORY",
        ip_address=request.client.host if request.client else None,
        request_method=request.method,
        request_path=request.url.path,
        status_code=200,
        details={
            "retrieved_count": len(history),
            "requested_limit": limit,
        },
    )

    return history
