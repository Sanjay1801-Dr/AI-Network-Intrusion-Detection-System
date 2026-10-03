"""Security Analytics endpoints for high-level KPIs, distributions, timeline, and investigation (Phase 13)."""

import logging
from typing import Optional
from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.dependencies import require_authenticated_user
from backend.app.core.limiter import limiter
from backend.app.db.session import get_db
from backend.app.models.user import UserRecord
from backend.app.schemas.analytics import (
    AnalyticsOverviewResponse,
    ThreatDistributionResponse,
    TimelineResponse,
    TopSourcesResponse,
    PredictionInvestigationResponse,
)
from backend.app.schemas.audit import AuditAction, AuditOutcome, AuditResourceType
from backend.app.services.audit_service import AuditService
from backend.app.services.security_analytics_service import SecurityAnalyticsService

logger = logging.getLogger("nids.api.analytics")

router = APIRouter(prefix="/analytics", tags=["Security Analytics"])


@router.get(
    "/overview",
    response_model=AnalyticsOverviewResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Security Operations Analytics Overview",
    description="Returns aggregate KPI metrics across predictions, alerts, and access security events.",
    responses={
        200: {"description": "Aggregate overview metrics.", "model": AnalyticsOverviewResponse},
        401: {"description": "Unauthenticated: Missing or invalid Bearer access token."},
        429: {"description": "Rate limit exceeded."},
    },
)
@limiter.limit(lambda: settings.RATE_LIMIT_READ)
def get_analytics_overview(
    request: Request,
    current_user: UserRecord = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
) -> AnalyticsOverviewResponse:
    """Calculate and return holistic SOC metrics."""
    overview = SecurityAnalyticsService.get_overview(db=db)

    # Record safe audit event
    AuditService.log_event(
        db=db,
        action=AuditAction.ANALYTICS_VIEWED,
        resource_type=AuditResourceType.ANALYTICS,
        outcome=AuditOutcome.SUCCESS,
        username=current_user.username,
        user_role=current_user.role,
        ip_address=request.client.host if request.client else None,
        request_method=request.method,
        request_path=request.url.path,
        status_code=200,
        details={"view": "analytics_overview"},
    )

    return overview


@router.get(
    "/threat-distribution",
    response_model=ThreatDistributionResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Threat Category and Severity Distributions",
    description="Returns aggregated distributions of evaluated threat categories and risk levels.",
    responses={
        200: {"description": "Aggregated distributions.", "model": ThreatDistributionResponse},
        401: {"description": "Unauthenticated."},
        429: {"description": "Rate limit exceeded."},
    },
)
@limiter.limit(lambda: settings.RATE_LIMIT_READ)
def get_threat_distribution(
    request: Request,
    current_user: UserRecord = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
) -> ThreatDistributionResponse:
    """Return attack category and severity triage distribution breakdowns."""
    return SecurityAnalyticsService.get_threat_distribution(db=db)


@router.get(
    "/timeline",
    response_model=TimelineResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Security Events Timeline",
    description="Returns chronological time series trend telemetry across predictions, alerts, and access events.",
    responses={
        200: {"description": "Time-bucketed security telemetry.", "model": TimelineResponse},
        401: {"description": "Unauthenticated."},
        429: {"description": "Rate limit exceeded."},
    },
)
@limiter.limit(lambda: settings.RATE_LIMIT_READ)
def get_security_timeline(
    request: Request,
    time_range: str = Query(
        default="7d",
        pattern="^(24h|7d|30d)$",
        description="Time range window for historical aggregation: 24h | 7d | 30d",
    ),
    limit: int = Query(default=50, ge=1, le=100, description="Maximum time buckets to return"),
    current_user: UserRecord = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
) -> TimelineResponse:
    """Return historical time series trend aggregation."""
    return SecurityAnalyticsService.get_security_timeline(
        db=db,
        time_range=time_range,
        limit=limit,
    )


@router.get(
    "/top-sources",
    response_model=TopSourcesResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Top Threat Originating Sources",
    description="Returns ranked source IP addresses associated with observed flow evaluations.",
    responses={
        200: {"description": "Top threat sources listing.", "model": TopSourcesResponse},
        401: {"description": "Unauthenticated."},
        429: {"description": "Rate limit exceeded."},
    },
)
@limiter.limit(lambda: settings.RATE_LIMIT_READ)
def get_top_threat_sources(
    request: Request,
    limit: int = Query(default=10, ge=1, le=50, description="Maximum number of sources to return"),
    current_user: UserRecord = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
) -> TopSourcesResponse:
    """Return aggregated top source IPs if stored in database."""
    return SecurityAnalyticsService.get_top_threat_sources(db=db, limit=limit)


@router.get(
    "/investigate/{prediction_id}",
    response_model=PredictionInvestigationResponse,
    status_code=status.HTTP_200_OK,
    summary="Investigate Prediction Telemetry",
    description="Provides deep forensic context, rule-based explainability, and threat intelligence for a prediction.",
    responses={
        200: {"description": "Forensic prediction investigation details.", "model": PredictionInvestigationResponse},
        401: {"description": "Unauthenticated."},
        404: {"description": "Prediction record not found."},
        429: {"description": "Rate limit exceeded."},
    },
)
@limiter.limit(lambda: settings.RATE_LIMIT_READ)
def investigate_prediction(
    request: Request,
    prediction_id: int,
    current_user: UserRecord = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
) -> PredictionInvestigationResponse:
    """Return deep investigation context for a specific prediction."""
    investigation = SecurityAnalyticsService.investigate_prediction(
        db=db,
        prediction_id=prediction_id,
    )

    # Record audit log
    AuditService.log_event(
        db=db,
        action=AuditAction.INVESTIGATION_VIEWED,
        resource_type=AuditResourceType.ANALYTICS,
        outcome=AuditOutcome.SUCCESS,
        username=current_user.username,
        user_role=current_user.role,
        resource_id=str(prediction_id),
        ip_address=request.client.host if request.client else None,
        request_method=request.method,
        request_path=request.url.path,
        status_code=200,
        details={
            "prediction_id": prediction_id,
            "threat_category": investigation.threat_category,
            "severity": investigation.severity,
        },
    )

    return investigation
