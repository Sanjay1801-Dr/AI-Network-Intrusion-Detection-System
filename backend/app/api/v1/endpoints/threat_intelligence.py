"""Threat Intelligence reputation query endpoint (Phase 13)."""

import logging
from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.dependencies import require_authenticated_user
from backend.app.core.limiter import limiter
from backend.app.db.session import get_db
from backend.app.models.user import UserRecord
from backend.app.schemas.analytics import ThreatIntelligenceLookupResponse
from backend.app.schemas.audit import AuditAction, AuditOutcome, AuditResourceType
from backend.app.services.audit_service import AuditService
from backend.app.services.threat_intelligence_service import ThreatIntelligenceService

logger = logging.getLogger("nids.api.threat_intelligence")

router = APIRouter(prefix="/threat-intelligence", tags=["Threat Intelligence"])


@router.get(
    "/ip/{ip_address}",
    response_model=ThreatIntelligenceLookupResponse,
    status_code=status.HTTP_200_OK,
    summary="Look Up IP Threat Intelligence",
    description="Queries local demonstration threat reputation for a designated IPv4 or IPv6 address.",
    responses={
        200: {"description": "Reputation lookup result.", "model": ThreatIntelligenceLookupResponse},
        401: {"description": "Unauthenticated: Missing or invalid Bearer access token."},
        422: {"description": "Validation error: Invalid IP address format."},
        429: {"description": "Rate limit exceeded."},
    },
)
@limiter.limit(lambda: settings.RATE_LIMIT_READ)
def lookup_ip_intelligence(
    request: Request,
    ip_address: str,
    current_user: UserRecord = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
) -> ThreatIntelligenceLookupResponse:
    """Validate IP and return demonstration threat intelligence metadata."""
    lookup_result = ThreatIntelligenceService.lookup_ip(ip_address)

    # Record safe audit event
    AuditService.log_event(
        db=db,
        action=AuditAction.THREAT_INTELLIGENCE_LOOKUP,
        resource_type=AuditResourceType.THREAT_INTELLIGENCE,
        outcome=AuditOutcome.SUCCESS,
        username=current_user.username,
        user_role=current_user.role,
        resource_id=lookup_result["ip"],
        ip_address=request.client.host if request.client else None,
        request_method=request.method,
        request_path=request.url.path,
        status_code=200,
        details={
            "queried_ip": lookup_result["ip"],
            "found": lookup_result["found"],
            "reputation": lookup_result["reputation"],
            "source": lookup_result["source"],
        },
    )

    return ThreatIntelligenceLookupResponse(**lookup_result)
