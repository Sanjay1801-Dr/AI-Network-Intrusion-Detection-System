"""FastAPI router endpoints for Phase 14 Incident Response & SOC Operations."""

from datetime import datetime, timezone
import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.dependencies import require_authenticated_user, require_role
from backend.app.core.limiter import limiter
from backend.app.db.session import get_db
from backend.app.models.user import UserRecord
from backend.app.schemas.audit import AuditAction, AuditOutcome, AuditResourceType
from backend.app.schemas.incident import (
    IncidentAssignRequest,
    IncidentCreateRequest,
    IncidentDetailResponse,
    IncidentListResponse,
    IncidentNoteCreateRequest,
    IncidentNoteResponse,
    IncidentResponse,
    IncidentStatusUpdateRequest,
    IncidentSummaryResponse,
    IncidentTimelineResponse,
)
from backend.app.services.audit_service import AuditService
from backend.app.services.incident_service import IncidentService
from backend.app.services.websocket_manager import websocket_manager

logger = logging.getLogger("nids.api.incidents")

router = APIRouter(prefix="/incidents", tags=["SOC Incident Response"])


@router.post(
    "",
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Incident",
    description="Open a new SOC incident record, optionally correlating an existing Alert or Prediction.",
)
@limiter.limit(lambda: settings.RATE_LIMIT_MUTATION)
async def create_incident(
    request: Request,
    payload: IncidentCreateRequest,
    current_user: UserRecord = Depends(require_role("ADMIN", "ANALYST")),
    db: Session = Depends(get_db),
) -> IncidentResponse:
    """Create a new incident case with inherited severity and threat context."""
    incident = IncidentService.create_incident(db, payload, current_user.username)

    # Broadcast real-time WebSocket event
    try:
        ws_event = {
            "event_type": "incident_created",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {
                "id": incident.id,
                "incident_key": incident.incident_key,
                "title": incident.title,
                "severity": incident.severity,
                "status": incident.status,
                "category": incident.category,
                "source_ip": incident.source_ip,
                "assigned_to": incident.assigned_to,
                "created_by": incident.created_by,
                "created_at": incident.created_at.isoformat() if incident.created_at else None,
            },
        }
        await websocket_manager.broadcast(ws_event)
    except Exception as ws_err:
        logger.warning("Error broadcasting incident_created WebSocket event: %s", ws_err)

    # Emit Phase 12 Security Audit Log
    AuditService.log_event(
        db=db,
        action=AuditAction.INCIDENT_CREATED,
        resource_type=AuditResourceType.INCIDENT,
        outcome=AuditOutcome.SUCCESS,
        username=current_user.username,
        user_role=current_user.role,
        resource_id=str(incident.id),
        ip_address=request.client.host if request.client else None,
        request_method=request.method,
        request_path=request.url.path,
        status_code=201,
        details={
            "incident_id": incident.id,
            "incident_key": incident.incident_key,
            "severity": incident.severity,
            "category": incident.category,
            "alert_id": payload.alert_id,
            "prediction_id": payload.prediction_id,
        },
    )

    return IncidentResponse(
        id=incident.id,
        incident_key=incident.incident_key,
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        status=incident.status,
        category=incident.category,
        source_ip=incident.source_ip,
        assigned_to=incident.assigned_to,
        created_by=incident.created_by,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        acknowledged_at=incident.acknowledged_at,
        investigation_started_at=incident.investigation_started_at,
        resolved_at=incident.resolved_at,
        resolution_summary=incident.resolution_summary,
        alerts_count=len(incident.alerts),
        predictions_count=len(incident.predictions),
        notes_count=len(incident.notes),
    )


@router.get(
    "",
    response_model=IncidentListResponse,
    status_code=status.HTTP_200_OK,
    summary="List Incidents",
    description="Retrieve paginated SOC incidents with optional status, severity, category, or assignee filters.",
)
@limiter.limit(lambda: settings.RATE_LIMIT_READ)
def list_incidents(
    request: Request,
    status: Optional[str] = Query(None, description="Filter by status: OPEN, ACKNOWLEDGED, INVESTIGATING, CONTAINED, RESOLVED"),
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
    category: Optional[str] = Query(None, description="Filter by category e.g. DoS, Port Scan"),
    assigned_to: Optional[str] = Query(None, description="Filter by assigned operator username"),
    limit: int = Query(default=20, ge=1, le=100, description="Page limit (1-100)"),
    offset: int = Query(default=0, ge=0, description="Offset (>=0)"),
    current_user: UserRecord = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
) -> IncidentListResponse:
    """List incidents matching query parameters."""
    items, total = IncidentService.list_incidents(
        db=db,
        status=status,
        severity=severity,
        category=category,
        assigned_to=assigned_to,
        limit=limit,
        offset=offset,
    )
    return IncidentListResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/summary",
    response_model=IncidentSummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Incident Summary Metrics",
    description="Aggregated incident metrics for SOC overview cards.",
)
@limiter.limit(lambda: settings.RATE_LIMIT_READ)
def get_incident_summary(
    request: Request,
    current_user: UserRecord = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
) -> IncidentSummaryResponse:
    """Retrieve aggregated incident counters for dashboard widgets."""
    return IncidentService.get_incident_summary(db)


@router.get(
    "/{incident_id}",
    response_model=IncidentDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Incident Details",
    description="Retrieve deep forensic incident details including linked alerts, predictions, and case notes.",
)
@limiter.limit(lambda: settings.RATE_LIMIT_READ)
def get_incident_details(
    request: Request,
    incident_id: int,
    current_user: UserRecord = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
) -> IncidentDetailResponse:
    """Fetch complete incident envelope."""
    detail = IncidentService.get_incident_detail(db, incident_id)

    # Emit Audit Log
    AuditService.log_event(
        db=db,
        action=AuditAction.INCIDENT_VIEWED,
        resource_type=AuditResourceType.INCIDENT,
        outcome=AuditOutcome.SUCCESS,
        username=current_user.username,
        user_role=current_user.role,
        resource_id=str(incident_id),
        ip_address=request.client.host if request.client else None,
        request_method=request.method,
        request_path=request.url.path,
        status_code=200,
        details={"incident_id": incident_id, "incident_key": detail.incident_key},
    )

    return detail


@router.patch(
    "/{incident_id}/status",
    response_model=IncidentDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Update Incident Status",
    description="Advance incident lifecycle through controlled state machine transitions.",
)
@limiter.limit(lambda: settings.RATE_LIMIT_MUTATION)
async def update_incident_status(
    request: Request,
    incident_id: int,
    payload: IncidentStatusUpdateRequest,
    current_user: UserRecord = Depends(require_role("ADMIN", "ANALYST")),
    db: Session = Depends(get_db),
) -> IncidentDetailResponse:
    """Transition incident lifecycle state."""
    incident = IncidentService.get_incident(db, incident_id)
    prev_status = incident.status

    updated = IncidentService.update_status(
        db=db,
        incident_id=incident_id,
        new_status_raw=payload.new_status,
        resolution_summary=payload.resolution_summary,
    )

    # Broadcast WebSocket update
    try:
        ws_event = {
            "event_type": "incident_status_changed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {
                "id": updated.id,
                "incident_key": updated.incident_key,
                "previous_status": prev_status,
                "new_status": updated.status,
                "resolved_at": updated.resolved_at.isoformat() if updated.resolved_at else None,
                "resolution_summary": updated.resolution_summary,
            },
        }
        await websocket_manager.broadcast(ws_event)
    except Exception as ws_err:
        logger.warning("Error broadcasting incident_status_changed WebSocket event: %s", ws_err)

    # Emit Audit Log
    AuditService.log_event(
        db=db,
        action=AuditAction.INCIDENT_STATUS_CHANGED,
        resource_type=AuditResourceType.INCIDENT,
        outcome=AuditOutcome.SUCCESS,
        username=current_user.username,
        user_role=current_user.role,
        resource_id=str(updated.id),
        ip_address=request.client.host if request.client else None,
        request_method=request.method,
        request_path=request.url.path,
        status_code=200,
        details={
            "incident_id": updated.id,
            "incident_key": updated.incident_key,
            "previous_status": prev_status,
            "new_status": updated.status,
            "has_resolution": bool(updated.resolution_summary),
        },
    )

    return IncidentService.get_incident_detail(db, incident_id)


@router.patch(
    "/{incident_id}/assign",
    response_model=IncidentDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Assign Incident",
    description="Reassign an incident case to an authorized SOC analyst or administrator.",
)
@limiter.limit(lambda: settings.RATE_LIMIT_MUTATION)
async def assign_incident(
    request: Request,
    incident_id: int,
    payload: IncidentAssignRequest,
    current_user: UserRecord = Depends(require_role("ADMIN", "ANALYST")),
    db: Session = Depends(get_db),
) -> IncidentDetailResponse:
    """Assign incident to verified operator."""
    updated = IncidentService.assign_incident(db, incident_id, payload.assigned_to)

    # Broadcast WebSocket update
    try:
        ws_event = {
            "event_type": "incident_assigned",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {
                "id": updated.id,
                "incident_key": updated.incident_key,
                "assigned_to": updated.assigned_to,
                "assigned_by": current_user.username,
            },
        }
        await websocket_manager.broadcast(ws_event)
    except Exception as ws_err:
        logger.warning("Error broadcasting incident_assigned WebSocket event: %s", ws_err)

    # Emit Audit Log
    AuditService.log_event(
        db=db,
        action=AuditAction.INCIDENT_ASSIGNED,
        resource_type=AuditResourceType.INCIDENT,
        outcome=AuditOutcome.SUCCESS,
        username=current_user.username,
        user_role=current_user.role,
        resource_id=str(updated.id),
        ip_address=request.client.host if request.client else None,
        request_method=request.method,
        request_path=request.url.path,
        status_code=200,
        details={
            "incident_id": updated.id,
            "incident_key": updated.incident_key,
            "assigned_to": updated.assigned_to,
        },
    )

    return IncidentService.get_incident_detail(db, incident_id)


@router.post(
    "/{incident_id}/notes",
    response_model=IncidentNoteResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add Incident Note",
    description="Append an analyst forensic note or triage update to an incident.",
)
@limiter.limit(lambda: settings.RATE_LIMIT_MUTATION)
async def add_incident_note(
    request: Request,
    incident_id: int,
    payload: IncidentNoteCreateRequest,
    current_user: UserRecord = Depends(require_role("ADMIN", "ANALYST")),
    db: Session = Depends(get_db),
) -> IncidentNoteResponse:
    """Record an analyst note on an incident case."""
    note = IncidentService.add_note(db, incident_id, current_user.username, payload.note)

    # Broadcast WebSocket update
    try:
        ws_event = {
            "event_type": "incident_note_added",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {
                "incident_id": incident_id,
                "note_id": note.id,
                "author": note.author,
                "created_at": note.created_at.isoformat(),
            },
        }
        await websocket_manager.broadcast(ws_event)
    except Exception as ws_err:
        logger.warning("Error broadcasting incident_note_added WebSocket event: %s", ws_err)

    # Emit Audit Log (Scrub note body to preserve privacy/security)
    AuditService.log_event(
        db=db,
        action=AuditAction.INCIDENT_NOTE_ADDED,
        resource_type=AuditResourceType.INCIDENT,
        outcome=AuditOutcome.SUCCESS,
        username=current_user.username,
        user_role=current_user.role,
        resource_id=str(incident_id),
        ip_address=request.client.host if request.client else None,
        request_method=request.method,
        request_path=request.url.path,
        status_code=201,
        details={
            "incident_id": incident_id,
            "note_id": note.id,
            "note_length": len(payload.note),
        },
    )

    return IncidentNoteResponse(
        id=note.id,
        incident_id=note.incident_id,
        author=note.author,
        note=note.note,
        created_at=note.created_at,
        updated_at=note.updated_at,
    )


@router.get(
    "/{incident_id}/notes",
    response_model=List[IncidentNoteResponse],
    status_code=status.HTTP_200_OK,
    summary="List Incident Notes",
    description="Retrieve all analyst notes attached to an incident, newest first.",
)
@limiter.limit(lambda: settings.RATE_LIMIT_READ)
def list_incident_notes(
    request: Request,
    incident_id: int,
    current_user: UserRecord = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
) -> List[IncidentNoteResponse]:
    """List notes attached to an incident."""
    notes = IncidentService.get_notes(db, incident_id)
    return [
        IncidentNoteResponse(
            id=n.id,
            incident_id=n.incident_id,
            author=n.author,
            note=n.note,
            created_at=n.created_at,
            updated_at=n.updated_at,
        )
        for n in notes
    ]


@router.get(
    "/{incident_id}/timeline",
    response_model=IncidentTimelineResponse,
    status_code=status.HTTP_200_OK,
    summary="Incident Timeline",
    description="Assemble unified chronological audit events for an incident case.",
)
@limiter.limit(lambda: settings.RATE_LIMIT_READ)
def get_incident_timeline(
    request: Request,
    incident_id: int,
    current_user: UserRecord = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
) -> IncidentTimelineResponse:
    """Retrieve full chronological timeline of events for an incident."""
    return IncidentService.get_incident_timeline(db, incident_id)
