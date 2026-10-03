"""Domain service managing SOC incident response workflows, state machine, and timeline (Phase 14)."""

from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app.core.errors import ConflictException, ResourceNotFoundException, ValidationException, AppException
from backend.app.models.alert import AlertRecord
from backend.app.models.audit import AuditLogRecord
from backend.app.models.incident import IncidentRecord, IncidentNoteRecord, incident_alerts, incident_predictions
from backend.app.models.prediction import PredictionRecord
from backend.app.models.user import UserRecord
from backend.app.schemas.audit import AuditAction
from backend.app.schemas.incident import (
    IncidentCreateRequest,
    IncidentDetailResponse,
    IncidentNoteResponse,
    IncidentResponse,
    IncidentStatus,
    IncidentSummaryResponse,
    IncidentTimelineEvent,
    IncidentTimelineResponse,
)

logger = logging.getLogger("nids.services.incident")

# Incident State Machine Definition
VALID_STATUS_TRANSITIONS: Dict[str, List[str]] = {
    "OPEN": ["ACKNOWLEDGED", "RESOLVED"],
    "ACKNOWLEDGED": ["INVESTIGATING", "CONTAINED", "RESOLVED"],
    "INVESTIGATING": ["CONTAINED", "RESOLVED"],
    "CONTAINED": ["RESOLVED"],
    "RESOLVED": [],  # Terminal state
}

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def utc_now() -> datetime:
    """Return timezone-aware current UTC time."""
    return datetime.now(timezone.utc)


class IncidentService:
    """Encapsulates incident lifecycle management, validation, notes, assignment, and timeline."""

    @classmethod
    def generate_incident_key(cls, db: Session) -> str:
        """Generate a sequential, collision-resistant incident key: INC-YYYY-XXXXXX."""
        year = utc_now().year
        prefix = f"INC-{year}-"

        # Count existing incidents for this calendar year
        existing_count = (
            db.query(func.count(IncidentRecord.id))
            .filter(IncidentRecord.incident_key.like(f"{prefix}%"))
            .scalar()
            or 0
        )

        seq = existing_count + 1
        candidate = f"{prefix}{seq:06d}"

        # Guarantee uniqueness against race conditions
        while db.query(IncidentRecord).filter(IncidentRecord.incident_key == candidate).first():
            seq += 1
            candidate = f"{prefix}{seq:06d}"

        return candidate

    @classmethod
    def get_incident(cls, db: Session, incident_id: int) -> IncidentRecord:
        """Fetch an incident by primary key or raise ResourceNotFoundException."""
        incident = db.query(IncidentRecord).filter(IncidentRecord.id == incident_id).first()
        if not incident:
            raise ResourceNotFoundException("IncidentRecord", incident_id)
        return incident

    @classmethod
    def create_incident(
        cls,
        db: Session,
        request: IncidentCreateRequest,
        created_by_user: str,
    ) -> IncidentRecord:
        """Create a new incident, optionally linked to an alert or prediction."""
        alert: Optional[AlertRecord] = None
        prediction: Optional[PredictionRecord] = None

        # 1. Alert Correlation & Duplicate Prevention
        if request.alert_id is not None:
            alert = db.query(AlertRecord).filter(AlertRecord.id == request.alert_id).first()
            if not alert:
                raise ResourceNotFoundException("AlertRecord", request.alert_id)

            # Prevent duplicate active incident for the same alert
            active_existing = (
                db.query(IncidentRecord)
                .join(incident_alerts, IncidentRecord.id == incident_alerts.c.incident_id)
                .filter(
                    incident_alerts.c.alert_id == request.alert_id,
                    IncidentRecord.status.in_(["OPEN", "ACKNOWLEDGED", "INVESTIGATING", "CONTAINED"]),
                )
                .first()
            )
            if active_existing:
                raise ConflictException(
                    message=f"An active incident ({active_existing.incident_key}) already exists for Alert #{request.alert_id}.",
                    details={"alert_id": request.alert_id, "active_incident_key": active_existing.incident_key},
                )

        # 2. Prediction Correlation
        if request.prediction_id is not None:
            prediction = db.query(PredictionRecord).filter(PredictionRecord.id == request.prediction_id).first()
            if not prediction:
                raise ResourceNotFoundException("PredictionRecord", request.prediction_id)

        # 3. Determine Inherited Severity & Category
        severity = request.severity
        if not severity:
            if alert:
                severity = str(alert.severity).upper()
            elif prediction:
                severity = str(prediction.risk_level).upper()
            else:
                severity = "HIGH"

        severity = severity.upper()
        if severity not in VALID_SEVERITIES:
            raise ValidationException(
                f"Invalid severity '{severity}'. Must be one of: {', '.join(sorted(VALID_SEVERITIES))}."
            )

        category = request.category
        if not category:
            if alert:
                category = alert.threat_label
            elif prediction:
                category = prediction.predicted_threat
            else:
                category = "Suspicious Network Activity"

        source_ip = None
        if alert and alert.source_ip:
            source_ip = alert.source_ip
        elif prediction and prediction.source_ip:
            source_ip = prediction.source_ip

        # 4. Optional Initial Operator Assignment Validation
        assigned_to_user = None
        if request.assigned_to:
            assigned_to_user = cls.validate_assignee(db, request.assigned_to)

        # 5. Persist Incident
        incident_key = cls.generate_incident_key(db)
        now = utc_now()

        incident = IncidentRecord(
            incident_key=incident_key,
            title=request.title.strip(),
            description=request.description.strip() if request.description else None,
            severity=severity,
            status=IncidentStatus.OPEN.value,
            category=category,
            source_ip=source_ip,
            assigned_to=assigned_to_user,
            created_by=created_by_user,
            created_at=now,
            updated_at=now,
        )

        if alert:
            incident.alerts.append(alert)
            # If the alert has an underlying prediction, link that prediction as well
            if alert.prediction and alert.prediction not in incident.predictions:
                incident.predictions.append(alert.prediction)

        if prediction and prediction not in incident.predictions:
            incident.predictions.append(prediction)

        try:
            db.add(incident)
            db.commit()
            db.refresh(incident)
            logger.info("Created incident %s (ID: %d) by %s", incident.incident_key, incident.id, created_by_user)
            return incident
        except Exception as exc:
            db.rollback()
            logger.error("Failed persisting new incident: %s", exc, exc_info=True)
            raise AppException("Database error occurred while persisting incident.", status_code=500)

    @classmethod
    def validate_assignee(cls, db: Session, username: str) -> str:
        """Verify assignee exists, is active, and holds an authorized SOC role (ANALYST or ADMIN)."""
        clean_name = username.strip()
        user = db.query(UserRecord).filter(UserRecord.username == clean_name).first()
        if not user:
            raise ResourceNotFoundException("User", clean_name)

        if not user.is_active:
            raise ValidationException(
                message=f"Operator '{clean_name}' is inactive and cannot be assigned incidents.",
                details={"username": clean_name, "is_active": False},
            )

        if user.role.upper() == "VIEWER":
            raise ValidationException(
                message=f"Operator '{clean_name}' has VIEWER role. Incidents can only be assigned to ANALYST or ADMIN operators.",
                details={"username": clean_name, "role": user.role},
            )

        return user.username

    @classmethod
    def assign_incident(cls, db: Session, incident_id: int, assigned_to: str) -> IncidentRecord:
        """Reassign an incident to a verified operator."""
        incident = cls.get_incident(db, incident_id)
        valid_username = cls.validate_assignee(db, assigned_to)

        incident.assigned_to = valid_username
        incident.updated_at = utc_now()

        try:
            db.add(incident)
            db.commit()
            db.refresh(incident)
            logger.info("Incident %s reassigned to %s", incident.incident_key, valid_username)
            return incident
        except Exception as exc:
            db.rollback()
            logger.error("Failed updating assignment for incident #%d: %s", incident_id, exc)
            raise AppException("Database error occurred while reassigning incident.", status_code=500)

    @classmethod
    def update_status(
        cls,
        db: Session,
        incident_id: int,
        new_status_raw: str,
        resolution_summary: Optional[str] = None,
    ) -> IncidentRecord:
        """Validate and apply state machine transition for an incident."""
        incident = cls.get_incident(db, incident_id)
        current = str(incident.status).upper()
        target = str(new_status_raw).upper().strip()

        # Check self-transition
        if current == target:
            raise ConflictException(
                message=f"Incident {incident.incident_key} is already in status '{target}'.",
                details={"incident_id": incident_id, "current_status": current, "target_status": target},
            )

        # Check terminal state
        if current == "RESOLVED":
            raise ConflictException(
                message=f"Cannot transition incident {incident.incident_key}: incident is in terminal status RESOLVED.",
                details={"incident_id": incident_id, "current_status": current, "target_status": target},
            )

        # Validate state machine rules
        allowed = VALID_STATUS_TRANSITIONS.get(current, [])
        if target not in allowed:
            raise ConflictException(
                message=f"Invalid incident status transition from '{current}' to '{target}'. Allowed: {', '.join(allowed)}.",
                details={"incident_id": incident_id, "current_status": current, "target_status": target, "allowed": allowed},
            )

        now = utc_now()

        # Handle resolution requirements
        if target == "RESOLVED":
            if not resolution_summary or len(resolution_summary.strip()) < 5:
                raise ValidationException(
                    message="A resolution summary (minimum 5 characters) is required when resolving an incident.",
                    details={"field": "resolution_summary"},
                )
            incident.resolved_at = now
            incident.resolution_summary = resolution_summary.strip()

        # Update lifecycle transition timestamps
        if target == "ACKNOWLEDGED" and not incident.acknowledged_at:
            incident.acknowledged_at = now
        elif target == "INVESTIGATING" and not incident.investigation_started_at:
            incident.investigation_started_at = now

        incident.status = target
        incident.updated_at = now

        try:
            db.add(incident)
            db.commit()
            db.refresh(incident)
            logger.info("Incident %s transitioned from %s to %s", incident.incident_key, current, target)
            return incident
        except Exception as exc:
            db.rollback()
            logger.error("Failed updating status for incident #%d: %s", incident_id, exc)
            raise AppException("Database error occurred while updating incident status.", status_code=500)

    @classmethod
    def add_note(cls, db: Session, incident_id: int, author: str, note_text: str) -> IncidentNoteRecord:
        """Append an analyst note to an incident."""
        incident = cls.get_incident(db, incident_id)
        clean_note = note_text.strip()
        if not clean_note:
            raise ValidationException("Note content cannot be empty.")

        now = utc_now()
        note = IncidentNoteRecord(
            incident_id=incident.id,
            author=author,
            note=clean_note,
            created_at=now,
            updated_at=now,
        )
        incident.updated_at = now

        try:
            db.add(note)
            db.add(incident)
            db.commit()
            db.refresh(note)
            logger.info("Note #%d added to incident %s by %s", note.id, incident.incident_key, author)
            return note
        except Exception as exc:
            db.rollback()
            logger.error("Failed adding note to incident #%d: %s", incident_id, exc)
            raise AppException("Database error occurred while adding incident note.", status_code=500)

    @classmethod
    def get_notes(cls, db: Session, incident_id: int) -> List[IncidentNoteRecord]:
        """Retrieve all analyst notes for an incident, sorted newest first."""
        cls.get_incident(db, incident_id)  # Validate existence
        return (
            db.query(IncidentNoteRecord)
            .filter(IncidentNoteRecord.incident_id == incident_id)
            .order_by(IncidentNoteRecord.created_at.desc())
            .all()
        )

    @classmethod
    def list_incidents(
        cls,
        db: Session,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        assigned_to: Optional[str] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> Tuple[List[IncidentResponse], int]:
        """Retrieve paginated incidents with dynamic multi-attribute filtering."""
        query = db.query(IncidentRecord)

        if status:
            query = query.filter(IncidentRecord.status == status.upper().strip())
        if severity:
            query = query.filter(IncidentRecord.severity == severity.upper().strip())
        if category:
            query = query.filter(IncidentRecord.category == category.strip())
        if assigned_to:
            query = query.filter(IncidentRecord.assigned_to == assigned_to.strip())

        total = query.count()
        records = (
            query.order_by(IncidentRecord.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        items = []
        for inc in records:
            items.append(
                IncidentResponse(
                    id=inc.id,
                    incident_key=inc.incident_key,
                    title=inc.title,
                    description=inc.description,
                    severity=inc.severity,
                    status=inc.status,
                    category=inc.category,
                    source_ip=inc.source_ip,
                    assigned_to=inc.assigned_to,
                    created_by=inc.created_by,
                    created_at=inc.created_at,
                    updated_at=inc.updated_at,
                    acknowledged_at=inc.acknowledged_at,
                    investigation_started_at=inc.investigation_started_at,
                    resolved_at=inc.resolved_at,
                    resolution_summary=inc.resolution_summary,
                    alerts_count=len(inc.alerts),
                    predictions_count=len(inc.predictions),
                    notes_count=len(inc.notes),
                )
            )

        return items, total

    @classmethod
    def get_incident_detail(cls, db: Session, incident_id: int) -> IncidentDetailResponse:
        """Fetch deep incident entity with serialized alerts, predictions, and case notes."""
        incident = cls.get_incident(db, incident_id)

        # Serialize related alerts
        alerts_data = [
            {
                "id": a.id,
                "status": a.status,
                "severity": a.severity,
                "threat_label": a.threat_label,
                "anomaly_score": a.anomaly_score,
                "confidence": a.confidence,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in incident.alerts
        ]

        # Serialize related predictions
        predictions_data = [
            {
                "id": p.id,
                "predicted_threat": p.predicted_threat,
                "risk_level": p.risk_level,
                "anomaly_score": p.anomaly_score,
                "classification_confidence": p.classification_confidence,
                "timestamp": p.timestamp.isoformat() if p.timestamp else None,
            }
            for p in incident.predictions
        ]

        # Serialize notes
        notes_data = [
            IncidentNoteResponse(
                id=n.id,
                incident_id=n.incident_id,
                author=n.author,
                note=n.note,
                created_at=n.created_at,
                updated_at=n.updated_at,
            )
            for n in incident.notes
        ]

        return IncidentDetailResponse(
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
            alerts=alerts_data,
            predictions=predictions_data,
            notes=notes_data,
        )

    @classmethod
    def get_incident_summary(cls, db: Session) -> IncidentSummaryResponse:
        """Compute aggregated incident metrics for the SOC dashboard."""
        total = db.query(func.count(IncidentRecord.id)).scalar() or 0
        open_cnt = db.query(func.count(IncidentRecord.id)).filter(IncidentRecord.status == "OPEN").scalar() or 0
        ack_cnt = db.query(func.count(IncidentRecord.id)).filter(IncidentRecord.status == "ACKNOWLEDGED").scalar() or 0
        inv_cnt = db.query(func.count(IncidentRecord.id)).filter(IncidentRecord.status == "INVESTIGATING").scalar() or 0
        cont_cnt = db.query(func.count(IncidentRecord.id)).filter(IncidentRecord.status == "CONTAINED").scalar() or 0
        res_cnt = db.query(func.count(IncidentRecord.id)).filter(IncidentRecord.status == "RESOLVED").scalar() or 0

        crit_cnt = db.query(func.count(IncidentRecord.id)).filter(IncidentRecord.severity == "CRITICAL").scalar() or 0
        high_cnt = db.query(func.count(IncidentRecord.id)).filter(IncidentRecord.severity == "HIGH").scalar() or 0

        # Recently resolved in last 24h
        since_24h = utc_now() - timedelta(hours=24)
        recently_resolved = (
            db.query(func.count(IncidentRecord.id))
            .filter(IncidentRecord.status == "RESOLVED", IncidentRecord.resolved_at >= since_24h)
            .scalar()
            or 0
        )

        return IncidentSummaryResponse(
            total_incidents=int(total),
            open_incidents=int(open_cnt),
            acknowledged_incidents=int(ack_cnt),
            investigating_incidents=int(inv_cnt),
            contained_incidents=int(cont_cnt),
            resolved_incidents=int(res_cnt),
            critical_incidents=int(crit_cnt),
            high_incidents=int(high_cnt),
            recently_resolved=int(recently_resolved),
        )

    @classmethod
    def get_incident_timeline(cls, db: Session, incident_id: int) -> IncidentTimelineResponse:
        """Assemble unified chronological audit events for an incident."""
        incident = cls.get_incident(db, incident_id)
        events: List[IncidentTimelineEvent] = []

        # 1. Incident Creation Event
        events.append(
            IncidentTimelineEvent(
                timestamp=incident.created_at,
                event_type="INCIDENT_CREATED",
                actor=incident.created_by,
                summary=f"Incident {incident.incident_key} created with severity {incident.severity}.",
                details={"category": incident.category, "severity": incident.severity},
            )
        )

        # 2. Lifecycle Transition Timestamps
        if incident.acknowledged_at:
            events.append(
                IncidentTimelineEvent(
                    timestamp=incident.acknowledged_at,
                    event_type="INCIDENT_ACKNOWLEDGED",
                    actor=incident.assigned_to or "SOC Analyst",
                    summary="Incident acknowledged and triaged.",
                )
            )

        if incident.investigation_started_at:
            events.append(
                IncidentTimelineEvent(
                    timestamp=incident.investigation_started_at,
                    event_type="INVESTIGATION_STARTED",
                    actor=incident.assigned_to or "SOC Analyst",
                    summary="Active forensic investigation initiated.",
                )
            )

        if incident.resolved_at:
            events.append(
                IncidentTimelineEvent(
                    timestamp=incident.resolved_at,
                    event_type="INCIDENT_RESOLVED",
                    actor=incident.assigned_to or "SOC Lead",
                    summary=f"Incident resolved: {incident.resolution_summary or 'Remediated'}",
                    details={"resolution_summary": incident.resolution_summary},
                )
            )

        # 3. Analyst Notes
        for n in incident.notes:
            events.append(
                IncidentTimelineEvent(
                    timestamp=n.created_at,
                    event_type="INCIDENT_NOTE_ADDED",
                    actor=n.author,
                    summary=f"Analyst note added: {n.note[:80]}..." if len(n.note) > 80 else f"Analyst note: {n.note}",
                    details={"note_id": n.id},
                )
            )

        # 4. Associated Alerts
        for a in incident.alerts:
            events.append(
                IncidentTimelineEvent(
                    timestamp=a.created_at or incident.created_at,
                    event_type="LINKED_ALERT",
                    actor="DETECTION_ENGINE",
                    summary=f"Linked Alert #{a.id} ({a.threat_label}, severity {a.severity}).",
                    details={"alert_id": a.id, "threat_label": a.threat_label, "severity": a.severity},
                )
            )

        # 5. Associated Predictions
        for p in incident.predictions:
            events.append(
                IncidentTimelineEvent(
                    timestamp=p.timestamp,
                    event_type="LINKED_PREDICTION",
                    actor="DETECTION_ENGINE",
                    summary=f"Linked Prediction #{p.id} ({p.predicted_threat}, risk {p.risk_level}).",
                    details={"prediction_id": p.id, "threat": p.predicted_threat, "risk": p.risk_level},
                )
            )

        # 6. Audit Trail Logs associated with this incident
        audit_records = (
            db.query(AuditLogRecord)
            .filter(AuditLogRecord.resource_id == str(incident.id))
            .filter(AuditLogRecord.action.in_([
                AuditAction.INCIDENT_ASSIGNED.value,
                AuditAction.INCIDENT_STATUS_CHANGED.value,
            ]))
            .all()
        )
        for log in audit_records:
            log_details = {}
            if log.details:
                if isinstance(log.details, dict):
                    log_details = log.details
                elif isinstance(log.details, str):
                    try:
                        import json
                        log_details = json.loads(log.details)
                    except Exception:
                        log_details = {"info": log.details}

            events.append(
                IncidentTimelineEvent(
                    timestamp=log.timestamp,
                    event_type=log.action,
                    actor=log.username or "SYSTEM",
                    summary=f"Audit event: {log.action}",
                    details=log_details,
                )
            )

        # Sort chronological (newest first for analyst inspection)
        events.sort(key=lambda e: e.timestamp, reverse=True)

        return IncidentTimelineResponse(
            incident_id=incident.id,
            incident_key=incident.incident_key,
            total_events=len(events),
            events=events,
            timeline=events,
        )
