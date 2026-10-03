"""Domain service coordinating security alert lifecycle state transitions (Phase 8)."""

from datetime import datetime, timezone
import logging
from sqlalchemy.orm import Session

from backend.app.core.errors import ConflictException, ResourceNotFoundException, AppException
from backend.app.models.alert import AlertRecord
from backend.app.repositories.alert_repository import AlertRepository

logger = logging.getLogger("nids.services.alert")


class AlertService:
    """Encapsulates alert lifecycle validation and atomic state persistence.
    
    Permitted Transitions:
    - NEW -> ACKNOWLEDGED
    - ACKNOWLEDGED -> RESOLVED
    - NEW -> RESOLVED
    
    Disallowed Transitions:
    - RESOLVED -> any state (Terminal state, HTTP 409)
    - ACKNOWLEDGED -> NEW (Regression disallowed, HTTP 409)
    - Current == Target (Redundant transition, HTTP 409)
    """

    @classmethod
    def get_alert(cls, db: Session, alert_id: int) -> AlertRecord:
        """Fetch an alert record by primary key or raise ResourceNotFoundException."""
        alert = AlertRepository.get_by_id(db, alert_id)
        if not alert:
            raise ResourceNotFoundException("Alert", alert_id)
        return alert

    @classmethod
    def acknowledge_alert(cls, db: Session, alert_id: int) -> AlertRecord:
        """Acknowledge a security alert, moving its lifecycle from NEW to ACKNOWLEDGED."""
        alert = AlertRepository.get_by_id(db, alert_id)
        if not alert:
            raise ResourceNotFoundException("Alert", alert_id)

        current_status = str(alert.status).upper()

        if current_status == "ACKNOWLEDGED":
            raise ConflictException(
                message=f"Alert #{alert_id} is already in ACKNOWLEDGED status.",
                details={"alert_id": alert_id, "current_status": current_status, "target_status": "ACKNOWLEDGED"},
            )

        if current_status == "RESOLVED":
            raise ConflictException(
                message=f"Cannot acknowledge alert #{alert_id}: alert is already in terminal status RESOLVED.",
                details={"alert_id": alert_id, "current_status": current_status, "target_status": "ACKNOWLEDGED"},
            )

        if current_status != "NEW":
            raise ConflictException(
                message=f"Invalid lifecycle transition for alert #{alert_id} from {current_status} to ACKNOWLEDGED.",
                details={"alert_id": alert_id, "current_status": current_status, "target_status": "ACKNOWLEDGED"},
            )

        now = datetime.now(timezone.utc)
        alert.status = "ACKNOWLEDGED"
        alert.acknowledged_at = now

        try:
            db.add(alert)
            db.commit()
            db.refresh(alert)
            logger.info("Alert #%d transitioned to ACKNOWLEDGED at %s", alert.id, now.isoformat())
            return alert
        except Exception as exc:
            db.rollback()
            logger.error("Failed persisting alert #%d acknowledgement: %s", alert_id, exc, exc_info=True)
            raise AppException(
                message="Database error occurred while persisting alert acknowledgement.",
                error_code="DATABASE_PERSISTENCE_ERROR",
                status_code=500,
            )

    @classmethod
    def resolve_alert(cls, db: Session, alert_id: int) -> AlertRecord:
        """Resolve a security alert, moving its lifecycle from NEW or ACKNOWLEDGED to RESOLVED."""
        alert = AlertRepository.get_by_id(db, alert_id)
        if not alert:
            raise ResourceNotFoundException("Alert", alert_id)

        current_status = str(alert.status).upper()

        if current_status == "RESOLVED":
            raise ConflictException(
                message=f"Alert #{alert_id} is already in terminal status RESOLVED.",
                details={"alert_id": alert_id, "current_status": current_status, "target_status": "RESOLVED"},
            )

        if current_status not in ("NEW", "ACKNOWLEDGED"):
            raise ConflictException(
                message=f"Invalid lifecycle transition for alert #{alert_id} from {current_status} to RESOLVED.",
                details={"alert_id": alert_id, "current_status": current_status, "target_status": "RESOLVED"},
            )

        now = datetime.now(timezone.utc)
        alert.status = "RESOLVED"
        alert.resolved_at = now
        # Retain original acknowledged_at if it was previously set; otherwise remains None

        try:
            db.add(alert)
            db.commit()
            db.refresh(alert)
            logger.info("Alert #%d transitioned to RESOLVED at %s", alert.id, now.isoformat())
            return alert
        except Exception as exc:
            db.rollback()
            logger.error("Failed persisting alert #%d resolution: %s", alert_id, exc, exc_info=True)
            raise AppException(
                message="Database error occurred while persisting alert resolution.",
                error_code="DATABASE_PERSISTENCE_ERROR",
                status_code=500,
            )
