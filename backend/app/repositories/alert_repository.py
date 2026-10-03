"""Repository pattern for database operations on AlertRecord entities."""

from typing import List, Optional, Tuple
from sqlalchemy.orm import Session
from backend.app.models.alert import AlertRecord


class AlertRepository:
    """Encapsulates transactional queries and inserts for security alert records."""

    @staticmethod
    def create(db: Session, alert: AlertRecord) -> AlertRecord:
        """Persist a new security alert record in the active database session."""
        db.add(alert)
        db.flush()
        return alert

    @staticmethod
    def get_by_id(db: Session, alert_id: int) -> Optional[AlertRecord]:
        """Retrieve a security alert record by its primary key ID."""
        return db.query(AlertRecord).filter(AlertRecord.id == alert_id).first()

    @staticmethod
    def list(
        db: Session,
        limit: int = 20,
        offset: int = 0,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Tuple[List[AlertRecord], int]:
        """Fetch paginated security alerts with optional severity and status filters.

        Returns:
            Tuple of (list of alerts, total matching count).
        """
        query = db.query(AlertRecord)

        if severity:
            query = query.filter(AlertRecord.severity == severity.upper().strip())

        if status:
            query = query.filter(AlertRecord.status == status.upper().strip())

        total_count = query.count()
        alerts = (
            query.order_by(AlertRecord.created_at.desc(), AlertRecord.id.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return alerts, total_count
