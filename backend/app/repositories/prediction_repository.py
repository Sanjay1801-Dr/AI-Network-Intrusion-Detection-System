"""Repository pattern for database operations on PredictionRecord entities."""

from typing import List, Optional, Tuple
from sqlalchemy import func
from sqlalchemy.orm import Session
from backend.app.models.prediction import PredictionRecord


class PredictionRepository:
    """Encapsulates transactional queries and inserts for prediction records."""

    @staticmethod
    def create(db: Session, record: PredictionRecord) -> PredictionRecord:
        """Persist a new prediction record in the active database session."""
        db.add(record)
        db.flush()
        return record

    @staticmethod
    def get_by_id(db: Session, prediction_id: int) -> Optional[PredictionRecord]:
        """Retrieve a prediction record by its primary key ID."""
        return db.query(PredictionRecord).filter(PredictionRecord.id == prediction_id).first()

    @staticmethod
    def list(
        db: Session,
        limit: int = 20,
        offset: int = 0,
    ) -> Tuple[List[PredictionRecord], int]:
        """Fetch paginated prediction history records ordered newest first.

        Returns:
            Tuple of (list of records, total count).
        """
        query = db.query(PredictionRecord)
        total_count = db.query(func.count(PredictionRecord.id)).scalar() or 0
        records = (
            query.order_by(PredictionRecord.created_at.desc(), PredictionRecord.id.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return records, total_count
