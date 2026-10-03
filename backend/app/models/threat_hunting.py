"""SQLAlchemy ORM model for threat hunting query history (Phase 16)."""

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    String,
    Text,
)
from backend.app.db.session import Base


def utc_now() -> datetime:
    """Return timezone-aware current UTC time."""
    return datetime.now(timezone.utc)


class HuntQueryHistoryRecord(Base):
    """Stores lightweight, sanitized query history entries for SOC threat hunters."""

    __tablename__ = "threat_hunt_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)
    username = Column(String(50), nullable=False, index=True)
    filter_summary = Column(String(255), nullable=False)
    filters_json = Column(Text, nullable=False)  # Sanitized JSON of search parameters for reloading
    result_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
