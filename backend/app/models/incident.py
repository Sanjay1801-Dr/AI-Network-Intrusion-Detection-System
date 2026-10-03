"""SQLAlchemy ORM models for Phase 14 SOC Incident Response & Workflow."""

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
)
from sqlalchemy.orm import relationship
from backend.app.db.session import Base


def utc_now() -> datetime:
    """Return timezone-aware current UTC time."""
    return datetime.now(timezone.utc)


# Association table between incidents and alerts
incident_alerts = Table(
    "incident_alerts",
    Base.metadata,
    Column("incident_id", Integer, ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("alert_id", Integer, ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
)

# Association table between incidents and prediction_records
incident_predictions = Table(
    "incident_predictions",
    Base.metadata,
    Column("incident_id", Integer, ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("prediction_id", Integer, ForeignKey("prediction_records.id", ondelete="CASCADE"), primary_key=True),
)


class IncidentRecord(Base):
    """Core SOC Incident entity managing investigation and remediation lifecycle."""

    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_key = Column(String(50), unique=True, nullable=False, index=True)  # e.g. INC-2026-000001
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW
    status = Column(String(30), nullable=False, default="OPEN", index=True)  # OPEN, ACKNOWLEDGED, INVESTIGATING, CONTAINED, RESOLVED
    category = Column(String(50), nullable=False, index=True)  # e.g. DoS, Port Scan, Bot, Web Attack
    source_ip = Column(String(45), nullable=True, index=True)
    assigned_to = Column(String(100), nullable=True, index=True)
    created_by = Column(String(100), nullable=False)

    # Lifecycle Timestamps
    created_at = Column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    investigation_started_at = Column(DateTime(timezone=True), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolution_summary = Column(Text, nullable=True)

    # Relationships
    alerts = relationship("AlertRecord", secondary=incident_alerts, backref="incidents")
    predictions = relationship("PredictionRecord", secondary=incident_predictions, backref="incidents")
    notes = relationship(
        "IncidentNoteRecord",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="desc(IncidentNoteRecord.created_at)",
    )


class IncidentNoteRecord(Base):
    """Analyst case notes and investigation log entries attached to an incident."""

    __tablename__ = "incident_notes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    author = Column(String(100), nullable=False)
    note = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    incident = relationship("IncidentRecord", back_populates="notes")
