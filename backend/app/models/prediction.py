"""SQLAlchemy ORM model for network flow prediction telemetry history."""

from datetime import datetime, timezone
from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship
from backend.app.db.session import Base


def utc_now() -> datetime:
    """Return timezone-aware current UTC time."""
    return datetime.now(timezone.utc)


class PredictionRecord(Base):
    """Stores full audit telemetry and AI evaluation for a single network flow prediction."""

    __tablename__ = "prediction_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)

    # Optional Network Flow Telemetry (Client-supplied network telemetry, not authentication identities)
    source_ip = Column(String(45), nullable=True, index=True)
    destination_ip = Column(String(45), nullable=True, index=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True, index=True)
    protocol = Column(String(20), nullable=True)
    flow_duration = Column(Float, nullable=True)
    total_forward_packets = Column(BigInteger, nullable=True)
    total_backward_packets = Column(BigInteger, nullable=True)
    total_bytes = Column(BigInteger, nullable=True)

    # AI Anomaly Detection Results
    anomaly_label = Column(String(30), nullable=False)
    anomaly_score = Column(Float, nullable=False)
    raw_decision_score = Column(Float, nullable=False)

    # AI Threat Classification Results
    predicted_threat = Column(String(50), nullable=False, index=True)
    intrusion_flag = Column(Boolean, nullable=False)
    classification_confidence = Column(Float, nullable=False)

    # Dual-Engine Composite Risk Triage
    risk_level = Column(String(20), nullable=False, index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    recommended_action = Column(String(255), nullable=False)

    # System & Audit Metadata
    model_version = Column(String(50), nullable=True, default="1.0.0-phase3")
    raw_flow_data = Column(Text, nullable=True)  # Compact sanitized JSON of input features
    created_at = Column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)

    # Relationships
    alerts = relationship("AlertRecord", back_populates="prediction", cascade="all, delete-orphan")
