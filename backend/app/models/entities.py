"""SQLAlchemy ORM models defining the core entities for the NIDS platform."""

import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Text,
    CheckConstraint,
)
from sqlalchemy.orm import relationship
from backend.app.db.session import Base


def generate_uuid() -> str:
    """Generate a string representation of a standard UUID4."""
    return str(uuid.uuid4())


def utc_now() -> datetime:
    """Return timezone-aware current UTC time."""
    return datetime.now(timezone.utc)


class SystemNode(Base):
    """Represents a monitored internal host, server, or sensor gateway."""

    __tablename__ = "system_nodes"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    hostname = Column(String(100), nullable=False)
    ip_address = Column(String(45), nullable=False, unique=True, index=True)
    environment = Column(String(30), default="production")
    criticality_level = Column(Integer, default=2)  # 1=Low, 2=Medium, 3=High, 4=Mission-Critical
    is_active = Column(Boolean, default=True)
    last_seen = Column(DateTime(timezone=True), default=utc_now)


# Import UserRecord as User alias for backwards compatibility
from backend.app.models.user import UserRecord as User


class TrafficRecord(Base):
    """Raw or parsed network flow telemetry record."""

    __tablename__ = "traffic_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    captured_at = Column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)
    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=False, index=True)
    source_port = Column(Integer, nullable=False)
    destination_port = Column(Integer, nullable=False, index=True)
    protocol = Column(String(10), nullable=False, index=True)  # TCP, UDP, ICMP
    duration_seconds = Column(Float, default=0.0, nullable=False)
    total_packets = Column(BigInteger, default=0, nullable=False)
    total_bytes = Column(BigInteger, default=0, nullable=False)
    syn_flag_count = Column(Integer, default=0, nullable=False)
    ack_flag_count = Column(Integer, default=0, nullable=False)
    rst_flag_count = Column(Integer, default=0, nullable=False)
    fin_flag_count = Column(Integer, default=0, nullable=False)
    is_suspicious = Column(Boolean, default=False, nullable=False)

    __table_args__ = (
        CheckConstraint("source_port >= 0 AND source_port <= 65535", name="check_src_port_range"),
        CheckConstraint("destination_port >= 0 AND destination_port <= 65535", name="check_dst_port_range"),
    )

    # Relationships
    threat_events = relationship("ThreatEvent", back_populates="traffic_record", cascade="all, delete-orphan")
    ml_predictions = relationship("MLPrediction", back_populates="traffic_record", cascade="all, delete-orphan")


class ThreatEvent(Base):
    """Security threat or behavioral anomaly flagged in a traffic flow."""

    __tablename__ = "threat_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    traffic_record_id = Column(String(36), ForeignKey("traffic_records.id", ondelete="CASCADE"), nullable=False)
    threat_type = Column(String(50), nullable=False, index=True)  # DoS, PortScan, BruteForce, Anomaly
    anomaly_score = Column(Float, default=0.0, nullable=False)
    confidence_score = Column(Float, default=0.0, nullable=False)
    severity = Column(String(20), nullable=False, index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(30), default="DETECTED", nullable=False)  # DETECTED, INVESTIGATING, MITIGATED, DISMISSED
    detected_at = Column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)
    analysis_notes = Column(Text, nullable=True)

    __table_args__ = (
        CheckConstraint("severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')", name="check_threat_severity"),
    )

    # Relationships
    traffic_record = relationship("TrafficRecord", back_populates="threat_events")
    security_alerts = relationship("SecurityAlert", back_populates="threat_event", cascade="all, delete-orphan")


class SecurityAlert(Base):
    """High-priority incident notification displayed on the SOC alert queue."""

    __tablename__ = "security_alerts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    threat_event_id = Column(String(36), ForeignKey("threat_events.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(150), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False, index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(30), default="NEW", index=True, nullable=False)  # NEW, ACKNOWLEDGED, RESOLVED, FALSE_POSITIVE
    created_at = Column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint("severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')", name="check_alert_severity"),
        CheckConstraint("status IN ('NEW', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE')", name="check_alert_status"),
    )

    # Relationships
    threat_event = relationship("ThreatEvent", back_populates="security_alerts")


class MLPrediction(Base):
    """Audit log of machine learning inference operations."""

    __tablename__ = "ml_predictions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    traffic_record_id = Column(String(36), ForeignKey("traffic_records.id", ondelete="CASCADE"), nullable=False)
    model_name = Column(String(80), nullable=False)
    model_version = Column(String(20), nullable=False)
    inference_latency_ms = Column(Float, nullable=False)
    raw_prediction = Column(String(100), nullable=False)
    prediction_probabilities = Column(Text, nullable=True)  # Serialized JSON
    executed_at = Column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)

    # Relationships
    traffic_record = relationship("TrafficRecord", back_populates="ml_predictions")
