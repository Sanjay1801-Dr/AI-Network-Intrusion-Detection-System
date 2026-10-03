"""Pydantic schemas and request/response models for Phase 16 Threat Hunting & Investigation Workbench."""

from datetime import datetime, timezone
import ipaddress
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator, model_validator


class ThreatHuntSearchRequest(BaseModel):
    """Structured query filters for bounded threat hunting investigation."""

    # Network Filters
    source_ip: Optional[str] = Field(None, description="Source IPv4 or IPv6 address")
    destination_ip: Optional[str] = Field(None, description="Destination IPv4 or IPv6 address")
    source_port: Optional[int] = Field(None, ge=1, le=65535, description="Source network port (1-65535)")
    destination_port: Optional[int] = Field(None, ge=1, le=65535, description="Destination network port (1-65535)")
    protocol: Optional[str] = Field(None, max_length=20, description="Transport protocol name or number (e.g. 6, 17, TCP, UDP)")

    # Detection & Severity Filters
    threat_category: Optional[str] = Field(None, max_length=100, description="Threat family e.g. DoS, DDoS, PortScan, Brute Force")
    severity: Optional[str] = Field(None, description="Severity: CRITICAL, HIGH, MEDIUM, LOW")
    risk_level: Optional[str] = Field(None, description="Composite risk level: CRITICAL, HIGH, MEDIUM, LOW")
    min_anomaly_score: Optional[float] = Field(None, ge=-1.0, le=1.0, description="Minimum anomaly score (-1.0 to 1.0)")
    max_anomaly_score: Optional[float] = Field(None, ge=-1.0, le=1.0, description="Maximum anomaly score (-1.0 to 1.0)")
    min_confidence: Optional[float] = Field(None, ge=0.0, le=1.0, description="Minimum ML classifier confidence (0.0 to 1.0)")
    max_confidence: Optional[float] = Field(None, ge=0.0, le=1.0, description="Maximum ML classifier confidence (0.0 to 1.0)")

    # Lifecycle Status Filters
    alert_status: Optional[str] = Field(None, description="Filter alerts by status: NEW, ACKNOWLEDGED, RESOLVED, FALSE_POSITIVE")
    incident_status: Optional[str] = Field(None, description="Filter incidents by status: OPEN, ACKNOWLEDGED, INVESTIGATING, CONTAINED, RESOLVED")

    # Time Filters
    time_range: Optional[str] = Field("24h", description="Predefined range: 1h, 24h, 7d, 30d, or custom")
    start_datetime: Optional[datetime] = Field(None, description="ISO UTC start timestamp for custom range")
    end_datetime: Optional[datetime] = Field(None, description="ISO UTC end timestamp for custom range")

    # Text Search Filter
    query_text: Optional[str] = Field(None, max_length=100, description="Safe text search across categories, titles, and keys")

    # Pagination & Limits
    limit: int = Field(50, ge=1, le=200, description="Max returned results per entity (1-200)")
    offset: int = Field(0, ge=0, description="Pagination offset (>= 0)")

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def validate_ip_address(cls, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        cleaned = v.strip()
        if not cleaned:
            return None
        try:
            ipaddress.ip_address(cleaned)
            return cleaned
        except ValueError:
            raise ValueError(f"Invalid IPv4 or IPv6 address: '{cleaned}'")

    @model_validator(mode="after")
    def validate_ranges(self) -> "ThreatHuntSearchRequest":
        if self.min_anomaly_score is not None and self.max_anomaly_score is not None:
            if self.min_anomaly_score > self.max_anomaly_score:
                raise ValueError("min_anomaly_score cannot be strictly greater than max_anomaly_score")

        if self.min_confidence is not None and self.max_confidence is not None:
            if self.min_confidence > self.max_confidence:
                raise ValueError("min_confidence cannot be strictly greater than max_confidence")

        if self.start_datetime is not None and self.end_datetime is not None:
            if self.start_datetime >= self.end_datetime:
                raise ValueError("start_datetime must be strictly earlier than end_datetime")
            if (self.end_datetime - self.start_datetime).days > 90:
                raise ValueError("Requested hunt time window exceeds maximum allowable limit of 90 days")

        return self


class HuntPredictionItem(BaseModel):
    """Matching prediction record item."""

    id: int
    timestamp: datetime
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    predicted_threat: str
    risk_level: str
    anomaly_score: float
    classification_confidence: float
    intrusion_flag: bool


class HuntAlertItem(BaseModel):
    """Matching security alert record item."""

    id: int
    timestamp: datetime
    prediction_id: Optional[int] = None
    severity: str
    status: str
    alert_type: str
    threat_label: str
    confidence: float
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None


class HuntIncidentItem(BaseModel):
    """Matching incident response case item."""

    id: int
    incident_key: str
    title: str
    severity: str
    status: str
    category: Optional[str] = None
    source_ip: Optional[str] = None
    assigned_to: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class HuntTimelineEvent(BaseModel):
    """Unified chronological investigation timeline event."""

    timestamp: datetime
    event_type: str  # PREDICTION, ALERT_CREATED, ALERT_ACKNOWLEDGED, INCIDENT_CREATED, INCIDENT_NOTE, etc.
    severity: Optional[str] = None
    source: Optional[str] = None
    destination: Optional[str] = None
    resource_type: str
    resource_id: str
    description: str
    details: Optional[Dict[str, Any]] = None


class CorrelationInsight(BaseModel):
    """Structured correlation finding between disparate security events."""

    correlation_type: str  # NETWORK_CONVERGENCE, TEMPORAL_BURST, MULTI_STAGE_INCURSION
    title: str
    description: str
    event_count: int
    confidence: str  # HIGH, MEDIUM, LOW
    disclaimer: str = "Potentially related security activity. Does not conclusively prove attack attribution."


class ThreatHuntSearchResponse(BaseModel):
    """Aggregated search and correlation results for a threat hunt query."""

    total_predictions: int
    total_alerts: int
    total_incidents: int
    matching_predictions: List[HuntPredictionItem] = Field(default_factory=list)
    matching_alerts: List[HuntAlertItem] = Field(default_factory=list)
    matching_incidents: List[HuntIncidentItem] = Field(default_factory=list)
    correlations: List[CorrelationInsight] = Field(default_factory=list)
    applied_filters: Dict[str, Any] = Field(default_factory=dict)
    time_range_label: str
    start_datetime: datetime
    end_datetime: datetime
    limit: int
    offset: int


class SourceInvestigationResponse(BaseModel):
    """Comprehensive source-centric investigation profile."""

    ip_address: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    total_observations: int = 0
    threat_categories: List[Dict[str, Any]] = Field(default_factory=list)
    severity_distribution: Dict[str, int] = Field(default_factory=dict)
    observed_destinations: List[Dict[str, Any]] = Field(default_factory=list)
    destination_ports: List[int] = Field(default_factory=list)
    protocols: List[str] = Field(default_factory=list)
    predictions: List[HuntPredictionItem] = Field(default_factory=list)
    alerts: List[HuntAlertItem] = Field(default_factory=list)
    incidents: List[HuntIncidentItem] = Field(default_factory=list)
    timeline: List[HuntTimelineEvent] = Field(default_factory=list)
    correlations: List[CorrelationInsight] = Field(default_factory=list)
    disclaimer: str = (
        "DEFENSIVE MONITORING NOTICE: Source activity reflects observed network flow telemetry in the NIDS database. "
        "Presence in records indicates detection triggers and does not alone establish malicious intent."
    )


class ThreatHuntingSummaryResponse(BaseModel):
    """High-level investigation workbench metrics."""

    total_flows_investigated: int = 0
    total_threat_detections: int = 0
    total_active_alerts: int = 0
    total_open_incidents: int = 0
    unique_source_ips: int = 0
    top_investigated_threats: List[Dict[str, Any]] = Field(default_factory=list)
    top_active_sources: List[Dict[str, Any]] = Field(default_factory=list)


class HuntQueryHistoryItem(BaseModel):
    """Lightweight, sanitized query history record for reloading previous hunt parameters."""

    id: int
    timestamp: datetime
    username: str
    filter_summary: str
    filters: Dict[str, Any] = Field(default_factory=dict)
    result_count: int
