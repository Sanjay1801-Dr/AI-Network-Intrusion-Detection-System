"""Pydantic schemas for Phase 13 Security Analytics & Threat Intelligence."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class AnalyticsOverviewResponse(BaseModel):
    """Structured security telemetry metrics across predictions, alerts, and access controls."""

    model_config = ConfigDict(from_attributes=True)

    # Prediction Analytics
    total_predictions: int = Field(default=0, description="Total network flow evaluations")
    benign_predictions: int = Field(default=0, description="Flows evaluated as benign")
    malicious_predictions: int = Field(default=0, description="Flows flagged as malicious attacks")
    anomaly_predictions: int = Field(default=0, description="Outlier divergences detected by Isolation Forest")

    # Alert Incident Analytics
    total_alerts: int = Field(default=0, description="Total security incident alerts generated")
    open_alerts: int = Field(default=0, description="Active alerts in NEW or ACKNOWLEDGED status")
    critical_alerts: int = Field(default=0, description="Alerts with CRITICAL severity")
    high_alerts: int = Field(default=0, description="Alerts with HIGH severity")
    medium_alerts: int = Field(default=0, description="Alerts with MEDIUM severity")
    resolved_alerts: int = Field(default=0, description="Alerts marked as RESOLVED")

    # Security & Audit Analytics
    failed_logins: int = Field(default=0, description="Failed credential authentication attempts")
    access_denied: int = Field(default=0, description="HTTP 403 authorization denials")
    rate_limit_events: int = Field(default=0, description="HTTP 429 throttle events")


class ThreatCategoryCount(BaseModel):
    """Aggregate volume and proportion for a specific attack category."""

    category: str
    count: int
    percentage: float = 0.0


class SeverityCount(BaseModel):
    """Aggregate volume and proportion for a triage risk level."""

    severity: str
    count: int
    percentage: float = 0.0


class ThreatDistributionResponse(BaseModel):
    """Aggregated threat category and severity distributions."""

    threat_categories: List[ThreatCategoryCount] = Field(default_factory=list)
    severity: List[SeverityCount] = Field(default_factory=list)
    total_evaluated: int = 0


class TimelineBucket(BaseModel):
    """Time-series aggregation slice for historical trend visualization."""

    bucket_time: str
    predictions: int = 0
    alerts: int = 0
    failed_logins: int = 0
    access_denied: int = 0
    rate_limit_events: int = 0


class TimelineResponse(BaseModel):
    """Chronologically sorted time series security telemetry."""

    time_range: str
    total_buckets: int
    timeline: List[TimelineBucket] = Field(default_factory=list)


class TopThreatSource(BaseModel):
    """Source IP aggregated network activity analysis."""

    source_ip: str
    prediction_count: int
    malicious_count: int
    highest_severity: str
    most_common_threat: str


class TopSourcesResponse(BaseModel):
    """Ranked listing of top attacking/originating source IP addresses."""

    total_sources: int = 0
    items: List[TopThreatSource] = Field(default_factory=list)
    source_data_available: bool = True


class ThreatIntelligenceLookupResponse(BaseModel):
    """Reputation and threat intelligence metadata for an IP address."""

    ip: str
    found: bool
    source: str = "LOCAL_DEMO_INTELLIGENCE"
    reputation: str = "UNKNOWN"  # MALICIOUS | SUSPICIOUS | BENIGN | UNKNOWN
    confidence: float = 0.0
    categories: List[str] = Field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    notes: Optional[str] = None


class PredictionInvestigationResponse(BaseModel):
    """Deep forensic investigation envelope for a specific prediction."""

    prediction_id: int
    timestamp: datetime
    threat_category: str
    severity: str
    anomaly_score: float
    classifier_confidence: float
    intrusion_flag: bool
    risk_reasons: List[str] = Field(
        default_factory=list,
        description="Rule-based deterministic explanation derived from ML outputs and flow characteristics",
    )
    flow_telemetry: Dict[str, Any] = Field(default_factory=dict)
    related_alert: Optional[Dict[str, Any]] = None
    related_audit_records: List[Dict[str, Any]] = Field(default_factory=list)
    threat_intelligence: Optional[ThreatIntelligenceLookupResponse] = None
