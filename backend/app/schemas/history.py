"""Pydantic schemas for historical prediction audit logs and security alerts."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class PredictionHistoryItem(BaseModel):
    """Historical record of an individual network flow AI prediction."""

    model_config = ConfigDict(from_attributes=True)

    id: int = Field(..., description="Unique prediction record identifier")
    timestamp: datetime = Field(..., description="Flow capture or evaluation timestamp")
    predicted_threat: str = Field(..., description="Predicted threat category (e.g. BENIGN, Port Scan, DoS)")
    intrusion_flag: bool = Field(..., description="Boolean flag indicating whether the flow was deemed intrusive")
    anomaly_score: float = Field(..., description="Normalized anomaly divergence score [0.0, 1.0]")
    classification_confidence: float = Field(..., description="Supervised classifier estimated class probability")
    risk_level: str = Field(..., description="Composite risk level: LOW | MEDIUM | HIGH | CRITICAL")
    recommended_action: str = Field(..., description="Triage guidance recommendation")
    source_ip: Optional[str] = Field(None, description="Client-supplied source IP telemetry")
    destination_ip: Optional[str] = Field(None, description="Client-supplied destination IP telemetry")
    destination_port: Optional[int] = Field(None, description="Destination service port")
    protocol: Optional[str] = Field(None, description="Transport protocol")
    created_at: datetime = Field(..., description="Database record insertion timestamp")


class PredictionHistoryResponse(BaseModel):
    """Paginated response containing historical prediction records."""

    total: int = Field(..., description="Total count of recorded predictions in the database")
    limit: int = Field(..., description="Requested page size limit")
    offset: int = Field(..., description="Requested pagination offset")
    items: List[PredictionHistoryItem] = Field(..., description="List of prediction records ordered newest first")


class AlertItem(BaseModel):
    """Security alert notification generated for significant security events."""

    model_config = ConfigDict(from_attributes=True)

    id: int = Field(..., description="Unique alert record identifier")
    prediction_id: Optional[int] = Field(None, description="Foreign key linking to prediction_records.id")
    timestamp: datetime = Field(..., description="Security event timestamp")
    alert_type: str = Field(..., description="Security alert classification (e.g. NETWORK_INTRUSION)")
    severity: str = Field(..., description="Alert severity: MEDIUM | HIGH | CRITICAL")
    threat_label: str = Field(..., description="Identified threat or anomaly family")
    anomaly_score: float = Field(..., description="Normalized anomaly score")
    confidence: float = Field(..., description="Supervised classifier confidence")
    source_ip: Optional[str] = Field(None, description="Source IP address if available in telemetry")
    destination_ip: Optional[str] = Field(None, description="Destination IP address if available in telemetry")
    status: str = Field("NEW", description="Alert lifecycle status: NEW | ACKNOWLEDGED | RESOLVED")
    recommended_action: str = Field(..., description="Recommended SOC triage response")
    created_at: datetime = Field(..., description="Alert creation timestamp")
    acknowledged_at: Optional[datetime] = Field(None, description="Timestamp when operator acknowledged the incident")
    resolved_at: Optional[datetime] = Field(None, description="Timestamp when operator marked incident resolved")


class PredictionMetadata(BaseModel):
    """Sanitized prediction telemetry associated with a security alert."""

    model_config = ConfigDict(from_attributes=True)

    id: int = Field(..., description="Unique prediction record identifier")
    predicted_threat: str = Field(..., description="Predicted threat category")
    anomaly_label: str = Field(..., description="Anomaly detector label (ANOMALY or NORMAL)")
    anomaly_score: float = Field(..., description="Normalized anomaly score")
    classification_confidence: float = Field(..., description="Classification confidence probability")
    risk_level: str = Field(..., description="Overall risk triage tier")
    recommended_action: str = Field(..., description="Action recommendation")
    flow_duration: Optional[float] = Field(None, description="Flow duration in microseconds")
    total_bytes: Optional[int] = Field(None, description="Total flow bytes transmitted")
    source_ip: Optional[str] = Field(None, description="Telemetry source IP")
    destination_ip: Optional[str] = Field(None, description="Telemetry destination IP")
    destination_port: Optional[int] = Field(None, description="Telemetry destination port")
    protocol: Optional[str] = Field(None, description="Transport protocol")
    created_at: datetime = Field(..., description="Prediction evaluation timestamp")


class AlertResponse(AlertItem):
    """Detailed alert response for single-alert lookup and lifecycle actions."""

    prediction: Optional[PredictionMetadata] = Field(None, description="Associated prediction telemetry, if linked")



class AlertHistoryResponse(BaseModel):
    """Paginated response containing security alert records with filtering telemetry."""

    total: int = Field(..., description="Total count of alerts matching filter criteria")
    limit: int = Field(..., description="Requested page size limit")
    offset: int = Field(..., description="Requested pagination offset")
    items: List[AlertItem] = Field(..., description="List of alert records ordered newest first")
