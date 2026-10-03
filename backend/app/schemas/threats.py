"""Pydantic schemas for detected threats."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class ThreatEventBase(BaseModel):
    """Base threat event attributes."""

    threat_type: str = Field(..., example="DoS_SYN_Flood")
    anomaly_score: float = Field(0.0, description="Outlier score from unsupervised model")
    confidence_score: float = Field(0.0, ge=0.0, le=1.0, description="Confidence probability")
    severity: str = Field("MEDIUM", description="LOW | MEDIUM | HIGH | CRITICAL")
    status: str = Field("DETECTED", description="DETECTED | INVESTIGATING | MITIGATED | DISMISSED")
    analysis_notes: Optional[str] = None


class ThreatEventResponse(ThreatEventBase):
    """Schema returned when retrieving a threat event."""

    id: str
    traffic_record_id: str
    detected_at: datetime

    class Config:
        from_attributes = True
