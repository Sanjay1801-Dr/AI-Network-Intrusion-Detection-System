"""Pydantic request and response schemas for Phase 14 Incident Response & SOC Operations."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


class IncidentStatus(str, Enum):
    """Permitted incident lifecycle states."""

    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"


class IncidentSeverity(str, Enum):
    """Standardized SOC incident triage severity."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class IncidentCreateRequest(BaseModel):
    """Payload to create a new SOC incident record."""

    title: str = Field(..., min_length=3, max_length=255, description="Brief descriptive summary of the incident")
    description: Optional[str] = Field(None, max_length=4000, description="Detailed analyst case description or context")
    alert_id: Optional[int] = Field(None, description="Optional triggering AlertRecord ID")
    prediction_id: Optional[int] = Field(None, description="Optional triggering PredictionRecord ID")
    severity: Optional[str] = Field(None, description="Optional override severity: CRITICAL, HIGH, MEDIUM, LOW")
    category: Optional[str] = Field(None, max_length=50, description="Optional threat category e.g. DoS, Port Scan")
    assigned_to: Optional[str] = Field(None, max_length=100, description="Optional initial operator assignment")

    @field_validator("title")
    @classmethod
    def validate_title(cls, v: str) -> str:
        cleaned = v.strip()
        if len(cleaned) < 3:
            raise ValueError("Title must be at least 3 non-whitespace characters.")
        return cleaned


class IncidentStatusUpdateRequest(BaseModel):
    """Payload to execute an incident lifecycle state transition."""

    new_status: str = Field(..., description="Target status: ACKNOWLEDGED, INVESTIGATING, CONTAINED, RESOLVED")
    resolution_summary: Optional[str] = Field(
        None,
        max_length=2000,
        description="Mandatory summary describing the resolution action when resolving an incident",
    )


class IncidentAssignRequest(BaseModel):
    """Payload to reassign an incident to an authorized SOC operator."""

    assigned_to: str = Field(..., min_length=1, max_length=100, description="Target operator username")

    @field_validator("assigned_to")
    @classmethod
    def validate_assigned_to(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("assigned_to username cannot be blank.")
        return cleaned


class IncidentNoteCreateRequest(BaseModel):
    """Payload for an analyst to append a forensic note to an incident."""

    note: str = Field(..., min_length=1, max_length=4000, description="Analyst observation or forensic note")

    @field_validator("note")
    @classmethod
    def validate_note(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Note content cannot be empty or purely whitespace.")
        return cleaned


class IncidentNoteResponse(BaseModel):
    """Serialized representation of an incident case note."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int
    author: str
    note: str
    created_at: datetime
    updated_at: datetime


class IncidentResponse(BaseModel):
    """Serialized summary of an incident record for listing and tables."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_key: str
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    category: str
    source_ip: Optional[str] = None
    assigned_to: Optional[str] = None
    created_by: str
    created_at: datetime
    updated_at: datetime
    acknowledged_at: Optional[datetime] = None
    investigation_started_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    resolution_summary: Optional[str] = None
    alerts_count: int = 0
    predictions_count: int = 0
    notes_count: int = 0


class IncidentDetailResponse(IncidentResponse):
    """Deep incident view containing linked alerts, predictions, and notes."""

    alerts: List[Dict[str, Any]] = Field(default_factory=list)
    predictions: List[Dict[str, Any]] = Field(default_factory=list)
    notes: List[IncidentNoteResponse] = Field(default_factory=list)


class IncidentTimelineEvent(BaseModel):
    """Unified chronological incident event."""

    timestamp: datetime
    event_type: str
    actor: str
    summary: str
    details: Optional[Dict[str, Any]] = None


class IncidentTimelineResponse(BaseModel):
    """Chronological event history for an incident."""

    incident_id: int
    incident_key: str
    total_events: int
    events: List[IncidentTimelineEvent] = Field(default_factory=list)
    timeline: List[IncidentTimelineEvent] = Field(default_factory=list)


class IncidentListResponse(BaseModel):
    """Paginated collection of incidents."""

    items: List[IncidentResponse]
    total: int
    limit: int
    offset: int


class IncidentSummaryResponse(BaseModel):
    """Aggregated incident metrics for SOC dashboard."""

    total_incidents: int = 0
    open_incidents: int = 0
    acknowledged_incidents: int = 0
    investigating_incidents: int = 0
    contained_incidents: int = 0
    resolved_incidents: int = 0
    critical_incidents: int = 0
    high_incidents: int = 0
    recently_resolved: int = 0
