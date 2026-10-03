"""Pydantic schemas for security alerts."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class AlertBase(BaseModel):
    """Base security alert attributes."""

    title: str = Field(..., max_length=150)
    description: str
    severity: str = Field("HIGH", description="LOW | MEDIUM | HIGH | CRITICAL")
    status: str = Field("NEW", description="NEW | ACKNOWLEDGED | RESOLVED | FALSE_POSITIVE")


class AlertUpdateStatus(BaseModel):
    """Payload to update an alert's status during SOC triage."""

    status: str = Field(..., description="NEW | ACKNOWLEDGED | RESOLVED | FALSE_POSITIVE")


class AlertResponse(AlertBase):
    """Schema returned when reading an alert."""

    id: str
    threat_event_id: str
    assigned_user_id: Optional[str] = None
    created_at: datetime
    resolved_at: Optional[datetime] = None

    class Config:
        from_attributes = True
