"""Pydantic schemas for backend health-check endpoints."""

from datetime import datetime
from typing import Dict
from pydantic import BaseModel, Field


class ComponentHealth(BaseModel):
    """Health status of individual system components."""

    database: str = Field(..., description="Database connectivity state: connected | degraded | offline")
    ml_engine: str = Field(..., description="ML inference subsystem state: ready | not_loaded | offline")
    api: str = Field(..., description="FastAPI gateway status: online")


class HealthResponse(BaseModel):
    """Schema returned by GET /api/health."""

    status: str = Field("healthy", description="Overall system health status: healthy | degraded | unhealthy")
    service: str = Field(..., description="Service identifier name")
    version: str = Field(..., description="Application semantic version")
    environment: str = Field(..., description="Operating environment: development | staging | production")
    timestamp: datetime = Field(..., description="Current UTC timestamp")
    components: ComponentHealth = Field(..., description="Status breakdown of subcomponents")
