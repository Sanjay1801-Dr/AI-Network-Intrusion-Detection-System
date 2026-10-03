"""Audit event taxonomy, enumerations, and Pydantic schemas (Phase 12)."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class AuditAction(str, Enum):
    """Standardized security audit action taxonomy."""

    # Authentication
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    LOGOUT = "LOGOUT"

    # Authorization
    ACCESS_DENIED = "ACCESS_DENIED"

    # AI Prediction
    PREDICTION_CREATED = "PREDICTION_CREATED"

    # Alert Incident Management
    ALERT_ACKNOWLEDGED = "ALERT_ACKNOWLEDGED"
    ALERT_RESOLVED = "ALERT_RESOLVED"

    # WebSocket Real-Time Monitoring
    WEBSOCKET_AUTH_SUCCESS = "WEBSOCKET_AUTH_SUCCESS"
    WEBSOCKET_AUTH_FAILURE = "WEBSOCKET_AUTH_FAILURE"

    # Rate Limiting & Abuse Protection
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"

    # Security Analytics & Threat Intelligence (Phase 13)
    ANALYTICS_VIEWED = "ANALYTICS_VIEWED"
    THREAT_INTELLIGENCE_LOOKUP = "THREAT_INTELLIGENCE_LOOKUP"
    INVESTIGATION_VIEWED = "INVESTIGATION_VIEWED"

    # Incident Response Management (Phase 14)
    INCIDENT_CREATED = "INCIDENT_CREATED"
    INCIDENT_ASSIGNED = "INCIDENT_ASSIGNED"
    INCIDENT_STATUS_CHANGED = "INCIDENT_STATUS_CHANGED"
    INCIDENT_NOTE_ADDED = "INCIDENT_NOTE_ADDED"
    INCIDENT_VIEWED = "INCIDENT_VIEWED"

    # Automated Reporting & Evidence Export (Phase 15)
    REPORT_GENERATED = "REPORT_GENERATED"
    REPORT_EXPORTED = "REPORT_EXPORTED"
    INCIDENT_EVIDENCE_EXPORTED = "INCIDENT_EVIDENCE_EXPORTED"

    # Advanced Threat Hunting & Investigation Workbench (Phase 16)
    THREAT_HUNT_SEARCHED = "THREAT_HUNT_SEARCHED"
    SOURCE_INVESTIGATION_VIEWED = "SOURCE_INVESTIGATION_VIEWED"
    THREAT_HUNT_HISTORY_VIEWED = "THREAT_HUNT_HISTORY_VIEWED"

    # System & Defensive Security
    SECURITY_ERROR = "SECURITY_ERROR"


class AuditOutcome(str, Enum):
    """Audit action outcome status."""

    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENIED = "DENIED"


class AuditResourceType(str, Enum):
    """Categorization of targeted resources."""

    AUTH = "AUTH"
    ACCESS_CONTROL = "ACCESS_CONTROL"
    PREDICTION = "PREDICTION"
    ALERT = "ALERT"
    WEBSOCKET = "WEBSOCKET"
    RATE_LIMIT = "RATE_LIMIT"
    ANALYTICS = "ANALYTICS"
    THREAT_INTELLIGENCE = "THREAT_INTELLIGENCE"
    INCIDENT = "INCIDENT"
    REPORT = "REPORT"
    EVIDENCE = "EVIDENCE"
    HUNTING = "HUNTING"
    SYSTEM = "SYSTEM"


class AuditLogResponse(BaseModel):
    """Schema for returning a single audit log entry."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    username: Optional[str] = None
    user_role: Optional[str] = None
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    outcome: str
    ip_address: Optional[str] = None
    request_method: Optional[str] = None
    request_path: Optional[str] = None
    status_code: Optional[int] = None
    details: Optional[str] = None
    created_at: datetime


class AuditLogHistoryResponse(BaseModel):
    """Paginated security audit history response."""

    total: int
    limit: int
    offset: int
    items: List[AuditLogResponse]


class SecurityMonitoringSummary(BaseModel):
    """High-level security telemetry metrics for SOC dashboard overview."""

    total_events: int = Field(default=0, description="Total audit events recorded in database")
    failed_logins: int = Field(default=0, description="Failed authentication attempts")
    access_denied: int = Field(default=0, description="Authorization 403 access rejections")
    rate_limit_exceeded: int = Field(default=0, description="Rate limit 429 throttle events")
