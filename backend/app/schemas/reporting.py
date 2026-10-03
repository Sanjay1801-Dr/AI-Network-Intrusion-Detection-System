"""Pydantic schemas and data models for Phase 15 Automated Security Reporting & Evidence Export."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class ReportTimeRange(str, Enum):
    """Supported time ranges for security reporting."""

    LAST_1H = "last_1h"
    LAST_24H = "last_24h"
    LAST_7D = "last_7d"
    LAST_30D = "last_30d"
    CUSTOM = "custom"


class ReportFormat(str, Enum):
    """Supported export formats."""

    JSON = "json"
    CSV = "csv"
    PDF = "pdf"


class EvidenceFormat(str, Enum):
    """Supported formats for incident evidence packages."""

    JSON = "json"
    ZIP = "zip"


class ExecutiveSecuritySummary(BaseModel):
    """High-level executive metrics for security operations overview."""

    total_predictions: int = 0
    total_threats: int = 0
    total_alerts: int = 0
    alerts_by_severity: Dict[str, int] = Field(default_factory=dict)
    total_incidents: int = 0
    incidents_by_status: Dict[str, int] = Field(default_factory=dict)
    resolved_incidents: int = 0
    unresolved_incidents: int = 0
    top_threat_categories: List[Dict[str, Any]] = Field(default_factory=list)
    top_source_ips: List[Dict[str, Any]] = Field(default_factory=list)
    anomaly_statistics: Dict[str, Any] = Field(default_factory=dict)


class ReportIncidentItem(BaseModel):
    """Incident record snapshot included in security reports."""

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
    resolved_at: Optional[datetime] = None
    resolution_summary: Optional[str] = None
    alerts_count: int = 0
    predictions_count: int = 0


class ReportAlertItem(BaseModel):
    """Alert record snapshot included in security reports."""

    id: int
    severity: str
    status: str
    alert_type: str
    threat_label: str
    confidence: float
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    timestamp: datetime
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None


class ReportPredictionItem(BaseModel):
    """Prediction record snapshot included in security reports."""

    id: int
    predicted_threat: str
    risk_level: str
    anomaly_score: float
    classification_confidence: float
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    timestamp: datetime


class SecurityReportResponse(BaseModel):
    """Complete structured security report payload."""

    report_title: str
    generated_at: datetime
    time_range: str
    start_date: datetime
    end_date: datetime
    generated_by: str
    executive_summary: ExecutiveSecuritySummary
    incidents: List[ReportIncidentItem] = Field(default_factory=list)
    alerts: List[ReportAlertItem] = Field(default_factory=list)
    predictions: List[ReportPredictionItem] = Field(default_factory=list)
    important_findings: List[str] = Field(default_factory=list)
    disclaimer: str = (
        "CONFIDENTIAL & DEFENSIVE USE ONLY: This automated report is generated from telemetry, "
        "AI inference, and incident response records persisted in the NIDS database. "
        "Metrics reflect monitored operational data only."
    )


class IncidentEvidencePackage(BaseModel):
    """Cryptographically hashed forensic evidence package for an individual incident case."""

    incident_id: int
    incident_key: str
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    category: Optional[str] = None
    source_ip: Optional[str] = None
    assigned_to: Optional[str] = None
    created_by: str
    created_at: datetime
    acknowledged_at: Optional[datetime] = None
    investigation_started_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    resolution_summary: Optional[str] = None
    notes: List[Dict[str, Any]] = Field(default_factory=list)
    related_alerts: List[Dict[str, Any]] = Field(default_factory=list)
    related_predictions: List[Dict[str, Any]] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    relevant_audit_events: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_hash_sha256: str
    exported_by: str
    exported_at: datetime
    disclaimer: str = (
        "CHAIN OF CUSTODY NOTICE: This forensic evidence export is compiled from active operational records. "
        "Tamper-detection SHA256 integrity hash is computed across all associated incident artifacts."
    )
