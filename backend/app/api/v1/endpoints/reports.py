"""FastAPI router endpoints for Phase 15 Automated Security Reporting & Evidence Export."""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, Optional, Union
from fastapi import APIRouter, Depends, Query, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.dependencies import require_authenticated_user
from backend.app.core.limiter import limiter
from backend.app.db.session import get_db
from backend.app.models.user import UserRecord
from backend.app.schemas.audit import AuditAction, AuditOutcome, AuditResourceType
from backend.app.schemas.reporting import (
    EvidenceFormat,
    IncidentEvidencePackage,
    ReportFormat,
    ReportTimeRange,
    SecurityReportResponse,
)
from backend.app.services.audit_service import AuditService
from backend.app.services.reporting_service import ReportingService

logger = logging.getLogger("nids.api.reports")

router = APIRouter(prefix="/reports", tags=["Security Reporting & Evidence Export"])


@router.get(
    "/security",
    summary="Generate Security Assessment Report",
    description="Generate executive security assessment report in JSON, CSV, or PDF format.",
)
@limiter.limit(lambda: settings.RATE_LIMIT_READ)
def get_security_report(
    request: Request,
    time_range: str = Query(default="last_24h", description="Time window: last_1h, last_24h, last_7d, last_30d, custom"),
    format: str = Query(default="json", description="Output format: json, csv, pdf"),
    start_date: Optional[str] = Query(None, description="ISO datetime start (required if time_range=custom)"),
    end_date: Optional[str] = Query(None, description="ISO datetime end (required if time_range=custom)"),
    severity: Optional[str] = Query(None, description="Optional severity filter: CRITICAL, HIGH, MEDIUM, LOW"),
    category: Optional[str] = Query(None, description="Optional threat category filter"),
    limit: int = Query(default=500, ge=1, le=1000, description="Max snapshot records (1-1000)"),
    current_user: UserRecord = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    """Compile and stream security report."""
    start_dt, end_dt, range_label = ReportingService.parse_time_range(
        time_range=time_range,
        start_date=start_date,
        end_date=end_date,
    )

    report_data = ReportingService.generate_security_report_data(
        db=db,
        start_time=start_dt,
        end_time=end_dt,
        range_label=range_label,
        severity_filter=severity,
        category_filter=category,
        limit=limit,
        generated_by=f"{current_user.username} ({current_user.role})",
    )

    requested_format = (format or "json").lower().strip()
    timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    # Audit Logging
    AuditService.log_event(
        db=db,
        action=AuditAction.REPORT_GENERATED if requested_format == "json" else AuditAction.REPORT_EXPORTED,
        resource_type=AuditResourceType.REPORT,
        outcome=AuditOutcome.SUCCESS,
        username=current_user.username,
        user_role=current_user.role,
        resource_id="SECURITY_ASSESSMENT",
        ip_address=request.client.host if request.client else None,
        request_method=request.method,
        request_path=request.url.path,
        status_code=200,
        details={
            "format": requested_format,
            "time_range": range_label,
            "severity_filter": severity,
            "category_filter": category,
            "total_predictions": report_data.executive_summary.total_predictions,
            "total_alerts": report_data.executive_summary.total_alerts,
            "total_incidents": report_data.executive_summary.total_incidents,
        },
    )

    if requested_format == ReportFormat.PDF.value:
        pdf_bytes = ReportingService.export_report_pdf(report_data)
        filename = f"nids-security-report-{timestamp_slug}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(pdf_bytes)),
            },
        )
    elif requested_format == ReportFormat.CSV.value:
        # Default CSV export for security report compiles the incident snapshot
        csv_content = ReportingService.export_incidents_csv(
            db=db,
            start_time=start_dt,
            end_time=end_dt,
            severity_filter=severity,
            category_filter=category,
            limit=limit,
        )
        filename = f"nids-security-report-{timestamp_slug}.csv"
        return Response(
            content=csv_content,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    else:
        return report_data


@router.get(
    "/predictions",
    summary="Export Predictions Dataset",
    description="Export network flow inferences as CSV or JSON.",
)
@limiter.limit(lambda: settings.RATE_LIMIT_READ)
def export_predictions(
    request: Request,
    time_range: str = Query(default="last_24h", description="Time window"),
    format: str = Query(default="csv", description="Output format: csv or json"),
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    limit: int = Query(default=1000, ge=1, le=1000),
    current_user: UserRecord = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    """Export flow predictions dataset."""
    start_dt, end_dt, range_label = ReportingService.parse_time_range(time_range, start_date, end_date)
    requested_format = (format or "csv").lower().strip()
    timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    AuditService.log_event(
        db=db,
        action=AuditAction.REPORT_EXPORTED,
        resource_type=AuditResourceType.REPORT,
        outcome=AuditOutcome.SUCCESS,
        username=current_user.username,
        user_role=current_user.role,
        resource_id="PREDICTIONS",
        ip_address=request.client.host if request.client else None,
        request_method=request.method,
        request_path=request.url.path,
        status_code=200,
        details={"dataset": "predictions", "format": requested_format, "time_range": range_label},
    )

    if requested_format == "json":
        report_data = ReportingService.generate_security_report_data(
            db=db, start_time=start_dt, end_time=end_dt, range_label=range_label,
            severity_filter=severity, category_filter=category, limit=limit,
        )
        return {"predictions": report_data.predictions, "count": len(report_data.predictions)}

    csv_data = ReportingService.export_predictions_csv(
        db=db, start_time=start_dt, end_time=end_dt,
        severity_filter=severity, category_filter=category, limit=limit,
    )
    return Response(
        content=csv_data,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="nids-predictions-{timestamp_slug}.csv"'},
    )


@router.get(
    "/alerts",
    summary="Export Alerts Dataset",
    description="Export security alerts as CSV or JSON.",
)
@limiter.limit(lambda: settings.RATE_LIMIT_READ)
def export_alerts(
    request: Request,
    time_range: str = Query(default="last_24h"),
    format: str = Query(default="csv"),
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    limit: int = Query(default=1000, ge=1, le=1000),
    current_user: UserRecord = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    """Export security alerts dataset."""
    start_dt, end_dt, range_label = ReportingService.parse_time_range(time_range, start_date, end_date)
    requested_format = (format or "csv").lower().strip()
    timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    AuditService.log_event(
        db=db,
        action=AuditAction.REPORT_EXPORTED,
        resource_type=AuditResourceType.REPORT,
        outcome=AuditOutcome.SUCCESS,
        username=current_user.username,
        user_role=current_user.role,
        resource_id="ALERTS",
        ip_address=request.client.host if request.client else None,
        request_method=request.method,
        request_path=request.url.path,
        status_code=200,
        details={"dataset": "alerts", "format": requested_format, "time_range": range_label},
    )

    if requested_format == "json":
        report_data = ReportingService.generate_security_report_data(
            db=db, start_time=start_dt, end_time=end_dt, range_label=range_label,
            severity_filter=severity, category_filter=category, limit=limit,
        )
        return {"alerts": report_data.alerts, "count": len(report_data.alerts)}

    csv_data = ReportingService.export_alerts_csv(
        db=db, start_time=start_dt, end_time=end_dt,
        severity_filter=severity, category_filter=category, limit=limit,
    )
    return Response(
        content=csv_data,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="nids-alerts-{timestamp_slug}.csv"'},
    )


@router.get(
    "/incidents",
    summary="Export Incidents Dataset",
    description="Export SOC incidents as CSV or JSON.",
)
@limiter.limit(lambda: settings.RATE_LIMIT_READ)
def export_incidents(
    request: Request,
    time_range: str = Query(default="last_24h"),
    format: str = Query(default="csv"),
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    limit: int = Query(default=1000, ge=1, le=1000),
    current_user: UserRecord = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    """Export incident cases dataset."""
    start_dt, end_dt, range_label = ReportingService.parse_time_range(time_range, start_date, end_date)
    requested_format = (format or "csv").lower().strip()
    timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    AuditService.log_event(
        db=db,
        action=AuditAction.REPORT_EXPORTED,
        resource_type=AuditResourceType.REPORT,
        outcome=AuditOutcome.SUCCESS,
        username=current_user.username,
        user_role=current_user.role,
        resource_id="INCIDENTS",
        ip_address=request.client.host if request.client else None,
        request_method=request.method,
        request_path=request.url.path,
        status_code=200,
        details={"dataset": "incidents", "format": requested_format, "time_range": range_label},
    )

    if requested_format == "json":
        report_data = ReportingService.generate_security_report_data(
            db=db, start_time=start_dt, end_time=end_dt, range_label=range_label,
            severity_filter=severity, category_filter=category, limit=limit,
        )
        return {"incidents": report_data.incidents, "count": len(report_data.incidents)}

    csv_data = ReportingService.export_incidents_csv(
        db=db, start_time=start_dt, end_time=end_dt,
        severity_filter=severity, category_filter=category, limit=limit,
    )
    return Response(
        content=csv_data,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="nids-incidents-{timestamp_slug}.csv"'},
    )


@router.get(
    "/audit-logs",
    summary="Export Audit Trail Dataset",
    description="Export security audit log events as CSV.",
)
@limiter.limit(lambda: settings.RATE_LIMIT_READ)
def export_audit_logs(
    request: Request,
    time_range: str = Query(default="last_24h"),
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    limit: int = Query(default=1000, ge=1, le=1000),
    current_user: UserRecord = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    """Export audit events as CSV."""
    start_dt, end_dt, range_label = ReportingService.parse_time_range(time_range, start_date, end_date)
    timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    AuditService.log_event(
        db=db,
        action=AuditAction.REPORT_EXPORTED,
        resource_type=AuditResourceType.REPORT,
        outcome=AuditOutcome.SUCCESS,
        username=current_user.username,
        user_role=current_user.role,
        resource_id="AUDIT_LOGS",
        ip_address=request.client.host if request.client else None,
        request_method=request.method,
        request_path=request.url.path,
        status_code=200,
        details={"dataset": "audit_logs", "time_range": range_label},
    )

    csv_data = ReportingService.export_audit_logs_csv(
        db=db, start_time=start_dt, end_time=end_dt, limit=limit,
    )
    return Response(
        content=csv_data,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="nids-audit-logs-{timestamp_slug}.csv"'},
    )


@router.get(
    "/incidents/{incident_id}/evidence",
    summary="Export Incident Forensic Evidence Package",
    description="Generate cryptographically signed forensic evidence package in JSON or ZIP format.",
)
@limiter.limit(lambda: settings.RATE_LIMIT_READ)
def export_incident_evidence(
    request: Request,
    incident_id: int,
    format: str = Query(default="json", description="Evidence format: json or zip"),
    current_user: UserRecord = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    """Compile and export tamper-evident incident evidence."""
    evidence = ReportingService.generate_incident_evidence(
        db=db,
        incident_id=incident_id,
        exported_by=f"{current_user.username} ({current_user.role})",
    )

    requested_format = (format or "json").lower().strip()
    timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    AuditService.log_event(
        db=db,
        action=AuditAction.INCIDENT_EVIDENCE_EXPORTED,
        resource_type=AuditResourceType.EVIDENCE,
        outcome=AuditOutcome.SUCCESS,
        username=current_user.username,
        user_role=current_user.role,
        resource_id=str(incident_id),
        ip_address=request.client.host if request.client else None,
        request_method=request.method,
        request_path=request.url.path,
        status_code=200,
        details={
            "incident_id": incident_id,
            "incident_key": evidence.incident_key,
            "format": requested_format,
            "evidence_hash": evidence.evidence_hash_sha256,
        },
    )

    if requested_format == EvidenceFormat.ZIP.value:
        zip_bytes = ReportingService.export_incident_evidence_zip(evidence)
        filename = f"evidence-{evidence.incident_key}-{timestamp_slug}.zip"
        return Response(
            content=zip_bytes,
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(zip_bytes)),
            },
        )
    else:
        return evidence
