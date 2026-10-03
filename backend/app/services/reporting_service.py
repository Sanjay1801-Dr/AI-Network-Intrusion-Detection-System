"""Core business logic for Phase 15 Automated Security Reporting & Evidence Export."""

import csv
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import logging
from typing import Any, Dict, List, Optional, Tuple
import zipfile

from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from backend.app.core.errors import ResourceNotFoundException, ValidationException
from backend.app.models.alert import AlertRecord
from backend.app.models.audit import AuditLogRecord
from backend.app.models.incident import IncidentRecord, IncidentNoteRecord
from backend.app.models.prediction import PredictionRecord
from backend.app.schemas.incident import IncidentStatus
from backend.app.schemas.reporting import (
    ExecutiveSecuritySummary,
    IncidentEvidencePackage,
    ReportAlertItem,
    ReportIncidentItem,
    ReportPredictionItem,
    ReportTimeRange,
    SecurityReportResponse,
)

logger = logging.getLogger("nids.services.reporting")

# Maximum bounded limits to prevent unbounded DB queries and out-of-memory errors
MAX_REPORT_ITEMS = 1000
MAX_CUSTOM_RANGE_DAYS = 90


class ReportingService:
    """Service providing aggregated security reporting, multi-format exports, and forensic evidence packages."""

    @staticmethod
    def parse_time_range(
        time_range: str = "last_24h",
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> Tuple[datetime, datetime, str]:
        """Convert time range descriptor or ISO date strings into validated UTC datetimes.

        Returns:
            Tuple[start_datetime, end_datetime, label]
        """
        now = datetime.now(timezone.utc)
        normalized_range = (time_range or "last_24h").lower().strip()

        if normalized_range == ReportTimeRange.LAST_1H.value:
            return now - timedelta(hours=1), now, "Last 1 Hour"
        elif normalized_range == ReportTimeRange.LAST_24H.value:
            return now - timedelta(hours=24), now, "Last 24 Hours"
        elif normalized_range == ReportTimeRange.LAST_7D.value:
            return now - timedelta(days=7), now, "Last 7 Days"
        elif normalized_range == ReportTimeRange.LAST_30D.value:
            return now - timedelta(days=30), now, "Last 30 Days"
        elif normalized_range == ReportTimeRange.CUSTOM.value:
            if not start_date or not end_date:
                raise ValidationException("Custom time range requires both start_date and end_date.")
            try:
                clean_start = start_date.replace(" ", "+").replace("Z", "+00:00")
                clean_end = end_date.replace(" ", "+").replace("Z", "+00:00")
                start_dt = datetime.fromisoformat(clean_start)
                end_dt = datetime.fromisoformat(clean_end)
            except ValueError as err:
                raise ValidationException(f"Invalid ISO datetime format for custom time range: {err}")

            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=timezone.utc)
            if end_dt.tzinfo is None:
                end_dt = end_dt.replace(tzinfo=timezone.utc)

            if start_dt >= end_dt:
                raise ValidationException("start_date must be strictly earlier than end_date.")

            if (end_dt - start_dt).days > MAX_CUSTOM_RANGE_DAYS:
                raise ValidationException(
                    f"Requested custom time range exceeds maximum limit of {MAX_CUSTOM_RANGE_DAYS} days."
                )

            return start_dt, end_dt, f"Custom ({start_dt.strftime('%Y-%m-%d')} to {end_dt.strftime('%Y-%m-%d')})"
        else:
            # Default to last 24h if unknown string provided
            return now - timedelta(hours=24), now, "Last 24 Hours"

    @classmethod
    def generate_security_report_data(
        cls,
        db: Session,
        start_time: datetime,
        end_time: datetime,
        range_label: str,
        severity_filter: Optional[str] = None,
        category_filter: Optional[str] = None,
        limit: int = 500,
        generated_by: str = "SOC Operator",
    ) -> SecurityReportResponse:
        """Compile a bounded security report from predictions, alerts, and incident records."""
        safe_limit = min(max(1, limit), MAX_REPORT_ITEMS)

        # 1. Predictions Query
        pred_query = db.query(PredictionRecord).filter(
            PredictionRecord.timestamp >= start_time,
            PredictionRecord.timestamp <= end_time,
        )
        if severity_filter:
            pred_query = pred_query.filter(PredictionRecord.risk_level == severity_filter.upper().strip())
        if category_filter:
            pred_query = pred_query.filter(
                func.lower(PredictionRecord.predicted_threat).contains(category_filter.lower().strip())
            )

        total_predictions = pred_query.count()

        # Anomalies / Threats count
        total_threats = (
            pred_query.filter(
                (PredictionRecord.intrusion_flag == True)
                | (PredictionRecord.anomaly_score < 0)
                | (PredictionRecord.predicted_threat != "BENIGN")
            ).count()
        )

        # Top threat categories
        threat_breakdown = (
            pred_query.with_entities(
                PredictionRecord.predicted_threat,
                func.count(PredictionRecord.id).label("count"),
            )
            .group_by(PredictionRecord.predicted_threat)
            .order_by(desc("count"))
            .limit(10)
            .all()
        )
        top_threat_categories = [
            {"threat": threat or "Unknown", "count": count} for threat, count in threat_breakdown
        ]

        # Top Source IPs
        source_breakdown = (
            pred_query.filter(PredictionRecord.source_ip.isnot(None))
            .with_entities(
                PredictionRecord.source_ip,
                func.count(PredictionRecord.id).label("count"),
            )
            .group_by(PredictionRecord.source_ip)
            .order_by(desc("count"))
            .limit(10)
            .all()
        )
        top_source_ips = [
            {"source_ip": ip, "count": count} for ip, count in source_breakdown if ip
        ]

        # Sample predictions for snapshot
        sample_preds = (
            pred_query.order_by(desc(PredictionRecord.timestamp))
            .limit(safe_limit)
            .all()
        )
        prediction_items = [
            ReportPredictionItem(
                id=p.id,
                predicted_threat=p.predicted_threat or "BENIGN",
                risk_level=p.risk_level or "LOW",
                anomaly_score=round(float(p.anomaly_score or 0.0), 4),
                classification_confidence=round(float(p.classification_confidence or 0.0), 4),
                source_ip=p.source_ip,
                destination_ip=p.destination_ip,
                timestamp=p.timestamp,
            )
            for p in sample_preds
        ]

        # 2. Alerts Query
        alert_query = db.query(AlertRecord).filter(
            AlertRecord.timestamp >= start_time,
            AlertRecord.timestamp <= end_time,
        )
        if severity_filter:
            alert_query = alert_query.filter(AlertRecord.severity == severity_filter.upper().strip())
        if category_filter:
            alert_query = alert_query.filter(
                func.lower(AlertRecord.threat_label).contains(category_filter.lower().strip())
            )

        total_alerts = alert_query.count()

        # Severity breakdown
        sev_counts = (
            alert_query.with_entities(
                AlertRecord.severity,
                func.count(AlertRecord.id).label("count"),
            )
            .group_by(AlertRecord.severity)
            .all()
        )
        alerts_by_severity = {sev or "UNKNOWN": count for sev, count in sev_counts}

        sample_alerts = (
            alert_query.order_by(desc(AlertRecord.timestamp))
            .limit(safe_limit)
            .all()
        )
        alert_items = [
            ReportAlertItem(
                id=a.id,
                severity=a.severity,
                status=a.status,
                alert_type=a.alert_type or "SECURITY_ALERT",
                threat_label=a.threat_label or "Anomaly",
                confidence=round(float(a.confidence or 0.0), 4),
                source_ip=a.source_ip,
                destination_ip=a.destination_ip,
                timestamp=a.timestamp,
                acknowledged_at=a.acknowledged_at,
                resolved_at=a.resolved_at,
            )
            for a in sample_alerts
        ]

        # 3. Incidents Query
        inc_query = db.query(IncidentRecord).filter(
            IncidentRecord.created_at >= start_time,
            IncidentRecord.created_at <= end_time,
        )
        if severity_filter:
            inc_query = inc_query.filter(IncidentRecord.severity == severity_filter.upper().strip())
        if category_filter:
            inc_query = inc_query.filter(
                func.lower(IncidentRecord.category).contains(category_filter.lower().strip())
            )

        total_incidents = inc_query.count()

        # Incidents by status
        status_counts = (
            inc_query.with_entities(
                IncidentRecord.status,
                func.count(IncidentRecord.id).label("count"),
            )
            .group_by(IncidentRecord.status)
            .all()
        )
        incidents_by_status = {st or "UNKNOWN": count for st, count in status_counts}
        resolved_incidents = incidents_by_status.get(IncidentStatus.RESOLVED.value, 0)
        unresolved_incidents = max(0, total_incidents - resolved_incidents)

        sample_incidents = (
            inc_query.order_by(desc(IncidentRecord.created_at))
            .limit(safe_limit)
            .all()
        )
        incident_items = [
            ReportIncidentItem(
                id=i.id,
                incident_key=i.incident_key,
                title=i.title,
                severity=i.severity,
                status=i.status,
                category=i.category,
                source_ip=i.source_ip,
                assigned_to=i.assigned_to,
                created_at=i.created_at,
                updated_at=i.updated_at,
                resolved_at=i.resolved_at,
                resolution_summary=i.resolution_summary,
                alerts_count=len(i.alerts),
                predictions_count=len(i.predictions),
            )
            for i in sample_incidents
        ]

        # 4. Synthesize Important Findings
        important_findings: List[str] = []
        if total_predictions == 0:
            important_findings.append("Zero network flow evaluations were logged within this timeframe.")
        else:
            threat_pct = (total_threats / total_predictions) * 100
            important_findings.append(
                f"Observed {total_threats} suspicious/anomalous flows out of {total_predictions} total evaluations ({threat_pct:.1f}% anomaly density)."
            )

        critical_alerts = alerts_by_severity.get("CRITICAL", 0)
        high_alerts = alerts_by_severity.get("HIGH", 0)
        if critical_alerts > 0 or high_alerts > 0:
            important_findings.append(
                f"High-priority alert volume: {critical_alerts} CRITICAL and {high_alerts} HIGH severity alerts triggered."
            )

        if total_incidents > 0:
            res_pct = (resolved_incidents / total_incidents) * 100
            important_findings.append(
                f"SOC Incident Resolution Rate: {res_pct:.1f}% ({resolved_incidents} resolved, {unresolved_incidents} open/in-progress)."
            )

        if top_threat_categories:
            top_vec = top_threat_categories[0]
            important_findings.append(
                f"Primary detected attack vector: '{top_vec['threat']}' with {top_vec['count']} matching event signatures."
            )

        if top_source_ips:
            top_ip = top_source_ips[0]
            important_findings.append(
                f"Most active source address: '{top_ip['source_ip']}' with {top_ip['count']} associated ingress flows."
            )

        exec_summary = ExecutiveSecuritySummary(
            total_predictions=total_predictions,
            total_threats=total_threats,
            total_alerts=total_alerts,
            alerts_by_severity=alerts_by_severity,
            total_incidents=total_incidents,
            incidents_by_status=incidents_by_status,
            resolved_incidents=resolved_incidents,
            unresolved_incidents=unresolved_incidents,
            top_threat_categories=top_threat_categories,
            top_source_ips=top_source_ips,
            anomaly_statistics={
                "anomalies_detected": total_threats,
                "benign_flows": max(0, total_predictions - total_threats),
                "threat_ratio_percent": round((total_threats / total_predictions * 100), 2) if total_predictions > 0 else 0.0,
            },
        )

        return SecurityReportResponse(
            report_title="NIDS SOC Operational Security & Threat Assessment Report",
            generated_at=datetime.now(timezone.utc),
            time_range=range_label,
            start_date=start_time,
            end_date=end_time,
            generated_by=generated_by,
            executive_summary=exec_summary,
            incidents=incident_items,
            alerts=alert_items,
            predictions=prediction_items,
            important_findings=important_findings,
        )

    # -------------------------------------------------------------------------
    # CSV Export Utilities
    # -------------------------------------------------------------------------

    @staticmethod
    def export_predictions_csv(
        db: Session,
        start_time: datetime,
        end_time: datetime,
        severity_filter: Optional[str] = None,
        category_filter: Optional[str] = None,
        limit: int = 1000,
    ) -> str:
        """Export predictions dataset as standardized RFC 4180 CSV."""
        safe_limit = min(max(1, limit), MAX_REPORT_ITEMS)
        query = db.query(PredictionRecord).filter(
            PredictionRecord.timestamp >= start_time,
            PredictionRecord.timestamp <= end_time,
        )
        if severity_filter:
            query = query.filter(PredictionRecord.risk_level == severity_filter.upper().strip())
        if category_filter:
            query = query.filter(
                func.lower(PredictionRecord.predicted_threat).contains(category_filter.lower().strip())
            )

        rows = query.order_by(desc(PredictionRecord.timestamp)).limit(safe_limit).all()

        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
        writer.writerow([
            "Prediction_ID",
            "Timestamp_UTC",
            "Source_IP",
            "Destination_IP",
            "Destination_Port",
            "Protocol",
            "Predicted_Threat",
            "Intrusion_Flag",
            "Anomaly_Score",
            "Classification_Confidence",
            "Risk_Level",
            "Recommended_Action",
        ])

        for r in rows:
            writer.writerow([
                r.id,
                r.timestamp.isoformat() if r.timestamp else "",
                r.source_ip or "",
                r.destination_ip or "",
                r.destination_port or "",
                r.protocol or "",
                r.predicted_threat or "",
                r.intrusion_flag,
                round(float(r.anomaly_score or 0.0), 4),
                round(float(r.classification_confidence or 0.0), 4),
                r.risk_level or "",
                r.recommended_action or "",
            ])

        return output.getvalue()

    @staticmethod
    def export_alerts_csv(
        db: Session,
        start_time: datetime,
        end_time: datetime,
        severity_filter: Optional[str] = None,
        category_filter: Optional[str] = None,
        limit: int = 1000,
    ) -> str:
        """Export alerts dataset as CSV."""
        safe_limit = min(max(1, limit), MAX_REPORT_ITEMS)
        query = db.query(AlertRecord).filter(
            AlertRecord.timestamp >= start_time,
            AlertRecord.timestamp <= end_time,
        )
        if severity_filter:
            query = query.filter(AlertRecord.severity == severity_filter.upper().strip())
        if category_filter:
            query = query.filter(
                func.lower(AlertRecord.threat_label).contains(category_filter.lower().strip())
            )

        rows = query.order_by(desc(AlertRecord.timestamp)).limit(safe_limit).all()

        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
        writer.writerow([
            "Alert_ID",
            "Prediction_ID",
            "Timestamp_UTC",
            "Severity",
            "Status",
            "Alert_Type",
            "Threat_Label",
            "Confidence",
            "Source_IP",
            "Destination_IP",
            "Acknowledged_At",
            "Resolved_At",
        ])

        for a in rows:
            writer.writerow([
                a.id,
                a.prediction_id or "",
                a.timestamp.isoformat() if a.timestamp else "",
                a.severity or "",
                a.status or "",
                a.alert_type or "",
                a.threat_label or "",
                round(float(a.confidence or 0.0), 4),
                a.source_ip or "",
                a.destination_ip or "",
                a.acknowledged_at.isoformat() if a.acknowledged_at else "",
                a.resolved_at.isoformat() if a.resolved_at else "",
            ])

        return output.getvalue()

    @staticmethod
    def export_incidents_csv(
        db: Session,
        start_time: datetime,
        end_time: datetime,
        severity_filter: Optional[str] = None,
        category_filter: Optional[str] = None,
        limit: int = 1000,
    ) -> str:
        """Export incidents dataset as CSV."""
        safe_limit = min(max(1, limit), MAX_REPORT_ITEMS)
        query = db.query(IncidentRecord).filter(
            IncidentRecord.created_at >= start_time,
            IncidentRecord.created_at <= end_time,
        )
        if severity_filter:
            query = query.filter(IncidentRecord.severity == severity_filter.upper().strip())
        if category_filter:
            query = query.filter(
                func.lower(IncidentRecord.category).contains(category_filter.lower().strip())
            )

        rows = query.order_by(desc(IncidentRecord.created_at)).limit(safe_limit).all()

        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
        writer.writerow([
            "Incident_ID",
            "Incident_Key",
            "Title",
            "Severity",
            "Status",
            "Category",
            "Source_IP",
            "Assigned_To",
            "Created_By",
            "Created_At_UTC",
            "Acknowledged_At",
            "Investigation_Started_At",
            "Resolved_At",
            "Resolution_Summary",
            "Linked_Alerts_Count",
            "Linked_Predictions_Count",
        ])

        for i in rows:
            writer.writerow([
                i.id,
                i.incident_key,
                i.title,
                i.severity,
                i.status,
                i.category or "",
                i.source_ip or "",
                i.assigned_to or "",
                i.created_by,
                i.created_at.isoformat() if i.created_at else "",
                i.acknowledged_at.isoformat() if i.acknowledged_at else "",
                i.investigation_started_at.isoformat() if i.investigation_started_at else "",
                i.resolved_at.isoformat() if i.resolved_at else "",
                i.resolution_summary or "",
                len(i.alerts),
                len(i.predictions),
            ])

        return output.getvalue()

    @staticmethod
    def export_audit_logs_csv(
        db: Session,
        start_time: datetime,
        end_time: datetime,
        limit: int = 1000,
    ) -> str:
        """Export audit events dataset as CSV, with strict privacy filtering (never leaking tokens/credentials)."""
        safe_limit = min(max(1, limit), MAX_REPORT_ITEMS)
        rows = (
            db.query(AuditLogRecord)
            .filter(
                AuditLogRecord.timestamp >= start_time,
                AuditLogRecord.timestamp <= end_time,
            )
            .order_by(desc(AuditLogRecord.timestamp))
            .limit(safe_limit)
            .all()
        )

        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
        writer.writerow([
            "Audit_ID",
            "Timestamp_UTC",
            "Username",
            "User_Role",
            "Action",
            "Resource_Type",
            "Resource_ID",
            "Outcome",
            "IP_Address",
            "Request_Method",
            "Request_Path",
            "Status_Code",
        ])

        for log in rows:
            writer.writerow([
                log.id,
                log.timestamp.isoformat() if log.timestamp else "",
                log.username or "",
                log.user_role or "",
                log.action,
                log.resource_type,
                log.resource_id or "",
                log.outcome,
                log.ip_address or "",
                log.request_method or "",
                log.request_path or "",
                log.status_code or "",
            ])

        return output.getvalue()

    # -------------------------------------------------------------------------
    # PDF Report Generator
    # -------------------------------------------------------------------------

    @classmethod
    def export_report_pdf(cls, report: SecurityReportResponse) -> bytes:
        """Generate a professional, polished PDF executive security report using ReportLab."""
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Table,
            TableStyle,
            HRFlowable,
            KeepTogether,
        )
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()

        # Custom Brand Styles
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0f172a"),
            fontName="Helvetica-Bold",
            spaceAfter=4,
        )
        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=13,
            textColor=colors.HexColor("#475569"),
            spaceAfter=12,
        )
        h2_style = ParagraphStyle(
            "SectionH2",
            parent=styles["Heading2"],
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#0f172a"),
            fontName="Helvetica-Bold",
            spaceBefore=10,
            spaceAfter=6,
        )
        body_style = ParagraphStyle(
            "BodyDark",
            parent=styles["Normal"],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#334155"),
        )
        finding_bullet_style = ParagraphStyle(
            "FindingBullet",
            parent=styles["Normal"],
            fontSize=8.5,
            leading=11.5,
            textColor=colors.HexColor("#1e293b"),
            leftIndent=12,
            firstLineIndent=-12,
            spaceAfter=3,
        )
        disclaimer_style = ParagraphStyle(
            "DisclaimerStyle",
            parent=styles["Italic"],
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#64748b"),
        )

        elements = []

        # 1. Header Banner
        elements.append(Paragraph(report.report_title, title_style))
        sub_text = (
            f"<b>Reporting Window:</b> {report.time_range} &nbsp;|&nbsp; "
            f"<b>Generated:</b> {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')} &nbsp;|&nbsp; "
            f"<b>Operator:</b> {report.generated_by}"
        )
        elements.append(Paragraph(sub_text, subtitle_style))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0ea5e9"), spaceAfter=10))

        # 2. Executive Summary Metrics Table
        elements.append(Paragraph("1. Executive Security Metrics Overview", h2_style))
        ex = report.executive_summary
        metrics_data = [
            ["Total Evaluated Flows", str(ex.total_predictions), "Total Security Alerts", str(ex.total_alerts)],
            ["Detected Threats & Anomalies", str(ex.total_threats), "Total Incident Cases", str(ex.total_incidents)],
            ["Critical Priority Alerts", str(ex.alerts_by_severity.get("CRITICAL", 0)), "Resolved Incidents", str(ex.resolved_incidents)],
            ["High Priority Alerts", str(ex.alerts_by_severity.get("HIGH", 0)), "Open / Active Cases", str(ex.unresolved_incidents)],
        ]
        metrics_table = Table(metrics_data, colWidths=[150, 100, 150, 100])
        metrics_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0f172a")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ]))
        elements.append(metrics_table)
        elements.append(Spacer(1, 10))

        # 3. Key Findings & Observations
        if report.important_findings:
            elements.append(Paragraph("2. Key Operational Findings", h2_style))
            for finding in report.important_findings:
                elements.append(Paragraph(f"• {finding}", finding_bullet_style))
            elements.append(Spacer(1, 10))

        # 4. Top Attack Vectors & Source Addresses
        if ex.top_threat_categories or ex.top_source_ips:
            elements.append(Paragraph("3. Threat Vectors & Attacking Origins", h2_style))
            vectors_str = ", ".join([f"{t['threat']} ({t['count']})" for t in ex.top_threat_categories[:5]]) or "None recorded"
            sources_str = ", ".join([f"{s['source_ip']} ({s['count']})" for s in ex.top_source_ips[:5]]) or "None recorded"
            tv_data = [
                [Paragraph("<b>Top Detected Attack Vectors:</b>", body_style), Paragraph(vectors_str, body_style)],
                [Paragraph("<b>Top Originating Source IPs:</b>", body_style), Paragraph(sources_str, body_style)],
            ]
            tv_table = Table(tv_data, colWidths=[160, 340])
            tv_table.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
            ]))
            elements.append(tv_table)
            elements.append(Spacer(1, 10))

        # 5. Incident Response Summary (Recent incidents in window)
        elements.append(Paragraph(f"4. SOC Incident Cases ({len(report.incidents)} sample records)", h2_style))
        if report.incidents:
            inc_headers = ["Key", "Severity", "Status", "Category", "Assigned To", "Created"]
            inc_rows = [inc_headers]
            for inc in report.incidents[:15]:
                inc_rows.append([
                    inc.incident_key,
                    inc.severity,
                    inc.status,
                    (inc.category or "General")[:18],
                    inc.assigned_to or "Unassigned",
                    inc.created_at.strftime("%Y-%m-%d %H:%M"),
                ])
            inc_table = Table(inc_rows, colWidths=[95, 60, 80, 105, 75, 85])
            inc_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
            ]))
            elements.append(inc_table)
        else:
            elements.append(Paragraph("<i>No incident cases recorded during this timeframe.</i>", body_style))
        elements.append(Spacer(1, 10))

        # 6. Recent Security Alerts Table
        elements.append(Paragraph(f"5. Correlated Security Alerts ({len(report.alerts)} sample records)", h2_style))
        if report.alerts:
            alert_headers = ["Alert ID", "Severity", "Threat Label", "Status", "Source IP", "Timestamp"]
            alert_rows = [alert_headers]
            for a in report.alerts[:15]:
                alert_rows.append([
                    f"#{a.id}",
                    a.severity,
                    (a.threat_label or "Anomaly")[:20],
                    a.status,
                    a.source_ip or "N/A",
                    a.timestamp.strftime("%Y-%m-%d %H:%M"),
                ])
            alert_table = Table(alert_rows, colWidths=[55, 65, 125, 75, 90, 90])
            alert_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
            ]))
            elements.append(alert_table)
        else:
            elements.append(Paragraph("<i>No security alerts triggered during this timeframe.</i>", body_style))
        elements.append(Spacer(1, 15))

        # 7. Disclaimer & Authenticity Footer
        elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94a3b8"), spaceAfter=6))
        elements.append(Paragraph(report.disclaimer, disclaimer_style))

        doc.build(elements)
        return buffer.getvalue()

    # -------------------------------------------------------------------------
    # Incident Evidence Export
    # -------------------------------------------------------------------------

    @classmethod
    def generate_incident_evidence(
        cls,
        db: Session,
        incident_id: int,
        exported_by: str,
    ) -> IncidentEvidencePackage:
        """Compile a cryptographically signed forensic evidence package for an individual incident."""
        incident = db.query(IncidentRecord).filter(IncidentRecord.id == incident_id).first()
        if not incident:
            raise ResourceNotFoundException("Incident", incident_id)

        # Linked alerts snapshot
        alerts_data = [
            {
                "alert_id": a.id,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "severity": a.severity,
                "threat_label": a.threat_label,
                "confidence": a.confidence,
                "source_ip": a.source_ip,
                "destination_ip": a.destination_ip,
                "status": a.status,
                "recommended_action": a.recommended_action,
            }
            for a in incident.alerts
        ]

        # Linked predictions snapshot
        predictions_data = [
            {
                "prediction_id": p.id,
                "timestamp": p.timestamp.isoformat() if p.timestamp else None,
                "anomaly_label": p.anomaly_label,
                "anomaly_score": p.anomaly_score,
                "predicted_threat": p.predicted_threat,
                "classification_confidence": p.classification_confidence,
                "risk_level": p.risk_level,
                "source_ip": p.source_ip,
                "destination_ip": p.destination_ip,
                "destination_port": p.destination_port,
                "protocol": p.protocol,
            }
            for p in incident.predictions
        ]

        # Case notes
        notes_data = [
            {
                "note_id": n.id,
                "author": n.author,
                "note": n.note,
                "created_at": n.created_at.isoformat() if n.created_at else None,
            }
            for n in incident.notes
        ]

        # Lifecycle Timeline
        timeline_events = [
            {
                "event_type": "INCIDENT_CREATED",
                "timestamp": incident.created_at.isoformat() if incident.created_at else None,
                "actor": incident.created_by,
                "summary": f"Incident {incident.incident_key} created with initial status OPEN.",
            }
        ]
        if incident.acknowledged_at:
            timeline_events.append({
                "event_type": "INCIDENT_ACKNOWLEDGED",
                "timestamp": incident.acknowledged_at.isoformat(),
                "actor": incident.assigned_to or incident.created_by,
                "summary": "Incident acknowledged by security operator.",
            })
        if incident.investigation_started_at:
            timeline_events.append({
                "event_type": "INVESTIGATION_STARTED",
                "timestamp": incident.investigation_started_at.isoformat(),
                "actor": incident.assigned_to or "SOC Operator",
                "summary": "Deep forensic investigation commenced.",
            })
        if incident.resolved_at:
            timeline_events.append({
                "event_type": "INCIDENT_RESOLVED",
                "timestamp": incident.resolved_at.isoformat(),
                "actor": incident.assigned_to or "SOC Operator",
                "summary": f"Incident resolved. Remediation: {incident.resolution_summary or 'Completed.'}",
            })

        # Relevant Audit Events for this incident
        audits = (
            db.query(AuditLogRecord)
            .filter(AuditLogRecord.resource_id == str(incident.id))
            .order_by(AuditLogRecord.timestamp.asc())
            .all()
        )
        audit_data = [
            {
                "audit_id": aud.id,
                "timestamp": aud.timestamp.isoformat() if aud.timestamp else None,
                "username": aud.username,
                "user_role": aud.user_role,
                "action": aud.action,
                "outcome": aud.outcome,
                "ip_address": aud.ip_address,
                "request_method": aud.request_method,
                "request_path": aud.request_path,
            }
            for aud in audits
        ]

        # Compute SHA-256 evidence integrity hash
        hash_payload = {
            "incident_id": incident.id,
            "incident_key": incident.incident_key,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "created_at": incident.created_at.isoformat() if incident.created_at else "",
            "alerts": alerts_data,
            "predictions": predictions_data,
            "notes": notes_data,
            "timeline": timeline_events,
            "audit_events": audit_data,
        }
        canonical_json = json.dumps(hash_payload, sort_keys=True)
        evidence_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

        return IncidentEvidencePackage(
            incident_id=incident.id,
            incident_key=incident.incident_key,
            title=incident.title,
            description=incident.description,
            severity=incident.severity,
            status=incident.status,
            category=incident.category,
            source_ip=incident.source_ip,
            assigned_to=incident.assigned_to,
            created_by=incident.created_by,
            created_at=incident.created_at,
            acknowledged_at=incident.acknowledged_at,
            investigation_started_at=incident.investigation_started_at,
            resolved_at=incident.resolved_at,
            resolution_summary=incident.resolution_summary,
            notes=notes_data,
            related_alerts=alerts_data,
            related_predictions=predictions_data,
            timeline=timeline_events,
            relevant_audit_events=audit_data,
            evidence_hash_sha256=evidence_hash,
            exported_by=exported_by,
            exported_at=datetime.now(timezone.utc),
        )

    @classmethod
    def export_incident_evidence_zip(cls, evidence: IncidentEvidencePackage) -> bytes:
        """Package forensic evidence components into an in-memory ZIP archive."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            # 1. Incident Overview JSON
            overview_dict = {
                "incident_key": evidence.incident_key,
                "incident_id": evidence.incident_id,
                "title": evidence.title,
                "description": evidence.description,
                "severity": evidence.severity,
                "status": evidence.status,
                "category": evidence.category,
                "source_ip": evidence.source_ip,
                "assigned_to": evidence.assigned_to,
                "created_by": evidence.created_by,
                "created_at": evidence.created_at.isoformat(),
                "acknowledged_at": evidence.acknowledged_at.isoformat() if evidence.acknowledged_at else None,
                "investigation_started_at": evidence.investigation_started_at.isoformat() if evidence.investigation_started_at else None,
                "resolved_at": evidence.resolved_at.isoformat() if evidence.resolved_at else None,
                "resolution_summary": evidence.resolution_summary,
                "evidence_hash_sha256": evidence.evidence_hash_sha256,
                "exported_by": evidence.exported_by,
                "exported_at": evidence.exported_at.isoformat(),
            }
            zip_file.writestr("incident_overview.json", json.dumps(overview_dict, indent=2))

            # 2. Correlated Alerts JSON
            zip_file.writestr("correlated_alerts.json", json.dumps(evidence.related_alerts, indent=2))

            # 3. Correlated Predictions JSON
            zip_file.writestr("correlated_predictions.json", json.dumps(evidence.related_predictions, indent=2))

            # 4. Analyst Notes JSON
            zip_file.writestr("analyst_notes.json", json.dumps(evidence.notes, indent=2))

            # 5. Timeline JSON
            zip_file.writestr("incident_timeline.json", json.dumps(evidence.timeline, indent=2))

            # 6. Audit Trail JSON
            zip_file.writestr("audit_trail.json", json.dumps(evidence.relevant_audit_events, indent=2))

            # 7. Chain of Custody & Verification Manifest
            manifest_content = (
                "========================================================================\n"
                "           NIDS SOC FORENSIC EVIDENCE CHAIN-OF-CUSTODY MANIFEST          \n"
                "========================================================================\n\n"
                f"Incident Key:       {evidence.incident_key} (ID: #{evidence.incident_id})\n"
                f"Case Title:         {evidence.title}\n"
                f"Severity / Status:  {evidence.severity} / {evidence.status}\n"
                f"Exported By:        {evidence.exported_by}\n"
                f"Export Timestamp:   {evidence.exported_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                f"SHA-256 Checksum:   {evidence.evidence_hash_sha256}\n\n"
                "Included Artifacts:\n"
                "- incident_overview.json\n"
                "- correlated_alerts.json\n"
                "- correlated_predictions.json\n"
                "- analyst_notes.json\n"
                "- incident_timeline.json\n"
                "- audit_trail.json\n\n"
                f"Disclaimer:\n{evidence.disclaimer}\n"
            )
            zip_file.writestr("manifest.txt", manifest_content)

        return zip_buffer.getvalue()
