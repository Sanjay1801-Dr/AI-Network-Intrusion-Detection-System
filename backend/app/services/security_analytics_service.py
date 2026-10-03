"""Security analytics aggregation and investigation service (Phase 13).

Provides database-driven analytics across predictions, alerts, and audit records:
- High-level overview KPIs
- Attack category and severity distributions
- Time-series security trend timeline
- Top threat originating IP sources
- Deterministic rule-based prediction explainability
- Forensic prediction investigation aggregation
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from backend.app.core.errors import ResourceNotFoundException
from backend.app.models.alert import AlertRecord
from backend.app.models.audit import AuditLogRecord
from backend.app.models.prediction import PredictionRecord
from backend.app.schemas.analytics import (
    AnalyticsOverviewResponse,
    ThreatCategoryCount,
    SeverityCount,
    ThreatDistributionResponse,
    TimelineBucket,
    TimelineResponse,
    TopThreatSource,
    TopSourcesResponse,
    PredictionInvestigationResponse,
    ThreatIntelligenceLookupResponse,
)
from backend.app.schemas.audit import AuditAction
from backend.app.services.threat_intelligence_service import ThreatIntelligenceService

logger = logging.getLogger("nids.services.analytics")

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


class SecurityAnalyticsService:
    """Coordinates security telemetry analytics and investigation workflows."""

    @staticmethod
    def get_overview(db: Session) -> AnalyticsOverviewResponse:
        """Compute aggregated security metrics across predictions, alerts, and access logs."""
        # 1. Prediction Statistics
        total_preds = db.query(func.count(PredictionRecord.id)).scalar() or 0

        benign_preds = (
            db.query(func.count(PredictionRecord.id))
            .filter(
                (func.upper(PredictionRecord.predicted_threat) == "BENIGN")
                | (PredictionRecord.intrusion_flag == False)  # noqa: E712
            )
            .scalar()
            or 0
        )

        malicious_preds = (
            db.query(func.count(PredictionRecord.id))
            .filter(
                (func.upper(PredictionRecord.predicted_threat) != "BENIGN")
                & (PredictionRecord.intrusion_flag == True)  # noqa: E712
            )
            .scalar()
            or 0
        )

        anomaly_preds = (
            db.query(func.count(PredictionRecord.id))
            .filter(
                (func.upper(PredictionRecord.anomaly_label).in_(["ANOMALOUS", "ANOMALY", "OUTLIER"]))
                | (PredictionRecord.anomaly_score >= 0.5)
            )
            .scalar()
            or 0
        )

        # 2. Alert Incident Statistics
        total_alerts = db.query(func.count(AlertRecord.id)).scalar() or 0

        open_alerts = (
            db.query(func.count(AlertRecord.id))
            .filter(AlertRecord.status.in_(["NEW", "ACKNOWLEDGED"]))
            .scalar()
            or 0
        )

        critical_alerts = (
            db.query(func.count(AlertRecord.id))
            .filter(AlertRecord.severity == "CRITICAL")
            .scalar()
            or 0
        )

        high_alerts = (
            db.query(func.count(AlertRecord.id))
            .filter(AlertRecord.severity == "HIGH")
            .scalar()
            or 0
        )

        medium_alerts = (
            db.query(func.count(AlertRecord.id))
            .filter(AlertRecord.severity == "MEDIUM")
            .scalar()
            or 0
        )

        resolved_alerts = (
            db.query(func.count(AlertRecord.id))
            .filter(AlertRecord.status == "RESOLVED")
            .scalar()
            or 0
        )

        # 3. Security Audit Statistics
        failed_logins = (
            db.query(func.count(AuditLogRecord.id))
            .filter(AuditLogRecord.action == AuditAction.LOGIN_FAILURE.value)
            .scalar()
            or 0
        )

        access_denied = (
            db.query(func.count(AuditLogRecord.id))
            .filter(AuditLogRecord.action == AuditAction.ACCESS_DENIED.value)
            .scalar()
            or 0
        )

        rate_limit_events = (
            db.query(func.count(AuditLogRecord.id))
            .filter(AuditLogRecord.action == AuditAction.RATE_LIMIT_EXCEEDED.value)
            .scalar()
            or 0
        )

        return AnalyticsOverviewResponse(
            total_predictions=int(total_preds),
            benign_predictions=int(benign_preds),
            malicious_predictions=int(malicious_preds),
            anomaly_predictions=int(anomaly_preds),
            total_alerts=int(total_alerts),
            open_alerts=int(open_alerts),
            critical_alerts=int(critical_alerts),
            high_alerts=int(high_alerts),
            medium_alerts=int(medium_alerts),
            resolved_alerts=int(resolved_alerts),
            failed_logins=int(failed_logins),
            access_denied=int(access_denied),
            rate_limit_events=int(rate_limit_events),
        )

    @staticmethod
    def get_threat_distribution(db: Session) -> ThreatDistributionResponse:
        """Compute aggregated distributions for attack categories and severity triage ratings."""
        total_evaluated = db.query(func.count(PredictionRecord.id)).scalar() or 0

        # Group by predicted_threat
        threat_rows = (
            db.query(
                PredictionRecord.predicted_threat,
                func.count(PredictionRecord.id),
            )
            .group_by(PredictionRecord.predicted_threat)
            .order_by(func.count(PredictionRecord.id).desc())
            .all()
        )

        threat_categories = []
        for cat, cnt in threat_rows:
            pct = round((cnt / total_evaluated) * 100, 2) if total_evaluated > 0 else 0.0
            threat_categories.append(ThreatCategoryCount(category=cat, count=cnt, percentage=pct))

        # Group by risk_level (severity)
        severity_rows = (
            db.query(
                PredictionRecord.risk_level,
                func.count(PredictionRecord.id),
            )
            .group_by(PredictionRecord.risk_level)
            .all()
        )

        # Ensure canonical severity sort
        canonical_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        severity_map = {row[0].upper(): row[1] for row in severity_rows if row[0]}
        severity_list = []
        for sev in canonical_severities:
            cnt = severity_map.get(sev, 0)
            pct = round((cnt / total_evaluated) * 100, 2) if total_evaluated > 0 else 0.0
            severity_list.append(SeverityCount(severity=sev, count=cnt, percentage=pct))

        return ThreatDistributionResponse(
            threat_categories=threat_categories,
            severity=severity_list,
            total_evaluated=int(total_evaluated),
        )

    @staticmethod
    def get_security_timeline(
        db: Session,
        time_range: str = "7d",
        limit: int = 50,
    ) -> TimelineResponse:
        """Aggregate security events across predictions, alerts, and audit logs into chronological time slices."""
        now = datetime.now(timezone.utc)
        if time_range == "24h":
            since = now - timedelta(hours=24)
            bucket_format = "%Y-%m-%d %H:00"
        elif time_range == "30d":
            since = now - timedelta(days=30)
            bucket_format = "%Y-%m-%d"
        else:  # default 7d
            since = now - timedelta(days=7)
            bucket_format = "%Y-%m-%d"

        # Bounded queries for events since threshold
        pred_records = (
            db.query(PredictionRecord.timestamp)
            .filter(PredictionRecord.timestamp >= since)
            .order_by(PredictionRecord.timestamp.asc())
            .limit(500)
            .all()
        )

        alert_records = (
            db.query(AlertRecord.timestamp)
            .filter(AlertRecord.timestamp >= since)
            .order_by(AlertRecord.timestamp.asc())
            .limit(500)
            .all()
        )

        audit_records = (
            db.query(AuditLogRecord.timestamp, AuditLogRecord.action)
            .filter(AuditLogRecord.timestamp >= since)
            .order_by(AuditLogRecord.timestamp.asc())
            .limit(500)
            .all()
        )

        # Time bucket aggregation
        buckets: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {
                "predictions": 0,
                "alerts": 0,
                "failed_logins": 0,
                "access_denied": 0,
                "rate_limit_events": 0,
            }
        )

        for (t,) in pred_records:
            if t:
                key = t.strftime(bucket_format)
                buckets[key]["predictions"] += 1

        for (t,) in alert_records:
            if t:
                key = t.strftime(bucket_format)
                buckets[key]["alerts"] += 1

        for t, act in audit_records:
            if t:
                key = t.strftime(bucket_format)
                if act == AuditAction.LOGIN_FAILURE.value:
                    buckets[key]["failed_logins"] += 1
                elif act == AuditAction.ACCESS_DENIED.value:
                    buckets[key]["access_denied"] += 1
                elif act == AuditAction.RATE_LIMIT_EXCEEDED.value:
                    buckets[key]["rate_limit_events"] += 1

        # Sort chronological and enforce limit
        sorted_keys = sorted(buckets.keys())[-limit:]
        timeline_items = [
            TimelineBucket(
                bucket_time=k,
                predictions=buckets[k]["predictions"],
                alerts=buckets[k]["alerts"],
                failed_logins=buckets[k]["failed_logins"],
                access_denied=buckets[k]["access_denied"],
                rate_limit_events=buckets[k]["rate_limit_events"],
            )
            for k in sorted_keys
        ]

        return TimelineResponse(
            time_range=time_range,
            total_buckets=len(timeline_items),
            timeline=timeline_items,
        )

    @staticmethod
    def get_top_threat_sources(db: Session, limit: int = 10) -> TopSourcesResponse:
        """Identify top originating source IP addresses with attack frequency metrics."""
        # Query distinct source IPs where source_ip is not null
        source_count = (
            db.query(func.count(func.distinct(PredictionRecord.source_ip)))
            .filter(PredictionRecord.source_ip.isnot(None), PredictionRecord.source_ip != "")
            .scalar()
            or 0
        )

        if source_count == 0:
            return TopSourcesResponse(
                total_sources=0,
                items=[],
                source_data_available=False,
            )

        # Aggregate prediction metrics grouped by source_ip
        results = (
            db.query(
                PredictionRecord.source_ip,
                func.count(PredictionRecord.id).label("total_preds"),
                func.sum(
                    case((PredictionRecord.predicted_threat != "Benign", 1), else_=0)
                ).label("malicious_count"),
            )
            .filter(PredictionRecord.source_ip.isnot(None), PredictionRecord.source_ip != "")
            .group_by(PredictionRecord.source_ip)
            .order_by(func.count(PredictionRecord.id).desc())
            .limit(limit)
            .all()
        )

        top_sources: List[TopThreatSource] = []
        for src_ip, total_preds, mal_count in results:
            # Query highest severity and most common threat for this IP
            records_for_ip = (
                db.query(PredictionRecord.risk_level, PredictionRecord.predicted_threat)
                .filter(PredictionRecord.source_ip == src_ip)
                .all()
            )

            # Determine highest severity
            highest_sev = "LOW"
            highest_sev_rank = 1
            threat_freq: Dict[str, int] = defaultdict(int)

            for risk, threat in records_for_ip:
                rank = SEVERITY_ORDER.get(str(risk).upper(), 1)
                if rank > highest_sev_rank:
                    highest_sev_rank = rank
                    highest_sev = str(risk).upper()
                if threat and threat != "Benign":
                    threat_freq[threat] += 1

            most_common = (
                max(threat_freq, key=threat_freq.get) if threat_freq else "Benign"
            )

            top_sources.append(
                TopThreatSource(
                    source_ip=src_ip,
                    prediction_count=int(total_preds),
                    malicious_count=int(mal_count or 0),
                    highest_severity=highest_sev,
                    most_common_threat=most_common,
                )
            )

        return TopSourcesResponse(
            total_sources=int(source_count),
            items=top_sources,
            source_data_available=True,
        )

    @classmethod
    def generate_prediction_explanation(
        cls, prediction: PredictionRecord
    ) -> List[str]:
        """Generate deterministic, rule-based explanations grounded in ML outputs and flow parameters.

        Strict Guarantee:
        - Deterministic thresholds and flow features only.
        - Never fabricates SHAP/LIME feature attribution.
        """
        reasons: List[str] = []

        # 1. Unsupervised Anomaly Divergence
        if prediction.anomaly_score >= 0.70:
            reasons.append(
                f"Severe anomaly divergence (score: {prediction.anomaly_score:.3f}) detected by Isolation Forest"
            )
        elif prediction.anomaly_score >= 0.50:
            reasons.append(
                f"Elevated statistical outlier score ({prediction.anomaly_score:.3f}) above nominal traffic baseline"
            )

        # 2. Supervised Threat Pattern Classification
        threat = prediction.predicted_threat
        if threat and threat.lower() != "benign":
            reasons.append(
                f"Supervised Random Forest classified flow signature as '{threat}' attack vector"
            )

        # 3. Model Classification Confidence
        conf = float(prediction.classification_confidence or 0.0)
        if conf >= 0.85 and threat and threat.lower() != "benign":
            reasons.append(
                f"High classifier confidence ({conf * 100:.1f}%) supporting threat designation"
            )
        elif conf < 0.50 and threat and threat.lower() != "benign":
            reasons.append(
                f"Moderate classifier confidence ({conf * 100:.1f}%); recommends secondary validation"
            )

        # 4. Critical Port Context
        port = prediction.destination_port
        if port is not None:
            if port in (21, 22, 23, 3389):
                reasons.append(f"Target involves administrative remote access service (port {port})")
            elif port in (80, 443, 8080, 8443):
                reasons.append(f"Target involves public web application service (port {port})")
            elif port in (53,):
                reasons.append("Target involves core DNS resolution infrastructure (port 53)")

        # 5. Composite Risk Assessment Triage
        risk = str(prediction.risk_level or "LOW").upper()
        if risk in ("CRITICAL", "HIGH"):
            reasons.append(
                f"Composite risk assessment assigned {risk} priority based on combined anomaly and threat scores"
            )

        # 6. Benign Confirmation
        if not prediction.intrusion_flag and (not threat or threat.lower() == "benign"):
            reasons.append(
                "Flow telemetry metrics conform to expected baseline benign traffic patterns"
            )

        return reasons if reasons else ["Standard baseline network flow evaluation"]

    @classmethod
    def investigate_prediction(
        cls,
        db: Session,
        prediction_id: int,
    ) -> PredictionInvestigationResponse:
        """Aggregate full forensic context for a specific network flow prediction."""
        pred = (
            db.query(PredictionRecord)
            .filter(PredictionRecord.id == prediction_id)
            .first()
        )
        if not pred:
            raise ResourceNotFoundException("Prediction", prediction_id)

        # 1. Deterministic Rule-Based Explanation
        risk_reasons = cls.generate_prediction_explanation(pred)

        # 2. Extract Flow Telemetry Attributes
        flow_telemetry: Dict[str, Any] = {
            "source_ip": pred.source_ip,
            "destination_ip": pred.destination_ip,
            "source_port": pred.source_port,
            "destination_port": pred.destination_port,
            "protocol": pred.protocol,
            "flow_duration": pred.flow_duration,
            "total_forward_packets": pred.total_forward_packets,
            "total_backward_packets": pred.total_backward_packets,
            "total_bytes": pred.total_bytes,
        }

        # Include additional non-sensitive parameters from raw_flow_data if available
        if pred.raw_flow_data:
            try:
                parsed_raw = json.loads(pred.raw_flow_data)
                if isinstance(parsed_raw, dict):
                    flow_telemetry["raw_features"] = parsed_raw
            except Exception:
                pass

        # 3. Query Associated Alert (if generated)
        alert = (
            db.query(AlertRecord)
            .filter(AlertRecord.prediction_id == prediction_id)
            .first()
        )
        related_alert_dict: Optional[Dict[str, Any]] = None
        if alert:
            related_alert_dict = {
                "alert_id": alert.id,
                "status": alert.status,
                "severity": alert.severity,
                "alert_type": alert.alert_type,
                "threat_label": alert.threat_label,
                "anomaly_score": alert.anomaly_score,
                "confidence": alert.confidence,
                "recommended_action": alert.recommended_action,
                "created_at": alert.created_at.isoformat() if alert.created_at else None,
                "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
                "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
            }

        # 4. Query Related Audit Trail Logs
        audit_records = (
            db.query(AuditLogRecord)
            .filter(AuditLogRecord.resource_id == str(prediction_id))
            .order_by(AuditLogRecord.timestamp.desc())
            .limit(10)
            .all()
        )
        related_audits = [
            {
                "id": a.id,
                "action": a.action,
                "outcome": a.outcome,
                "username": a.username,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            }
            for a in audit_records
        ]

        # 5. Threat Intelligence Reputation Enrichment
        threat_intel: Optional[ThreatIntelligenceLookupResponse] = None
        if pred.source_ip:
            try:
                intel_data = ThreatIntelligenceService.lookup_ip(pred.source_ip)
                threat_intel = ThreatIntelligenceLookupResponse(**intel_data)
            except Exception as intel_err:
                logger.debug("Threat intelligence lookup skipped for %s: %s", pred.source_ip, intel_err)

        return PredictionInvestigationResponse(
            prediction_id=pred.id,
            timestamp=pred.timestamp,
            threat_category=pred.predicted_threat,
            severity=pred.risk_level,
            anomaly_score=float(pred.anomaly_score),
            classifier_confidence=float(pred.classification_confidence),
            intrusion_flag=pred.intrusion_flag,
            risk_reasons=risk_reasons,
            flow_telemetry=flow_telemetry,
            related_alert=related_alert_dict,
            related_audit_records=related_audits,
            threat_intelligence=threat_intel,
        )
