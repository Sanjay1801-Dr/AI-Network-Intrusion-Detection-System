"""Business logic and correlation engine for Phase 16 Threat Hunting & Investigation Workbench."""

from datetime import datetime, timedelta, timezone
import ipaddress
import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import desc, func, or_
from sqlalchemy.orm import Session

from backend.app.core.errors import ResourceNotFoundException, ValidationException
from backend.app.models.alert import AlertRecord
from backend.app.models.audit import AuditLogRecord
from backend.app.models.incident import IncidentRecord
from backend.app.models.prediction import PredictionRecord
from backend.app.models.threat_hunting import HuntQueryHistoryRecord
from backend.app.schemas.threat_hunting import (
    CorrelationInsight,
    HuntAlertItem,
    HuntIncidentItem,
    HuntPredictionItem,
    HuntQueryHistoryItem,
    HuntTimelineEvent,
    SourceInvestigationResponse,
    ThreatHuntSearchRequest,
    ThreatHuntSearchResponse,
    ThreatHuntingSummaryResponse,
)

logger = logging.getLogger("nids.services.threat_hunting")

MAX_HUNT_ITEMS = 200
MAX_HISTORY_ENTRIES = 50


class ThreatHuntingService:
    """Service providing structured threat hunt search, event correlation, and source-centric investigation."""

    @staticmethod
    def parse_hunt_time_range(
        time_range: Optional[str] = "24h",
        start_datetime: Optional[datetime] = None,
        end_datetime: Optional[datetime] = None,
    ) -> Tuple[datetime, datetime, str]:
        """Convert time range descriptor or custom timestamps into validated UTC datetimes."""
        now = datetime.now(timezone.utc)
        normalized = (time_range or "24h").lower().strip()

        if normalized == "1h":
            return now - timedelta(hours=1), now, "Last 1 Hour"
        elif normalized == "24h":
            return now - timedelta(hours=24), now, "Last 24 Hours"
        elif normalized == "7d":
            return now - timedelta(days=7), now, "Last 7 Days"
        elif normalized == "30d":
            return now - timedelta(days=30), now, "Last 30 Days"
        elif normalized == "custom":
            if not start_datetime or not end_datetime:
                raise ValidationException("Custom time range requires both start_datetime and end_datetime.")

            start_dt = start_datetime if start_datetime.tzinfo else start_datetime.replace(tzinfo=timezone.utc)
            end_dt = end_datetime if end_datetime.tzinfo else end_datetime.replace(tzinfo=timezone.utc)

            if start_dt >= end_dt:
                raise ValidationException("start_datetime must be strictly earlier than end_datetime.")
            if (end_dt - start_dt).days > 90:
                raise ValidationException("Requested custom hunt time window cannot exceed 90 days.")

            return start_dt, end_dt, f"Custom ({start_dt.strftime('%Y-%m-%d')} to {end_dt.strftime('%Y-%m-%d')})"
        else:
            return now - timedelta(hours=24), now, "Last 24 Hours"

    @classmethod
    def execute_hunt_search(
        cls,
        db: Session,
        req: ThreatHuntSearchRequest,
        username: str = "analyst",
    ) -> ThreatHuntSearchResponse:
        """Execute structured, parameterized threat hunt across predictions, alerts, and incidents."""
        start_dt, end_dt, range_label = cls.parse_hunt_time_range(
            time_range=req.time_range,
            start_datetime=req.start_datetime,
            end_datetime=req.end_datetime,
        )

        safe_limit = min(max(1, req.limit), MAX_HUNT_ITEMS)
        safe_offset = max(0, req.offset)

        # -----------------------------------------------------------------
        # 1. Query Predictions
        # -----------------------------------------------------------------
        p_query = db.query(PredictionRecord).filter(
            PredictionRecord.timestamp >= start_dt,
            PredictionRecord.timestamp <= end_dt,
        )

        if req.source_ip:
            p_query = p_query.filter(PredictionRecord.source_ip == req.source_ip)
        if req.destination_ip:
            p_query = p_query.filter(PredictionRecord.destination_ip == req.destination_ip)
        if req.source_port is not None:
            p_query = p_query.filter(PredictionRecord.source_port == req.source_port)
        if req.destination_port is not None:
            p_query = p_query.filter(PredictionRecord.destination_port == req.destination_port)
        if req.protocol:
            p_query = p_query.filter(PredictionRecord.protocol == str(req.protocol).strip())
        if req.threat_category:
            p_query = p_query.filter(
                func.lower(PredictionRecord.predicted_threat).contains(req.threat_category.lower().strip())
            )
        if req.severity:
            p_query = p_query.filter(PredictionRecord.risk_level == req.severity.upper().strip())
        if req.risk_level:
            p_query = p_query.filter(PredictionRecord.risk_level == req.risk_level.upper().strip())
        if req.min_anomaly_score is not None:
            p_query = p_query.filter(PredictionRecord.anomaly_score >= req.min_anomaly_score)
        if req.max_anomaly_score is not None:
            p_query = p_query.filter(PredictionRecord.anomaly_score <= req.max_anomaly_score)
        if req.min_confidence is not None:
            p_query = p_query.filter(PredictionRecord.classification_confidence >= req.min_confidence)
        if req.max_confidence is not None:
            p_query = p_query.filter(PredictionRecord.classification_confidence <= req.max_confidence)
        if req.query_text:
            text_pat = f"%{req.query_text.lower().strip()}%"
            p_query = p_query.filter(
                or_(
                    func.lower(PredictionRecord.predicted_threat).like(text_pat),
                    func.lower(PredictionRecord.anomaly_label).like(text_pat),
                    func.lower(PredictionRecord.source_ip).like(text_pat),
                    func.lower(PredictionRecord.destination_ip).like(text_pat),
                )
            )

        total_predictions = p_query.count()
        prediction_rows = (
            p_query.order_by(desc(PredictionRecord.timestamp))
            .offset(safe_offset)
            .limit(safe_limit)
            .all()
        )

        matching_predictions = [
            HuntPredictionItem(
                id=p.id,
                timestamp=p.timestamp,
                source_ip=p.source_ip,
                destination_ip=p.destination_ip,
                source_port=p.source_port,
                destination_port=p.destination_port,
                protocol=p.protocol,
                predicted_threat=p.predicted_threat or "BENIGN",
                risk_level=p.risk_level or "LOW",
                anomaly_score=round(float(p.anomaly_score or 0.0), 4),
                classification_confidence=round(float(p.classification_confidence or 0.0), 4),
                intrusion_flag=bool(p.intrusion_flag),
            )
            for p in prediction_rows
        ]

        # -----------------------------------------------------------------
        # 2. Query Alerts
        # -----------------------------------------------------------------
        a_query = db.query(AlertRecord).filter(
            AlertRecord.timestamp >= start_dt,
            AlertRecord.timestamp <= end_dt,
        )

        if req.source_ip:
            a_query = a_query.filter(AlertRecord.source_ip == req.source_ip)
        if req.destination_ip:
            a_query = a_query.filter(AlertRecord.destination_ip == req.destination_ip)
        if req.threat_category:
            a_query = a_query.filter(
                func.lower(AlertRecord.threat_label).contains(req.threat_category.lower().strip())
            )
        if req.severity:
            a_query = a_query.filter(AlertRecord.severity == req.severity.upper().strip())
        if req.alert_status:
            a_query = a_query.filter(AlertRecord.status == req.alert_status.upper().strip())
        if req.query_text:
            text_pat = f"%{req.query_text.lower().strip()}%"
            a_query = a_query.filter(
                or_(
                    func.lower(AlertRecord.threat_label).like(text_pat),
                    func.lower(AlertRecord.alert_type).like(text_pat),
                    func.lower(AlertRecord.source_ip).like(text_pat),
                    func.lower(AlertRecord.destination_ip).like(text_pat),
                )
            )

        total_alerts = a_query.count()
        alert_rows = (
            a_query.order_by(desc(AlertRecord.timestamp))
            .offset(safe_offset)
            .limit(safe_limit)
            .all()
        )

        matching_alerts = [
            HuntAlertItem(
                id=a.id,
                timestamp=a.timestamp,
                prediction_id=a.prediction_id,
                severity=a.severity,
                status=a.status,
                alert_type=a.alert_type or "SECURITY_ALERT",
                threat_label=a.threat_label or "Anomaly",
                confidence=round(float(a.confidence or 0.0), 4),
                source_ip=a.source_ip,
                destination_ip=a.destination_ip,
            )
            for a in alert_rows
        ]

        # -----------------------------------------------------------------
        # 3. Query Incidents
        # -----------------------------------------------------------------
        i_query = db.query(IncidentRecord).filter(
            IncidentRecord.created_at >= start_dt,
            IncidentRecord.created_at <= end_dt,
        )

        if req.source_ip:
            i_query = i_query.filter(IncidentRecord.source_ip == req.source_ip)
        if req.threat_category:
            i_query = i_query.filter(
                func.lower(IncidentRecord.category).contains(req.threat_category.lower().strip())
            )
        if req.severity:
            i_query = i_query.filter(IncidentRecord.severity == req.severity.upper().strip())
        if req.incident_status:
            i_query = i_query.filter(IncidentRecord.status == req.incident_status.upper().strip())
        if req.query_text:
            text_pat = f"%{req.query_text.lower().strip()}%"
            i_query = i_query.filter(
                or_(
                    func.lower(IncidentRecord.incident_key).like(text_pat),
                    func.lower(IncidentRecord.title).like(text_pat),
                    func.lower(IncidentRecord.description).like(text_pat),
                    func.lower(IncidentRecord.category).like(text_pat),
                )
            )

        total_incidents = i_query.count()
        incident_rows = (
            i_query.order_by(desc(IncidentRecord.created_at))
            .offset(safe_offset)
            .limit(safe_limit)
            .all()
        )

        matching_incidents = [
            HuntIncidentItem(
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
            )
            for i in incident_rows
        ]

        # -----------------------------------------------------------------
        # 4. Synthesize Correlation Insights
        # -----------------------------------------------------------------
        correlations = cls.synthesize_correlations(
            predictions=matching_predictions,
            alerts=matching_alerts,
            incidents=matching_incidents,
        )

        # -----------------------------------------------------------------
        # 5. Persist Safe Query History
        # -----------------------------------------------------------------
        filter_summary_parts = []
        if req.source_ip:
            filter_summary_parts.append(f"src:{req.source_ip}")
        if req.threat_category:
            filter_summary_parts.append(f"threat:{req.threat_category}")
        if req.severity:
            filter_summary_parts.append(f"sev:{req.severity}")
        if req.destination_port:
            filter_summary_parts.append(f"port:{req.destination_port}")
        if req.query_text:
            filter_summary_parts.append(f"q:'{req.query_text}'")
        filter_summary_parts.append(range_label)

        filter_summary = ", ".join(filter_summary_parts)[:250]
        total_results = total_predictions + total_alerts + total_incidents

        cls.record_query_history(
            db=db,
            username=username,
            filter_summary=filter_summary,
            filters=req.model_dump(exclude_none=True),
            result_count=total_results,
        )

        return ThreatHuntSearchResponse(
            total_predictions=total_predictions,
            total_alerts=total_alerts,
            total_incidents=total_incidents,
            matching_predictions=matching_predictions,
            matching_alerts=matching_alerts,
            matching_incidents=matching_incidents,
            correlations=correlations,
            applied_filters=req.model_dump(exclude_none=True),
            time_range_label=range_label,
            start_datetime=start_dt,
            end_datetime=end_dt,
            limit=safe_limit,
            offset=safe_offset,
        )

    # -------------------------------------------------------------------------
    # Correlation Logic
    # -------------------------------------------------------------------------

    @classmethod
    def synthesize_correlations(
        cls,
        predictions: List[HuntPredictionItem],
        alerts: List[HuntAlertItem],
        incidents: List[HuntIncidentItem],
    ) -> List[CorrelationInsight]:
        """Correlate security events by network convergence, temporal bursts, and incident links."""
        insights: List[CorrelationInsight] = []

        # 1. Network Convergence: Group by Source IP
        src_map: Dict[str, List[HuntPredictionItem]] = {}
        for p in predictions:
            if p.source_ip:
                src_map.setdefault(p.source_ip, []).append(p)

        for src_ip, items in src_map.items():
            if len(items) >= 2:
                ports = {p.destination_port for p in items if p.destination_port}
                ports_str = ", ".join(str(pt) for pt in sorted(ports)) if ports else "N/A"
                insights.append(
                    CorrelationInsight(
                        correlation_type="NETWORK_CONVERGENCE",
                        title=f"Repeated Probe / Attack Convergence from {src_ip}",
                        description=(
                            f"Source IP '{src_ip}' generated {len(items)} matching flow predictions "
                            f"targeting destination port(s): {ports_str}."
                        ),
                        event_count=len(items),
                        confidence="HIGH" if len(items) >= 5 else "MEDIUM",
                    )
                )

        # 2. Correlated Incidents Linkage
        if incidents:
            for inc in incidents[:3]:
                insights.append(
                    CorrelationInsight(
                        correlation_type="CASE_CORRELATION",
                        title=f"Associated SOC Incident Case: {inc.incident_key}",
                        description=(
                            f"Active case '{inc.title}' ({inc.severity}, status {inc.status}) "
                            f"shares search attributes with current threat hunt results."
                        ),
                        event_count=1,
                        confidence="HIGH",
                    )
                )

        # 3. Temporal Density / Burst Correlation
        if len(predictions) >= 3:
            timestamps = sorted([p.timestamp for p in predictions])
            earliest = timestamps[0]
            latest = timestamps[-1]
            span_seconds = (latest - earliest).total_seconds()
            if span_seconds > 0 and span_seconds <= 600:  # Within 10 minutes
                insights.append(
                    CorrelationInsight(
                        correlation_type="TEMPORAL_BURST",
                        title="Short-Duration Event Burst Detected",
                        description=(
                            f"Observed {len(predictions)} suspicious flows within a tight "
                            f"{int(span_seconds / 60)} minute window. Indicates potential automated script or tool."
                        ),
                        event_count=len(predictions),
                        confidence="HIGH",
                    )
                )

        return insights

    # -------------------------------------------------------------------------
    # Source-Centric Investigation
    # -------------------------------------------------------------------------

    @classmethod
    def investigate_source_ip(cls, db: Session, ip_address: str) -> SourceInvestigationResponse:
        """Conduct a deep, source-centric forensic analysis for an individual IP address."""
        cleaned_ip = ip_address.strip()
        try:
            ipaddress.ip_address(cleaned_ip)
        except ValueError:
            raise ValidationException(f"Invalid IPv4 or IPv6 address: '{cleaned_ip}'")

        # 1. Fetch Predictions
        pred_rows = (
            db.query(PredictionRecord)
            .filter(PredictionRecord.source_ip == cleaned_ip)
            .order_by(desc(PredictionRecord.timestamp))
            .limit(MAX_HUNT_ITEMS)
            .all()
        )

        # 2. Fetch Alerts
        alert_rows = (
            db.query(AlertRecord)
            .filter(AlertRecord.source_ip == cleaned_ip)
            .order_by(desc(AlertRecord.timestamp))
            .limit(MAX_HUNT_ITEMS)
            .all()
        )

        # 3. Fetch Incidents
        inc_rows = (
            db.query(IncidentRecord)
            .filter(IncidentRecord.source_ip == cleaned_ip)
            .order_by(desc(IncidentRecord.created_at))
            .limit(MAX_HUNT_ITEMS)
            .all()
        )

        total_obs = len(pred_rows) + len(alert_rows) + len(inc_rows)

        # First Seen / Last Seen
        all_timestamps: List[datetime] = []
        for p in pred_rows:
            if p.timestamp:
                all_timestamps.append(p.timestamp)
        for a in alert_rows:
            if a.timestamp:
                all_timestamps.append(a.timestamp)
        for i in inc_rows:
            if i.created_at:
                all_timestamps.append(i.created_at)

        first_seen = min(all_timestamps) if all_timestamps else None
        last_seen = max(all_timestamps) if all_timestamps else None

        # Threat Categories breakdown
        threat_counts: Dict[str, int] = {}
        for p in pred_rows:
            t = p.predicted_threat or "BENIGN"
            threat_counts[t] = threat_counts.get(t, 0) + 1
        for a in alert_rows:
            t = a.threat_label or "Anomaly"
            threat_counts[t] = threat_counts.get(t, 0) + 1

        threat_categories = [
            {"threat": t, "count": cnt}
            for t, cnt in sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)
        ]

        # Severity distribution
        severity_dist: Dict[str, int] = {}
        for a in alert_rows:
            sev = a.severity or "UNKNOWN"
            severity_dist[sev] = severity_dist.get(sev, 0) + 1
        for p in pred_rows:
            risk = p.risk_level or "LOW"
            severity_dist[risk] = severity_dist.get(risk, 0) + 1

        # Observed destinations and ports
        dest_map: Dict[Tuple[str, int], int] = {}
        ports_set = set()
        proto_set = set()

        for p in pred_rows:
            d_ip = p.destination_ip or "Unknown"
            d_port = p.destination_port or 0
            dest_map[(d_ip, d_port)] = dest_map.get((d_ip, d_port), 0) + 1
            if p.destination_port:
                ports_set.add(p.destination_port)
            if p.protocol:
                proto_set.add(str(p.protocol))

        observed_destinations = [
            {"destination_ip": k[0], "destination_port": k[1], "count": cnt}
            for k, cnt in sorted(dest_map.items(), key=lambda x: x[1], reverse=True)[:15]
        ]

        # Serialization to items
        hunt_preds = [
            HuntPredictionItem(
                id=p.id,
                timestamp=p.timestamp,
                source_ip=p.source_ip,
                destination_ip=p.destination_ip,
                source_port=p.source_port,
                destination_port=p.destination_port,
                protocol=p.protocol,
                predicted_threat=p.predicted_threat or "BENIGN",
                risk_level=p.risk_level or "LOW",
                anomaly_score=round(float(p.anomaly_score or 0.0), 4),
                classification_confidence=round(float(p.classification_confidence or 0.0), 4),
                intrusion_flag=bool(p.intrusion_flag),
            )
            for p in pred_rows
        ]

        hunt_alerts = [
            HuntAlertItem(
                id=a.id,
                timestamp=a.timestamp,
                prediction_id=a.prediction_id,
                severity=a.severity,
                status=a.status,
                alert_type=a.alert_type or "SECURITY_ALERT",
                threat_label=a.threat_label or "Anomaly",
                confidence=round(float(a.confidence or 0.0), 4),
                source_ip=a.source_ip,
                destination_ip=a.destination_ip,
            )
            for a in alert_rows
        ]

        hunt_incidents = [
            HuntIncidentItem(
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
            )
            for i in inc_rows
        ]

        # Unified Timeline Assembly
        timeline_events: List[HuntTimelineEvent] = []

        for p in pred_rows:
            timeline_events.append(
                HuntTimelineEvent(
                    timestamp=p.timestamp,
                    event_type="PREDICTION",
                    severity=p.risk_level,
                    source=p.source_ip,
                    destination=f"{p.destination_ip}:{p.destination_port}" if p.destination_port else p.destination_ip,
                    resource_type="PREDICTION",
                    resource_id=str(p.id),
                    description=f"Flow evaluated as {p.predicted_threat} ({p.risk_level} risk, score {p.anomaly_score:.2f}).",
                )
            )

        for a in alert_rows:
            timeline_events.append(
                HuntTimelineEvent(
                    timestamp=a.timestamp,
                    event_type="ALERT",
                    severity=a.severity,
                    source=a.source_ip,
                    destination=a.destination_ip,
                    resource_type="ALERT",
                    resource_id=str(a.id),
                    description=f"Security alert #{a.id} ({a.severity}) triggered: {a.threat_label}.",
                )
            )

        for inc in inc_rows:
            timeline_events.append(
                HuntTimelineEvent(
                    timestamp=inc.created_at,
                    event_type="INCIDENT",
                    severity=inc.severity,
                    source=inc.source_ip,
                    destination=None,
                    resource_type="INCIDENT",
                    resource_id=str(inc.id),
                    description=f"SOC Incident {inc.incident_key} opened: '{inc.title}'.",
                )
            )

        timeline_events.sort(key=lambda e: e.timestamp, reverse=True)

        correlations = cls.synthesize_correlations(hunt_preds, hunt_alerts, hunt_incidents)

        return SourceInvestigationResponse(
            ip_address=cleaned_ip,
            first_seen=first_seen,
            last_seen=last_seen,
            total_observations=total_obs,
            threat_categories=threat_categories,
            severity_distribution=severity_dist,
            observed_destinations=observed_destinations,
            destination_ports=sorted(list(ports_set)),
            protocols=sorted(list(proto_set)),
            predictions=hunt_preds,
            alerts=hunt_alerts,
            incidents=hunt_incidents,
            timeline=timeline_events,
            correlations=correlations,
        )

    # -------------------------------------------------------------------------
    # Investigation Summary
    # -------------------------------------------------------------------------

    @classmethod
    def get_hunting_summary(cls, db: Session) -> ThreatHuntingSummaryResponse:
        """Retrieve aggregated metrics for the threat hunting workbench header."""
        total_flows = db.query(PredictionRecord).count()
        total_threats = (
            db.query(PredictionRecord)
            .filter(
                or_(
                    PredictionRecord.intrusion_flag == True,
                    PredictionRecord.anomaly_score < 0,
                    PredictionRecord.predicted_threat != "BENIGN",
                )
            )
            .count()
        )
        total_active_alerts = (
            db.query(AlertRecord)
            .filter(AlertRecord.status.in_(["NEW", "ACKNOWLEDGED"]))
            .count()
        )
        total_open_incidents = (
            db.query(IncidentRecord)
            .filter(IncidentRecord.status != "RESOLVED")
            .count()
        )

        unique_sources = (
            db.query(func.count(func.distinct(PredictionRecord.source_ip)))
            .filter(PredictionRecord.source_ip.isnot(None))
            .scalar()
            or 0
        )

        threat_breakdown = (
            db.query(
                PredictionRecord.predicted_threat,
                func.count(PredictionRecord.id).label("cnt"),
            )
            .filter(PredictionRecord.predicted_threat != "BENIGN")
            .group_by(PredictionRecord.predicted_threat)
            .order_by(desc("cnt"))
            .limit(5)
            .all()
        )
        top_threats = [{"threat": t, "count": cnt} for t, cnt in threat_breakdown]

        source_breakdown = (
            db.query(
                PredictionRecord.source_ip,
                func.count(PredictionRecord.id).label("cnt"),
            )
            .filter(PredictionRecord.source_ip.isnot(None))
            .group_by(PredictionRecord.source_ip)
            .order_by(desc("cnt"))
            .limit(5)
            .all()
        )
        top_sources = [{"source_ip": ip, "count": cnt} for ip, cnt in source_breakdown]

        return ThreatHuntingSummaryResponse(
            total_flows_investigated=total_flows,
            total_threat_detections=total_threats,
            total_active_alerts=total_active_alerts,
            total_open_incidents=total_open_incidents,
            unique_source_ips=unique_sources,
            top_investigated_threats=top_threats,
            top_active_sources=top_sources,
        )

    # -------------------------------------------------------------------------
    # Query History Persistence
    # -------------------------------------------------------------------------

    @classmethod
    def record_query_history(
        cls,
        db: Session,
        username: str,
        filter_summary: str,
        filters: Dict[str, Any],
        result_count: int,
    ) -> None:
        """Persist lightweight query history entry for reloading previous hunt parameters."""
        try:
            record = HuntQueryHistoryRecord(
                username=username,
                filter_summary=filter_summary,
                filters_json=json.dumps(filters),
                result_count=result_count,
            )
            db.add(record)
            db.commit()

            # Bound history size per user
            count = (
                db.query(HuntQueryHistoryRecord)
                .filter(HuntQueryHistoryRecord.username == username)
                .count()
            )
            if count > MAX_HISTORY_ENTRIES:
                oldest = (
                    db.query(HuntQueryHistoryRecord)
                    .filter(HuntQueryHistoryRecord.username == username)
                    .order_by(HuntQueryHistoryRecord.timestamp.asc())
                    .limit(count - MAX_HISTORY_ENTRIES)
                    .all()
                )
                for old in oldest:
                    db.delete(old)
                db.commit()
        except Exception as err:
            logger.warning("Failed to record threat hunt query history: %s", err)
            db.rollback()

    @classmethod
    def get_query_history(cls, db: Session, username: str, limit: int = 20) -> List[HuntQueryHistoryItem]:
        """Fetch sanitized query history entries for the authenticated operator."""
        safe_limit = min(max(1, limit), MAX_HISTORY_ENTRIES)
        records = (
            db.query(HuntQueryHistoryRecord)
            .filter(HuntQueryHistoryRecord.username == username)
            .order_by(desc(HuntQueryHistoryRecord.timestamp))
            .limit(safe_limit)
            .all()
        )

        results = []
        for r in records:
            try:
                filters = json.loads(r.filters_json)
            except Exception:
                filters = {}
            results.append(
                HuntQueryHistoryItem(
                    id=r.id,
                    timestamp=r.timestamp,
                    username=r.username,
                    filter_summary=r.filter_summary,
                    filters=filters,
                    result_count=r.result_count,
                )
            )
        return results
