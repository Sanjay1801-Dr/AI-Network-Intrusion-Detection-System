"""Persistence service coordinating database storage for prediction audits and security alerts."""

import json
import logging
from typing import Any, Dict, Optional, Tuple
from sqlalchemy.orm import Session
from backend.app.core.errors import AppException
from backend.app.models.prediction import PredictionRecord
from backend.app.models.alert import AlertRecord

logger = logging.getLogger("nids.services.persistence")


class PersistenceService:
    """Coordinates atomic database operations for network flow predictions and security alerts.

    Guarantees:
    - Atomicity: Prediction and linked alert (if applicable) are committed within a single transaction.
    - Transaction Rollback: Database errors trigger immediate rollback and raise sanitized AppExceptions.
    - Alert Rules:
      * CRITICAL -> AlertRecord(severity="CRITICAL", alert_type="CRITICAL_INTRUSION")
      * HIGH     -> AlertRecord(severity="HIGH", alert_type="NETWORK_INTRUSION")
      * MEDIUM   -> AlertRecord(severity="MEDIUM", alert_type="ANOMALY_MONITORING")
      * LOW      -> No alert record created (audit prediction history only)
    """

    @classmethod
    def _extract_telemetry_field(cls, data: Dict[str, Any], *candidate_keys: str) -> Optional[Any]:
        """Extract a value from data trying candidate keys (case-insensitive and aliases)."""
        for key in candidate_keys:
            if key in data and data[key] is not None:
                return data[key]
            # Try lowercased / normalized key
            key_lower = key.lower().replace(" ", "_")
            for d_k, d_v in data.items():
                if d_k.lower().replace(" ", "_") == key_lower and d_v is not None:
                    return d_v
        return None

    @staticmethod
    def _to_int(val: Optional[Any]) -> Optional[int]:
        if val is None:
            return None
        try:
            return int(float(val))
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _to_float(val: Optional[Any]) -> Optional[float]:
        if val is None:
            return None
        try:
            return float(val)
        except (ValueError, TypeError):
            return None

    @classmethod
    def save_prediction_and_alert(
        cls,
        db: Session,
        flow_data: Dict[str, Any],
        prediction: Dict[str, Any],
    ) -> Tuple[PredictionRecord, Optional[AlertRecord]]:
        """Atomically persist prediction history and associated security alert to the database."""
        # 1. Extract Network Telemetry (client-supplied, optional)
        src_ip = cls._extract_telemetry_field(flow_data, "source_ip", "Source IP", "src_ip")
        dst_ip = cls._extract_telemetry_field(flow_data, "destination_ip", "Destination IP", "dst_ip")
        src_port = cls._extract_telemetry_field(flow_data, "source_port", "Source Port", "src_port")
        dst_port = cls._extract_telemetry_field(flow_data, "destination_port", "Destination Port", "dst_port")
        proto = cls._extract_telemetry_field(flow_data, "protocol", "Protocol")
        duration = cls._extract_telemetry_field(flow_data, "flow_duration", "Flow Duration", "duration")
        fwd_pkts = cls._extract_telemetry_field(flow_data, "total_fwd_packets", "Total Fwd Packets", "total_forward_packets")
        bwd_pkts = cls._extract_telemetry_field(flow_data, "total_backward_packets", "Total Backward Packets", "total_bwd_packets")

        # Total Bytes Calculation
        fwd_bytes = cls._extract_telemetry_field(flow_data, "total_length_of_fwd_packets", "Total Length of Fwd Packets")
        bwd_bytes = cls._extract_telemetry_field(flow_data, "total_length_of_bwd_packets", "Total Length of Bwd Packets")
        direct_bytes = cls._extract_telemetry_field(flow_data, "total_bytes", "Total Bytes")

        calc_bytes: Optional[int] = None
        if direct_bytes is not None:
            calc_bytes = cls._to_int(direct_bytes)
        elif fwd_bytes is not None or bwd_bytes is not None:
            calc_bytes = (cls._to_int(fwd_bytes) or 0) + (cls._to_int(bwd_bytes) or 0)

        # 2. Extract ML Inference Results
        anomaly = prediction.get("anomaly", {})
        classification = prediction.get("classification", {})
        risk = prediction.get("risk_assessment", {})
        risk_level = str(risk.get("risk_level", "LOW")).upper()

        # Compact JSON representation for debugging / audit
        try:
            compact_json = json.dumps(
                {str(k): v for k, v in list(flow_data.items())[:25] if isinstance(v, (int, float, str, bool))},
                separators=(",", ":"),
            )
        except Exception:
            compact_json = None

        # 3. Build PredictionRecord Entity
        pred_record = PredictionRecord(
            source_ip=str(src_ip) if src_ip is not None else None,
            destination_ip=str(dst_ip) if dst_ip is not None else None,
            source_port=cls._to_int(src_port),
            destination_port=cls._to_int(dst_port),
            protocol=str(proto) if proto is not None else None,
            flow_duration=cls._to_float(duration),
            total_forward_packets=cls._to_int(fwd_pkts),
            total_backward_packets=cls._to_int(bwd_pkts),
            total_bytes=calc_bytes,
            anomaly_label=str(anomaly.get("anomaly_label", "NORMAL")),
            anomaly_score=float(anomaly.get("anomaly_score", 0.0)),
            raw_decision_score=float(anomaly.get("raw_decision_score", 0.0)),
            predicted_threat=str(classification.get("predicted_label", "BENIGN")),
            intrusion_flag=bool(classification.get("is_intrusion", False)),
            classification_confidence=float(classification.get("confidence", 0.0)),
            risk_level=risk_level,
            recommended_action=str(risk.get("recommended_action", "Standard Flow Logging")),
            model_version="1.0.0-phase3",
            raw_flow_data=compact_json,
        )

        # 4. Determine Security Alert Creation Rules
        alert_record: Optional[AlertRecord] = None
        if risk_level == "CRITICAL":
            alert_record = AlertRecord(
                alert_type="CRITICAL_INTRUSION",
                severity="CRITICAL",
                threat_label=pred_record.predicted_threat,
                anomaly_score=pred_record.anomaly_score,
                confidence=pred_record.classification_confidence,
                source_ip=pred_record.source_ip,
                destination_ip=pred_record.destination_ip,
                status="NEW",
                recommended_action=pred_record.recommended_action,
            )
        elif risk_level == "HIGH":
            alert_record = AlertRecord(
                alert_type="NETWORK_INTRUSION",
                severity="HIGH",
                threat_label=pred_record.predicted_threat,
                anomaly_score=pred_record.anomaly_score,
                confidence=pred_record.classification_confidence,
                source_ip=pred_record.source_ip,
                destination_ip=pred_record.destination_ip,
                status="NEW",
                recommended_action=pred_record.recommended_action,
            )
        elif risk_level == "MEDIUM":
            alert_record = AlertRecord(
                alert_type="ANOMALY_MONITORING",
                severity="MEDIUM",
                threat_label=pred_record.predicted_threat,
                anomaly_score=pred_record.anomaly_score,
                confidence=pred_record.classification_confidence,
                source_ip=pred_record.source_ip,
                destination_ip=pred_record.destination_ip,
                status="NEW",
                recommended_action=pred_record.recommended_action,
            )
        # LOW risk creates no alert record

        # 5. Execute Atomic Database Transaction
        try:
            db.add(pred_record)
            db.flush()  # generates pred_record.id

            if alert_record is not None:
                alert_record.prediction_id = pred_record.id
                db.add(alert_record)

            db.commit()
            db.refresh(pred_record)
            if alert_record is not None:
                db.refresh(alert_record)

            logger.info(
                "Persisted prediction #%d (Threat='%s', Risk='%s'). Alert created: %s",
                pred_record.id,
                pred_record.predicted_threat,
                pred_record.risk_level,
                bool(alert_record is not None),
            )
            return pred_record, alert_record

        except Exception as exc:
            db.rollback()
            logger.error("Database persistence transaction failed: %s", exc, exc_info=True)
            raise AppException(
                message="Database persistence failed while recording prediction telemetry.",
                error_code="DATABASE_PERSISTENCE_ERROR",
                status_code=500,
            )
