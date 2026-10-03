"""Pydantic schemas for network traffic prediction API requests, responses, and validation."""

import math
import re
from typing import Any, Dict, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, model_validator


class PredictionRequest(BaseModel):
    """Network flow telemetry request payload for AI anomaly detection and threat classification.

    Accepts standard CIC-IDS2017 flow metrics using either title-case headers or snake_case names.
    Supports additional dynamic network telemetry attributes while enforcing defensive validation:
    - Rejects empty payloads.
    - Rejects NaN, Infinity, and -Infinity values.
    - Rejects non-numeric values for numeric features.
    - Rejects suspicious executable code or non-scalar structures.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        extra="allow",
        json_schema_extra={
            "example": {
                "Destination Port": 443,
                "Flow Duration": 245012,
                "Total Fwd Packets": 14,
                "Total Backward Packets": 18,
                "Total Length of Fwd Packets": 1240,
                "Total Length of Bwd Packets": 18450,
                "Fwd Packet Length Max": 480,
                "Fwd Packet Length Min": 0,
                "Fwd Packet Length Mean": 88.57,
                "Bwd Packet Length Mean": 1025.0,
                "Flow Bytes/s": 80363.41,
                "Flow Packets/s": 130.60,
                "Flow IAT Mean": 7903.61,
                "Flow IAT Std": 12450.2,
                "Flow IAT Max": 45210,
                "Flow IAT Min": 12,
                "Fwd Header Length": 456,
                "Bwd Header Length": 584,
                "Fwd Packets/s": 57.14,
                "Bwd Packets/s": 73.46,
                "Min Packet Length": 0,
                "Max Packet Length": 1460,
                "Packet Length Mean": 615.31,
                "Packet Length Std": 520.14,
                "FIN Flag Count": 1,
                "SYN Flag Count": 1,
                "RST Flag Count": 0,
                "PSH Flag Count": 8,
                "ACK Flag Count": 31,
                "Down/Up Ratio": 1,
                "Average Packet Size": 634.5,
                "Protocol": 6,
            }
        },
    )

    # Standard Network Flow Features (All optional to allow flexible flow telemetry)
    destination_port: Optional[float] = Field(None, alias="Destination Port", description="Target TCP/UDP service port")
    flow_duration: Optional[float] = Field(None, alias="Flow Duration", description="Total flow duration in microseconds")
    total_fwd_packets: Optional[float] = Field(None, alias="Total Fwd Packets", description="Total packets transmitted in forward direction")
    total_backward_packets: Optional[float] = Field(None, alias="Total Backward Packets", description="Total packets transmitted in backward direction")
    total_length_of_fwd_packets: Optional[float] = Field(None, alias="Total Length of Fwd Packets", description="Total bytes sent in forward direction")
    total_length_of_bwd_packets: Optional[float] = Field(None, alias="Total Length of Bwd Packets", description="Total bytes sent in backward direction")
    fwd_packet_length_max: Optional[float] = Field(None, alias="Fwd Packet Length Max", description="Maximum packet size in forward direction")
    fwd_packet_length_min: Optional[float] = Field(None, alias="Fwd Packet Length Min", description="Minimum packet size in forward direction")
    fwd_packet_length_mean: Optional[float] = Field(None, alias="Fwd Packet Length Mean", description="Mean packet size in forward direction")
    bwd_packet_length_mean: Optional[float] = Field(None, alias="Bwd Packet Length Mean", description="Mean packet size in backward direction")
    flow_bytes_per_s: Optional[float] = Field(None, alias="Flow Bytes/s", description="Flow throughput in bytes per second")
    flow_packets_per_s: Optional[float] = Field(None, alias="Flow Packets/s", description="Flow throughput in packets per second")
    flow_iat_mean: Optional[float] = Field(None, alias="Flow IAT Mean", description="Mean inter-arrival time between packets")
    flow_iat_std: Optional[float] = Field(None, alias="Flow IAT Std", description="Standard deviation of packet inter-arrival times")
    flow_iat_max: Optional[float] = Field(None, alias="Flow IAT Max", description="Maximum inter-arrival time")
    flow_iat_min: Optional[float] = Field(None, alias="Flow IAT Min", description="Minimum inter-arrival time")
    fwd_header_length: Optional[float] = Field(None, alias="Fwd Header Length", description="Total bytes consumed by forward IP/transport headers")
    bwd_header_length: Optional[float] = Field(None, alias="Bwd Header Length", description="Total bytes consumed by backward IP/transport headers")
    fwd_packets_per_s: Optional[float] = Field(None, alias="Fwd Packets/s", description="Forward packet transmission rate")
    bwd_packets_per_s: Optional[float] = Field(None, alias="Bwd Packets/s", description="Backward packet transmission rate")
    min_packet_length: Optional[float] = Field(None, alias="Min Packet Length", description="Minimum observed packet size")
    max_packet_length: Optional[float] = Field(None, alias="Max Packet Length", description="Maximum observed packet size")
    packet_length_mean: Optional[float] = Field(None, alias="Packet Length Mean", description="Overall mean packet size")
    packet_length_std: Optional[float] = Field(None, alias="Packet Length Std", description="Overall packet size standard deviation")
    fin_flag_count: Optional[float] = Field(None, alias="FIN Flag Count", description="Number of packets with FIN flag set")
    syn_flag_count: Optional[float] = Field(None, alias="SYN Flag Count", description="Number of packets with SYN flag set")
    rst_flag_count: Optional[float] = Field(None, alias="RST Flag Count", description="Number of packets with RST flag set")
    psh_flag_count: Optional[float] = Field(None, alias="PSH Flag Count", description="Number of packets with PSH flag set")
    ack_flag_count: Optional[float] = Field(None, alias="ACK Flag Count", description="Number of packets with ACK flag set")
    urg_flag_count: Optional[float] = Field(None, alias="URG Flag Count", description="Number of packets with URG flag set")
    down_per_up_ratio: Optional[float] = Field(None, alias="Down/Up Ratio", description="Ratio of incoming to outgoing packets")
    average_packet_size: Optional[float] = Field(None, alias="Average Packet Size", description="Average observed packet size")
    protocol: Optional[float] = Field(None, alias="Protocol", description="Transport layer protocol code (e.g. 6=TCP, 17=UDP)")

    @model_validator(mode="before")
    @classmethod
    def validate_flow_payload(cls, data: Any) -> Any:
        """Enforce strict defensive validation on the incoming network flow payload."""
        if not isinstance(data, dict):
            raise ValueError("Request body must be a valid JSON object.")

        if not data:
            raise ValueError(
                "Network flow payload cannot be empty. Please provide network flow telemetry attributes."
            )

        # Inspect all provided key-value pairs
        non_empty_count = 0
        for key, val in data.items():
            if not isinstance(key, str):
                raise ValueError("All payload keys must be strings.")

            # Reject malicious or invalid key strings
            if re.search(r"[<>{}\$\[\];\'\"`]", key) or key.startswith("__"):
                raise ValueError(f"Invalid characters detected in field name: '{key}'.")

            if val is None:
                continue

            # Check for NaN / Infinity in numeric values or strings
            if isinstance(val, (int, float)):
                if math.isnan(val) or math.isinf(val):
                    raise ValueError(f"Invalid numeric value for field '{key}': NaN and Infinity are strictly forbidden.")
                non_empty_count += 1
            elif isinstance(val, str):
                # Reject string representations of NaN and Infinity
                val_lower = val.strip().lower()
                if val_lower in ("nan", "inf", "-inf", "+inf", "infinity", "-infinity"):
                    raise ValueError(f"Invalid numeric value for field '{key}': NaN and Infinity are strictly forbidden.")
                # Allow safe strings (e.g. 'registered', 'well_known', 'dynamic' for port_category)
                if not re.match(r"^[a-zA-Z0-9_\-\.\s]+$", val):
                    raise ValueError(f"Disallowed string format in field '{key}'. Only alphanumeric characters are permitted.")
                non_empty_count += 1
            elif isinstance(val, bool):
                non_empty_count += 1
            else:
                raise ValueError(f"Unsupported data type for field '{key}': {type(val).__name__}. Nested structures are not permitted.")

        if non_empty_count == 0:
            raise ValueError("Payload contains no valid non-null flow attributes.")

        return data

    def to_flow_dict(self) -> Dict[str, Any]:
        """Convert validated request into a clean dictionary suitable for NetworkPredictor."""
        result: Dict[str, Any] = {}
        for field_name, val in self.__dict__.items():
            if field_name == "__pydantic_extra__":
                continue
            if val is not None:
                field_info = self.model_fields.get(field_name)
                key_to_use = field_info.alias if field_info and field_info.alias else field_name
                result[key_to_use] = val

        if hasattr(self, "__pydantic_extra__") and self.__pydantic_extra__:
            for extra_key, extra_val in self.__pydantic_extra__.items():
                if extra_val is not None:
                    result[extra_key] = extra_val

        return result


class AnomalyResult(BaseModel):
    """Unsupervised anomaly detection result produced by Isolation Forest."""

    is_anomaly: bool = Field(..., description="Binary outlier indicator from unsupervised Isolation Forest")
    anomaly_label: str = Field(..., description="Categorical anomaly label: 'NORMAL' or 'ANOMALOUS'")
    anomaly_score: float = Field(..., description="Normalized outlier divergence score [0.0, 1.0]. Higher values indicate higher divergence.")
    raw_decision_score: float = Field(..., description="Raw Isolation Forest decision function score (negative for outliers, positive for inliers)")
    interpretation: str = Field(..., description="Security interpretation explaining the anomaly score")


class ClassificationResult(BaseModel):
    """Supervised threat classification result produced by Random Forest."""

    predicted_label: str = Field(..., description="Predicted network traffic category (e.g. BENIGN, DoS, Port Scan, Bot, Web Attack)")
    is_intrusion: bool = Field(..., description="True if the predicted category represents a malicious intrusion pattern (non-BENIGN)")
    confidence: float = Field(..., description="Classifier estimated class probability [0.0, 1.0]")
    confidence_type: str = Field("estimated_class_probability", description="Explicit identifier of the confidence metric type ('estimated_class_probability')")
    class_probabilities: Dict[str, float] = Field(..., description="Posterior probability distribution across all trained attack categories")


class RiskAssessment(BaseModel):
    """Dual-engine composite risk evaluation and operational triage recommendation."""

    risk_level: str = Field(..., description="Triage risk rating: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'")
    recommended_action: str = Field(..., description="Actionable response recommendation for SOC analysts")
    summary: str = Field(..., description="Synthesized diagnostic summary combining anomaly and classification findings")


class PredictionResponse(BaseModel):
    """Unified AI threat prediction response combining anomaly detection and threat classification."""

    anomaly: AnomalyResult = Field(..., description="Unsupervised flow anomaly detection evaluation")
    classification: ClassificationResult = Field(..., description="Supervised multi-class attack pattern classification")
    risk_assessment: RiskAssessment = Field(..., description="Dual-engine composite security risk evaluation and triage recommendation")
