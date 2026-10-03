"""Comprehensive unit and integration tests for FastAPI AI Threat Prediction API (Phase 4)."""

import math
from fastapi.testclient import TestClient
import pytest
from backend.app.main import app
from backend.app.services.prediction_service import PredictionService

client = TestClient(app)

SAMPLE_BENIGN_FLOW = {
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


def test_health_reports_ml_engine_ready():
    """Verify that system health reports the ML engine as ready after startup."""
    # Ensure initialized
    PredictionService.initialize()

    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["components"]["ml_engine"] == "ready"
    assert data["status"] == "healthy"

    # Also test the versioned alias
    v1_response = client.get("/api/v1/health")
    assert v1_response.status_code == 200
    assert v1_response.json()["components"]["ml_engine"] == "ready"


def test_predict_endpoint_valid_payload():
    """Verify POST /api/v1/predict with a complete valid development network-flow payload."""
    response = client.post("/api/v1/predict", json=SAMPLE_BENIGN_FLOW)
    assert response.status_code == 200
    data = response.json()

    # 1. Verify Anomaly section
    assert "anomaly" in data
    anomaly = data["anomaly"]
    assert isinstance(anomaly["is_anomaly"], bool)
    assert anomaly["anomaly_label"] in ("NORMAL", "ANOMALOUS")
    assert 0.0 <= anomaly["anomaly_score"] <= 1.0
    assert isinstance(anomaly["raw_decision_score"], float)
    assert "Outlier divergence score" in anomaly["interpretation"]

    # 2. Verify Classification section
    assert "classification" in data
    classification = data["classification"]
    assert isinstance(classification["predicted_label"], str)
    assert isinstance(classification["is_intrusion"], bool)
    assert 0.0 <= classification["confidence"] <= 1.0
    assert classification["confidence_type"] == "estimated_class_probability"
    assert isinstance(classification["class_probabilities"], dict)
    assert len(classification["class_probabilities"]) > 0

    # 3. Verify Risk Assessment section
    assert "risk_assessment" in data
    risk = data["risk_assessment"]
    assert risk["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert isinstance(risk["recommended_action"], str)
    assert len(risk["recommended_action"]) > 0
    assert "Flow evaluated:" in risk["summary"]


def test_predict_endpoint_sparse_and_snake_case_payload():
    """Verify POST /api/v1/predict accepts sparse network telemetry in snake_case."""
    sparse_payload = {
        "destination_port": 80,
        "flow_duration": 184500,
        "total_fwd_packets": 8,
        "total_backward_packets": 10,
    }
    response = client.post("/api/v1/predict", json=sparse_payload)
    assert response.status_code == 200
    data = response.json()

    assert "anomaly" in data
    assert "classification" in data
    assert "risk_assessment" in data
    assert data["anomaly"]["anomaly_label"] in ("NORMAL", "ANOMALOUS")


def test_predict_rejects_empty_payload():
    """Verify that an empty dictionary payload is rejected with HTTP 422."""
    response = client.post("/api/v1/predict", json={})
    assert response.status_code == 422
    data = response.json()
    assert data["status"] == "error"
    assert data["error_code"] == "UNPROCESSABLE_ENTITY"


def test_predict_rejects_nan_and_infinity_numbers():
    """Verify that numeric NaN and Infinity values are safely rejected with HTTP 422."""
    # Test NaN float
    # Test NaN float in raw JSON payload
    nan_content = '{"Destination Port": NaN, "Flow Duration": 1000}'
    response = client.post(
        "/api/v1/predict",
        content=nan_content,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422

    # Test Inf float in raw JSON payload
    inf_content = '{"Destination Port": 80, "Flow Duration": Infinity}'
    response = client.post(
        "/api/v1/predict",
        content=inf_content,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422


def test_predict_rejects_string_nan_and_infinity():
    """Verify that string representations of NaN and Infinity are rejected with HTTP 422."""
    nan_str_payload = {"Destination Port": "NaN", "Flow Duration": 5000}
    response = client.post("/api/v1/predict", json=nan_str_payload)
    assert response.status_code == 422

    inf_str_payload = {"Destination Port": 80, "Flow Duration": "Infinity"}
    response = client.post("/api/v1/predict", json=inf_str_payload)
    assert response.status_code == 422


def test_predict_rejects_invalid_numeric_values():
    """Verify that non-numeric types and malformed values are rejected with HTTP 422."""
    invalid_payload = {"Destination Port": "not_a_valid_port", "Flow Duration": 5000}
    response = client.post("/api/v1/predict", json=invalid_payload)
    assert response.status_code == 422


def test_predict_rejects_malformed_keys_and_code():
    """Verify that malicious keys and executable expressions are rejected with HTTP 422."""
    malicious_key_payload = {"<script>alert('xss')</script>": 443}
    response = client.post("/api/v1/predict", json=malicious_key_payload)
    assert response.status_code == 422

    dunder_key_payload = {"__import__": 1}
    response = client.post("/api/v1/predict", json=dunder_key_payload)
    assert response.status_code == 422


def test_predict_model_loading_failure_returns_503(monkeypatch):
    """Verify that if models are unavailable, the API returns controlled HTTP 503 without leaking paths."""
    # Simulate unavailable models
    monkeypatch.setattr(PredictionService, "is_ready", lambda: False)
    monkeypatch.setattr(PredictionService, "initialize", lambda: False)
    monkeypatch.setattr(PredictionService, "_status", "unavailable")

    response = client.post("/api/v1/predict", json=SAMPLE_BENIGN_FLOW)
    assert response.status_code == 503
    data = response.json()

    assert data["status"] == "error"
    assert data["error_code"] == "ML_INFERENCE_ERROR"
    assert "currently unavailable" in data["message"]

    # Verify no local filesystem paths or stack traces leaked
    assert "c:\\" not in str(data).lower()
    assert "traceback" not in str(data).lower()


def test_predict_internal_error_returns_500_without_stack_trace(monkeypatch):
    """Verify that unexpected internal prediction failures return HTTP 500 without stack traces."""
    def mock_fail(*args, **kwargs):
        raise RuntimeError("Simulated low-level math library crash in matrix multiplication")

    PredictionService.initialize()
    assert PredictionService._predictor is not None
    monkeypatch.setattr(PredictionService._predictor, "predict", mock_fail)

    response = client.post("/api/v1/predict", json=SAMPLE_BENIGN_FLOW)
    assert response.status_code == 500
    data = response.json()

    assert data["status"] == "error"
    assert data["error_code"] in ("INTERNAL_PREDICTION_ERROR", "UNHANDLED_EXCEPTION")
    assert "unexpected internal error" in data["message"]

    # Ensure no technical internal traceback or crash message leaked to client
    assert "Simulated low-level math library crash" not in data["message"]
    assert "Traceback" not in str(data)
    assert "File " not in str(data)


def test_models_are_not_retrained_per_request():
    """Verify that multiple predictions reuse the identical frozen estimator instance and never retrain."""
    PredictionService.initialize()
    predictor = PredictionService._predictor
    assert predictor is not None

    # Track object identities of trained estimators
    preprocessor_id = id(predictor.preprocessor)
    anomaly_estimator_id = id(predictor.anomaly_trainer.model)
    classifier_estimator_id = id(predictor.classifier_trainer.model)

    # Perform multiple predictions
    res1 = client.post("/api/v1/predict", json=SAMPLE_BENIGN_FLOW)
    res2 = client.post("/api/v1/predict", json=SAMPLE_BENIGN_FLOW)

    assert res1.status_code == 200
    assert res2.status_code == 200

    # Ensure estimator instances in memory did not change (no retraining/reinstantiation)
    assert id(PredictionService._predictor.preprocessor) == preprocessor_id
    assert id(PredictionService._predictor.anomaly_trainer.model) == anomaly_estimator_id
    assert id(PredictionService._predictor.classifier_trainer.model) == classifier_estimator_id


def test_openapi_documentation_contains_predict_route():
    """Verify that GET /openapi.json properly documents POST /api/v1/predict."""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()

    paths = schema.get("paths", {})
    assert "/api/v1/predict" in paths
    predict_endpoint = paths["/api/v1/predict"]
    assert "post" in predict_endpoint

    post_meta = predict_endpoint["post"]
    assert "summary" in post_meta
    assert "description" in post_meta
    assert "responses" in post_meta

    responses = post_meta["responses"]
    assert "200" in responses
    assert "422" in responses
    assert "503" in responses
    assert "500" in responses
