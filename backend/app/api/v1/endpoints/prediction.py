"""AI Threat Prediction API endpoint integrating Phase 3 detection engines."""

import logging
from typing import Any, Dict
from fastapi import APIRouter, status
from backend.app.schemas.prediction import PredictionRequest, PredictionResponse
from backend.app.services.prediction_service import PredictionService

logger = logging.getLogger("nids.api.prediction")

router = APIRouter(tags=["AI Threat Prediction"])


@router.post(
    "/predict",
    response_model=PredictionResponse,
    status_code=status.HTTP_200_OK,
    summary="Predict Network Flow Anomaly and Threat Classification",
    description=(
        "Analyzes network flow telemetry through the dual-stage AI detection pipeline:\n\n"
        "1. **Unsupervised Anomaly Detection**: Isolation Forest calculates outlier divergence score.\n"
        "2. **Supervised Threat Classification**: Random Forest predicts attack category (e.g. DoS, Port Scan, Bot, Web Attack).\n"
        "3. **Composite Risk Assessment**: Combines statistical anomaly divergence and supervised confidence to assign "
        "an actionable security triage rating (LOW, MEDIUM, HIGH, CRITICAL).\n\n"
        "**Architectural Guarantee**: Models are pre-loaded and frozen; no model retraining occurs during request execution."
    ),
    responses={
        200: {
            "description": "Successful dual-engine prediction and risk triage assessment.",
            "model": PredictionResponse,
        },
        422: {
            "description": "Validation error: Malformed request, empty payload, non-numeric values, or NaN/Infinity detected.",
        },
        503: {
            "description": "ML inference service unavailable or model artifacts not loaded.",
        },
        500: {
            "description": "Internal prediction computation error.",
        },
    },
)
def predict_network_flow(request: PredictionRequest) -> PredictionResponse:
    """Analyze incoming flow telemetry and return anomaly detection, threat classification, and risk level."""
    flow_data: Dict[str, Any] = request.to_flow_dict()
    prediction_result = PredictionService.predict(flow_data)
    return PredictionResponse(**prediction_result)
