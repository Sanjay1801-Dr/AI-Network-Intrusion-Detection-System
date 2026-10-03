"""AI Threat Prediction and historical prediction audit endpoints."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict
from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.dependencies import require_authenticated_user, require_role
from backend.app.core.limiter import limiter
from backend.app.db.session import get_db
from backend.app.models.user import UserRecord
from backend.app.schemas.prediction import PredictionRequest, PredictionResponse
from backend.app.schemas.history import PredictionHistoryResponse
from backend.app.schemas.audit import AuditAction, AuditOutcome, AuditResourceType
from backend.app.services.audit_service import AuditService
from backend.app.services.prediction_service import PredictionService
from backend.app.services.persistence_service import PersistenceService
from backend.app.services.websocket_manager import websocket_manager
from backend.app.repositories.prediction_repository import PredictionRepository

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
        "an actionable security triage rating (LOW, MEDIUM, HIGH, CRITICAL).\n"
        "4. **Database Persistence**: Atomically records the flow telemetry and prediction audit log into the database, "
        "generating an associated security alert when risk is MEDIUM, HIGH, or CRITICAL.\n"
        "5. **Real-Time Notification**: Broadcasts WebSocket events to connected monitoring dashboards.\n\n"
        "**Architectural Guarantee**: Models are pre-loaded and frozen; no model retraining occurs during request execution."
    ),
    responses={
        200: {
            "description": "Successful dual-engine prediction and risk triage assessment.",
            "model": PredictionResponse,
        },
        401: {
            "description": "Unauthenticated: Missing or invalid Bearer access token.",
        },
        403: {
            "description": "Forbidden: Requires ANALYST or ADMIN role.",
        },
        422: {
            "description": "Validation error: Malformed request, empty payload, non-numeric values, or NaN/Infinity detected.",
        },
        429: {
            "description": "Rate limit exceeded: Too many prediction inference requests.",
        },
        503: {
            "description": "ML inference service unavailable or model artifacts not loaded.",
        },
        500: {
            "description": "Internal prediction computation or database persistence error.",
        },
    },
)
@limiter.limit(lambda: settings.RATE_LIMIT_PREDICT)
async def predict_network_flow(
    request: Request,
    payload: PredictionRequest,
    current_user: UserRecord = Depends(require_role("ADMIN", "ANALYST")),
    db: Session = Depends(get_db),
) -> PredictionResponse:
    """Analyze incoming flow telemetry, persist audit record, and return prediction results."""
    flow_data: Dict[str, Any] = payload.to_flow_dict()

    # 1. Run Machine Learning Inference (Never retrains)
    prediction_result = PredictionService.predict(flow_data)

    # 2. Persist Prediction and Alert Records (Atomic database transaction)
    from backend.app.core.errors import AppException
    try:
        pred_record, alert_record = PersistenceService.save_prediction_and_alert(
            db=db,
            flow_data=flow_data,
            prediction=prediction_result,
        )
    except AppException:
        raise
    except Exception as exc:
        logger.error("Database persistence failed: %s", exc, exc_info=True)
        raise AppException(
            message="Database persistence failed while recording prediction telemetry.",
            error_code="DATABASE_PERSISTENCE_ERROR",
            status_code=500,
        )

    # 3. Broadcast Real-Time WebSocket Events (Only after database commit succeeds)
    try:
        prediction_event = {
            "event_type": "prediction_created",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {
                "prediction_id": pred_record.id,
                "predicted_threat": pred_record.predicted_threat,
                "intrusion_flag": pred_record.intrusion_flag,
                "anomaly_score": float(pred_record.anomaly_score),
                "classification_confidence": float(pred_record.classification_confidence),
                "risk_level": pred_record.risk_level,
                "recommended_action": pred_record.recommended_action,
            },
        }
        await websocket_manager.broadcast(prediction_event)

        if alert_record is not None:
            alert_event = {
                "event_type": "alert_created",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": {
                    "alert_id": alert_record.id,
                    "prediction_id": alert_record.prediction_id,
                    "severity": alert_record.severity,
                    "threat_label": alert_record.threat_label,
                    "anomaly_score": float(alert_record.anomaly_score),
                    "confidence": float(alert_record.confidence),
                    "status": alert_record.status,
                    "alert_type": alert_record.alert_type,
                    "recommended_action": alert_record.recommended_action,
                },
            }
            await websocket_manager.broadcast(alert_event)
    except Exception as ws_exc:
        logger.warning("Non-fatal error broadcasting WebSocket telemetry: %s", ws_exc)

    # 4. Record Security Audit Log (Safe metadata only, no full flow payload)
    AuditService.log_event(
        db=db,
        action=AuditAction.PREDICTION_CREATED,
        resource_type=AuditResourceType.PREDICTION,
        outcome=AuditOutcome.SUCCESS,
        username=current_user.username,
        user_role=current_user.role,
        resource_id=str(pred_record.id),
        ip_address=request.client.host if request.client else None,
        request_method=request.method,
        request_path=request.url.path,
        status_code=200,
        details={
            "prediction_id": pred_record.id,
            "threat_category": pred_record.predicted_threat,
            "severity": pred_record.risk_level,
            "anomaly_score": round(float(pred_record.anomaly_score), 4),
            "intrusion_flag": pred_record.intrusion_flag,
        },
    )

    # 5. Build Lightweight Explainability (Rule-based prediction explanation)
    from backend.app.services.security_analytics_service import SecurityAnalyticsService
    risk_reasons = SecurityAnalyticsService.generate_prediction_explanation(pred_record)
    explanation = {
        "method": "Rule-based prediction explanation",
        "anomaly_detected": pred_record.anomaly_label != "Normal",
        "anomaly_score": float(pred_record.anomaly_score),
        "predicted_threat": pred_record.predicted_threat,
        "classifier_confidence": float(pred_record.classification_confidence),
        "severity": pred_record.risk_level,
        "risk_reasons": risk_reasons,
    }

    # 6. Return structured API response compatible with Phase 4
    return PredictionResponse(**prediction_result, explanation=explanation)


@router.get(
    "/predictions",
    response_model=PredictionHistoryResponse,
    status_code=status.HTTP_200_OK,
    summary="Query Prediction Audit History",
    description="Returns paginated historical network flow predictions ordered newest first for audit and model verification.",
    responses={
        200: {
            "description": "Paginated list of historical prediction records.",
            "model": PredictionHistoryResponse,
        },
        401: {
            "description": "Unauthenticated: Missing or invalid Bearer access token.",
        },
        422: {
            "description": "Validation error for invalid pagination limits or offsets.",
        },
        429: {
            "description": "Rate limit exceeded: Too many read requests.",
        },
    },
)
@limiter.limit(lambda: settings.RATE_LIMIT_READ)
def get_prediction_history(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100, description="Maximum number of records to return (1-100)"),
    offset: int = Query(default=0, ge=0, description="Number of records to skip (>=0)"),
    current_user: UserRecord = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
) -> PredictionHistoryResponse:
    """Query recent prediction telemetry audit records with deterministic ordering."""
    records, total_count = PredictionRepository.list(db=db, limit=limit, offset=offset)
    return PredictionHistoryResponse(
        total=total_count,
        limit=limit,
        offset=offset,
        items=records,
    )
