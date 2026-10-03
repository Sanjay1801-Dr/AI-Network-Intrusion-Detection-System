"""Aggregated API router for Version 1."""

from fastapi import APIRouter
from backend.app.api.v1.endpoints import (
    auth_router,
    health_router,
    traffic_router,
    threats_router,
    alerts_router,
    metrics_router,
    models_router,
    prediction_router,
    websocket_router,
    audit_router,
    analytics_router,
    threat_intel_router,
    incidents_router,
    reports_router,
    hunting_router,
)

api_router = APIRouter()

# Register endpoints under V1
api_router.include_router(auth_router)
api_router.include_router(audit_router)
api_router.include_router(analytics_router)
api_router.include_router(threat_intel_router)
api_router.include_router(incidents_router)
api_router.include_router(reports_router)
api_router.include_router(hunting_router)
api_router.include_router(websocket_router)
api_router.include_router(prediction_router)
api_router.include_router(traffic_router)
api_router.include_router(threats_router)
api_router.include_router(alerts_router)
api_router.include_router(metrics_router)
api_router.include_router(models_router)
api_router.include_router(health_router)
