"""API V1 endpoints package."""

from backend.app.api.v1.endpoints.health import router as health_router
from backend.app.api.v1.endpoints.traffic import router as traffic_router
from backend.app.api.v1.endpoints.threats import router as threats_router
from backend.app.api.v1.endpoints.alerts import router as alerts_router
from backend.app.api.v1.endpoints.metrics import router as metrics_router
from backend.app.api.v1.endpoints.models import router as models_router
from backend.app.api.v1.endpoints.prediction import router as prediction_router
from backend.app.api.v1.endpoints.websocket import router as websocket_router
from backend.app.api.v1.endpoints.auth import router as auth_router
from backend.app.api.v1.endpoints.audit import router as audit_router
from backend.app.api.v1.endpoints.analytics import router as analytics_router
from backend.app.api.v1.endpoints.threat_intelligence import router as threat_intel_router
from backend.app.api.v1.endpoints.incidents import router as incidents_router
from backend.app.api.v1.endpoints.reports import router as reports_router
from backend.app.api.v1.endpoints.hunting import router as hunting_router

__all__ = [
    "auth_router",
    "audit_router",
    "analytics_router",
    "threat_intel_router",
    "incidents_router",
    "reports_router",
    "hunting_router",
    "health_router",
    "traffic_router",
    "threats_router",
    "alerts_router",
    "metrics_router",
    "models_router",
    "prediction_router",
    "websocket_router",
]

