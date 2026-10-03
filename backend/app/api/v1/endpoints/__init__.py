"""API V1 endpoints package."""

from backend.app.api.v1.endpoints.health import router as health_router
from backend.app.api.v1.endpoints.traffic import router as traffic_router
from backend.app.api.v1.endpoints.threats import router as threats_router
from backend.app.api.v1.endpoints.alerts import router as alerts_router
from backend.app.api.v1.endpoints.metrics import router as metrics_router
from backend.app.api.v1.endpoints.models import router as models_router

__all__ = [
    "health_router",
    "traffic_router",
    "threats_router",
    "alerts_router",
    "metrics_router",
    "models_router",
]
