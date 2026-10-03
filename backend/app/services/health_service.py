"""Service layer handling system health evaluation and component readiness checks."""

from datetime import datetime, timezone
import os
from backend.app.core.config import settings
from backend.app.db.session import check_db_connection
from backend.app.schemas.health import HealthResponse, ComponentHealth


class HealthService:
    """Service to evaluate backend runtime health and component status."""

    @staticmethod
    def get_system_health() -> HealthResponse:
        """Evaluate database connectivity, model directory readiness, and overall API health."""
        # 1. Check Database connectivity
        db_alive = check_db_connection()
        db_status = "connected" if db_alive else "degraded"

        # 2. Check ML subsystem readiness
        # In Phase 1, model directory presence indicates readiness for model loading
        models_dir_exists = os.path.exists(settings.MODEL_DIRECTORY)
        ml_status = "ready" if models_dir_exists else "not_loaded"

        # 3. Overall status calculation
        overall_status = "healthy" if db_alive else "degraded"

        return HealthResponse(
            status=overall_status,
            service=settings.APP_NAME,
            version=settings.APP_VERSION,
            environment=settings.ENVIRONMENT,
            timestamp=datetime.now(timezone.utc),
            components=ComponentHealth(
                database=db_status,
                ml_engine=ml_status,
                api="online",
            ),
        )
