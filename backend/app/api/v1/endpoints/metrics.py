"""SOC dashboard telemetry and metrics endpoints (Planned for Phase 4)."""

from typing import Dict, Any
from fastapi import APIRouter, status

router = APIRouter(prefix="/metrics", tags=["Telemetry & Metrics"])


@router.get(
    "/overview",
    status_code=status.HTTP_200_OK,
    summary="Dashboard Overview Metrics (Phase 4)",
    description="Returns aggregate metrics: active threats, flow rate, severity breakdown.",
)
def get_metrics_overview() -> Dict[str, Any]:
    """Placeholder endpoint documented for Phase 4 implementation."""
    return {
        "status": "planned",
        "phase": 4,
        "message": "Telemetry metrics will be activated in Phase 4.",
    }
