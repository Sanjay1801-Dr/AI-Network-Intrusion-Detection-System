"""System health check endpoint."""

from fastapi import APIRouter, status
from backend.app.schemas.health import HealthResponse
from backend.app.services.health_service import HealthService

router = APIRouter(tags=["Health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Backend Health Check",
    description="Returns backend service operational status, component readiness, and version metadata.",
)
def get_health() -> HealthResponse:
    """Return health status confirming the backend is running."""
    return HealthService.get_system_health()
