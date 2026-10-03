"""Security alerts endpoints (Planned for Phase 3)."""

from typing import Dict, Any
from fastapi import APIRouter, status

router = APIRouter(prefix="/alerts", tags=["Security Alerts"])


@router.get(
    "",
    status_code=status.HTTP_200_OK,
    summary="List Active Security Alerts (Phase 3)",
    description="Returns security alerts queued for SOC analyst triage.",
)
def list_alerts() -> Dict[str, Any]:
    """Placeholder endpoint documented for Phase 3 implementation."""
    return {
        "status": "planned",
        "phase": 3,
        "message": "Alerts management will be implemented in Phase 3.",
        "data": [],
    }
