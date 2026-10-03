"""Detected threat events endpoints (Planned for Phase 3)."""

from typing import Dict, Any
from fastapi import APIRouter, status

router = APIRouter(prefix="/threats", tags=["Threats"])


@router.get(
    "",
    status_code=status.HTTP_200_OK,
    summary="List Detected Threats (Phase 3)",
    description="Returns classified threat events filtered by severity, threat family, or IP.",
)
def list_threats() -> Dict[str, Any]:
    """Placeholder endpoint documented for Phase 3 implementation."""
    return {
        "status": "planned",
        "phase": 3,
        "message": "Threat querying will be implemented in Phase 3.",
        "data": [],
    }
