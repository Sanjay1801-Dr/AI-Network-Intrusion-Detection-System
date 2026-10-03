"""Integration tests for the FastAPI health check endpoint."""

from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_api_health_endpoint():
    """Verify that GET /api/health returns 200 OK and valid health telemetry."""
    response = client.get("/api/health")

    assert response.status_code == 200
    data = response.json()

    # Validate top-level keys
    assert data["status"] in ("healthy", "degraded")
    assert "service" in data
    assert "version" in data
    assert "environment" in data
    assert "timestamp" in data
    assert "components" in data

    # Validate components
    components = data["components"]
    assert "database" in components
    assert "ml_engine" in components
    assert components["api"] == "online"


def test_api_v1_health_alias():
    """Verify that GET /api/v1/health is also accessible via versioned router."""
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ("healthy", "degraded")
