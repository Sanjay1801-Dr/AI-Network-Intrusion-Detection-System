"""Unit and integration tests for Phase 8 Alert Lifecycle Management and WebSocket Events."""

from datetime import datetime, timezone
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.errors import ConflictException, ResourceNotFoundException
from backend.app.db.session import Base, get_db
from backend.app.main import app
from backend.app.models.alert import AlertRecord
from backend.app.models.prediction import PredictionRecord
from backend.app.services.alert_service import AlertService
from backend.app.services.websocket_manager import WebSocketManager, websocket_manager

# Setup isolated in-memory SQLite database for testing
test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


from backend.app.core.dependencies import get_current_user
from backend.app.models.user import UserRecord

@pytest.fixture(scope="module", autouse=True)
def setup_test_db():
    """Create fresh isolated tables in memory and configure dependency override."""
    Base.metadata.create_all(bind=test_engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = lambda: UserRecord(
        id=1, username="admin", role="ADMIN", is_active=True
    )

    yield

    Base.metadata.drop_all(bind=test_engine)
    app.dependency_overrides.clear()


@pytest.fixture
def db_session():
    """Provide a transactional session for test assertions."""
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client():
    """TestClient configured with the in-memory test database."""
    return TestClient(app)


def create_sample_alert(
    db,
    status: str = "NEW",
    severity: str = "HIGH",
    with_prediction: bool = True,
    acknowledged_at=None,
    resolved_at=None,
) -> AlertRecord:
    """Helper to seed a test alert in the database."""
    pred_id = None
    if with_prediction:
        pred = PredictionRecord(
            predicted_threat="DoS Slowloris",
            intrusion_flag=True,
            anomaly_label="ANOMALY",
            anomaly_score=0.88,
            raw_decision_score=-0.25,
            classification_confidence=0.92,
            risk_level="HIGH",
            recommended_action="Rate-limit source IP and inspect connections.",
            source_ip="192.168.1.150",
            destination_ip="10.0.0.1",
            destination_port=80,
            protocol="TCP",
            flow_duration=15000.0,
            total_bytes=45000,
        )
        db.add(pred)
        db.flush()
        pred_id = pred.id

    alert = AlertRecord(
        prediction_id=pred_id,
        alert_type="NETWORK_INTRUSION",
        severity=severity,
        threat_label="DoS Slowloris",
        anomaly_score=0.88,
        confidence=0.92,
        source_ip="192.168.1.150",
        destination_ip="10.0.0.1",
        status=status,
        recommended_action="Rate-limit source IP and inspect connections.",
        acknowledged_at=acknowledged_at,
        resolved_at=resolved_at,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


# ==============================================================================
# 1. ALERT LIFECYCLE REST API TESTS
# ==============================================================================

def test_acknowledge_alert_new_to_acknowledged_success(client, db_session):
    """Verify that a NEW alert transitions to ACKNOWLEDGED with audit timestamp."""
    alert = create_sample_alert(db_session, status="NEW")

    response = client.patch(f"/api/v1/alerts/{alert.id}/acknowledge")
    assert response.status_code == 200
    data = response.json()

    assert data["id"] == alert.id
    assert data["status"] == "ACKNOWLEDGED"
    assert data["acknowledged_at"] is not None
    assert data["resolved_at"] is None
    # Ensure created_at is preserved
    assert data["created_at"] is not None

    # Check database persistence
    db_session.expire_all()
    refreshed = db_session.query(AlertRecord).filter(AlertRecord.id == alert.id).first()
    assert refreshed.status == "ACKNOWLEDGED"
    assert refreshed.acknowledged_at is not None
    assert refreshed.resolved_at is None


def test_resolve_alert_acknowledged_to_resolved_success(client, db_session):
    """Verify that an ACKNOWLEDGED alert transitions to RESOLVED preserving acknowledged_at."""
    ack_time = datetime.now(timezone.utc)
    alert = create_sample_alert(db_session, status="ACKNOWLEDGED", acknowledged_at=ack_time)

    response = client.patch(f"/api/v1/alerts/{alert.id}/resolve")
    assert response.status_code == 200
    data = response.json()

    assert data["id"] == alert.id
    assert data["status"] == "RESOLVED"
    assert data["resolved_at"] is not None
    assert data["acknowledged_at"] is not None  # preserved from previous state

    # Verify database persistence
    db_session.expire_all()
    refreshed = db_session.query(AlertRecord).filter(AlertRecord.id == alert.id).first()
    assert refreshed.status == "RESOLVED"
    assert refreshed.resolved_at is not None
    assert refreshed.acknowledged_at is not None


def test_resolve_alert_new_to_resolved_success(client, db_session):
    """Verify that a NEW alert can transition directly to RESOLVED without prior acknowledgement."""
    alert = create_sample_alert(db_session, status="NEW")

    response = client.patch(f"/api/v1/alerts/{alert.id}/resolve")
    assert response.status_code == 200
    data = response.json()

    assert data["id"] == alert.id
    assert data["status"] == "RESOLVED"
    assert data["resolved_at"] is not None
    assert data["acknowledged_at"] is None  # remains None since it was resolved directly from NEW


def test_acknowledge_resolved_alert_rejected(client, db_session):
    """Verify that attempting to acknowledge an already RESOLVED alert returns HTTP 409."""
    alert = create_sample_alert(
        db_session,
        status="RESOLVED",
        resolved_at=datetime.now(timezone.utc),
    )

    response = client.patch(f"/api/v1/alerts/{alert.id}/acknowledge")
    assert response.status_code == 409
    data = response.json()
    assert "error" in data["status"]
    assert "RESOLVED" in data["message"]


def test_resolve_resolved_alert_rejected(client, db_session):
    """Verify that attempting to resolve an already RESOLVED alert returns HTTP 409."""
    alert = create_sample_alert(
        db_session,
        status="RESOLVED",
        resolved_at=datetime.now(timezone.utc),
    )

    response = client.patch(f"/api/v1/alerts/{alert.id}/resolve")
    assert response.status_code == 409
    data = response.json()
    assert "error" in data["status"]
    assert "terminal status RESOLVED" in data["message"]


def test_acknowledge_already_acknowledged_alert_rejected(client, db_session):
    """Verify that acknowledging an alert that is already ACKNOWLEDGED returns HTTP 409."""
    alert = create_sample_alert(
        db_session,
        status="ACKNOWLEDGED",
        acknowledged_at=datetime.now(timezone.utc),
    )

    response = client.patch(f"/api/v1/alerts/{alert.id}/acknowledge")
    assert response.status_code == 409
    data = response.json()
    assert data["status"] == "error"


def test_lifecycle_nonexistent_alert_returns_404(client):
    """Verify that attempting lifecycle actions on nonexistent alerts returns HTTP 404."""
    ack_res = client.patch("/api/v1/alerts/999999/acknowledge")
    assert ack_res.status_code == 404
    assert "not found" in ack_res.json()["message"].lower()

    res_res = client.patch("/api/v1/alerts/999999/resolve")
    assert res_res.status_code == 404
    assert "not found" in res_res.json()["message"].lower()


def test_get_alert_details_success(client, db_session):
    """Verify GET /api/v1/alerts/{alert_id} returns detailed alert with linked prediction."""
    alert = create_sample_alert(db_session, status="NEW", with_prediction=True)

    response = client.get(f"/api/v1/alerts/{alert.id}")
    assert response.status_code == 200
    data = response.json()

    assert data["id"] == alert.id
    assert data["status"] == "NEW"
    assert data["severity"] == alert.severity
    assert data["threat_label"] == alert.threat_label
    assert data["prediction_id"] == alert.prediction_id
    assert "prediction" in data
    assert data["prediction"]["id"] == alert.prediction_id
    assert data["prediction"]["predicted_threat"] == "DoS Slowloris"


def test_get_nonexistent_alert_returns_404(client):
    """Verify GET /api/v1/alerts/{alert_id} returns 404 for unknown IDs."""
    response = client.get("/api/v1/alerts/999999")
    assert response.status_code == 404


# ==============================================================================
# 2. DATABASE FAILURE GUARDS WEBSOCKET EVENT
# ==============================================================================

@pytest.mark.asyncio
async def test_db_failure_suppresses_websocket_broadcast(db_session):
    """Verify that if database persistence fails, NO WebSocket event is broadcast."""
    alert = create_sample_alert(db_session, status="NEW")

    with patch("backend.app.services.alert_service.AlertRepository.get_by_id") as mock_get:
        mock_alert = MagicMock()
        mock_alert.id = alert.id
        mock_alert.status = "NEW"
        mock_get.return_value = mock_alert

        # Mock db session commit to fail
        failing_db = MagicMock()
        failing_db.commit.side_effect = RuntimeError("Simulated DB Connection Crash")

        with patch.object(websocket_manager, "broadcast", new_callable=AsyncMock) as mock_broadcast:
            with pytest.raises(Exception):
                AlertService.acknowledge_alert(failing_db, alert.id)

            # Assert broadcast was NEVER called because DB transaction failed
            mock_broadcast.assert_not_called()


# ==============================================================================
# 3. WEBSOCKET LIFECYCLE BROADCASTS
# ==============================================================================

def test_websocket_broadcast_on_acknowledgement(client, db_session):
    """Verify that a successful alert acknowledgement triggers WebSocket alert_acknowledged broadcast."""
    alert = create_sample_alert(db_session, status="NEW")

    with patch.object(websocket_manager, "broadcast", new_callable=AsyncMock) as mock_broadcast:
        response = client.patch(f"/api/v1/alerts/{alert.id}/acknowledge")
        assert response.status_code == 200

        mock_broadcast.assert_called_once()
        broadcast_payload = mock_broadcast.call_args[0][0]
        assert broadcast_payload["event_type"] == "alert_acknowledged"
        assert broadcast_payload["data"]["alert_id"] == alert.id
        assert broadcast_payload["data"]["status"] == "ACKNOWLEDGED"
        assert broadcast_payload["data"]["acknowledged_at"] is not None


def test_websocket_broadcast_on_resolution(client, db_session):
    """Verify that a successful alert resolution triggers WebSocket alert_resolved broadcast."""
    alert = create_sample_alert(db_session, status="NEW")

    with patch.object(websocket_manager, "broadcast", new_callable=AsyncMock) as mock_broadcast:
        response = client.patch(f"/api/v1/alerts/{alert.id}/resolve")
        assert response.status_code == 200

        mock_broadcast.assert_called_once()
        broadcast_payload = mock_broadcast.call_args[0][0]
        assert broadcast_payload["event_type"] == "alert_resolved"
        assert broadcast_payload["data"]["alert_id"] == alert.id
        assert broadcast_payload["data"]["status"] == "RESOLVED"
        assert broadcast_payload["data"]["resolved_at"] is not None


@pytest.mark.asyncio
async def test_websocket_broadcast_multiple_clients_and_isolated_failure():
    """Verify that lifecycle events reach multiple clients, and a faulty client does not break others."""
    manager = WebSocketManager()

    good_client_1 = AsyncMock()
    good_client_2 = AsyncMock()
    failing_client = AsyncMock()

    await manager.connect(good_client_1)
    await manager.connect(good_client_2)
    await manager.connect(failing_client)

    assert manager.active_count == 3

    # Now simulate broken connection during broadcast
    failing_client.send_json.side_effect = RuntimeError("Broken pipe")

    event = {
        "event_type": "alert_acknowledged",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": {"alert_id": 1, "status": "ACKNOWLEDGED"},
    }

    reached = await manager.broadcast(event)
    # Both good clients received the event
    assert reached == 2
    good_client_1.send_json.assert_called_with(event)
    good_client_2.send_json.assert_called_with(event)

    # Failing client was cleaned up
    assert manager.active_count == 2
