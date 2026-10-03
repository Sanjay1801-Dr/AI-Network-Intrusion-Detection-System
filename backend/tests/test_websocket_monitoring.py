"""Unit and integration tests for Phase 7 WebSocket Real-Time Security Monitoring."""

import asyncio
from datetime import datetime, timezone
from fastapi.testclient import TestClient
import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from backend.app.main import app
from backend.app.services.websocket_manager import WebSocketManager, websocket_manager

client = TestClient(app)

SAMPLE_FLOW_BENIGN = {
    "Destination Port": 443,
    "Flow Duration": 245000,
    "Total Fwd Packets": 14,
    "Total Backward Packets": 18,
    "Total Length of Fwd Packets": 1240,
    "Total Length of Bwd Packets": 18450,
    "Flow Bytes/s": 80363.41,
    "Flow Packets/s": 130.60,
    "Protocol": 6,
    "Flow IAT Mean": 7903.61,
    "Flow IAT Std": 12450.2,
    "Flow IAT Max": 45210,
    "Flow IAT Min": 12,
    "Fwd Packet Length Mean": 88.57,
    "Bwd Packet Length Mean": 1025.0,
    "FIN Flag Count": 1,
    "SYN Flag Count": 1,
    "RST Flag Count": 0,
    "PSH Flag Count": 8,
    "ACK Flag Count": 31,
    "source_ip": "192.168.1.105",
    "destination_ip": "104.244.42.1",
}

SAMPLE_FLOW_DOS = {
    "Destination Port": 80,
    "Flow Duration": 12050,
    "Total Fwd Packets": 850,
    "Total Backward Packets": 0,
    "Total Length of Fwd Packets": 51000,
    "Total Length of Bwd Packets": 0,
    "Flow Bytes/s": 4232365.14,
    "Flow Packets/s": 70539.41,
    "Protocol": 6,
    "Flow IAT Mean": 14.17,
    "Flow IAT Std": 8.35,
    "Flow IAT Max": 42,
    "Flow IAT Min": 2,
    "Fwd Packet Length Mean": 60.0,
    "Bwd Packet Length Mean": 0.0,
    "FIN Flag Count": 0,
    "SYN Flag Count": 850,
    "RST Flag Count": 0,
    "PSH Flag Count": 0,
    "ACK Flag Count": 0,
    "source_ip": "185.220.101.4",
    "destination_ip": "192.168.1.20",
}


from backend.app.core.dependencies import get_current_user
from backend.app.models.user import UserRecord

@pytest.fixture(scope="module", autouse=True)
def setup_auth_override():
    """Inject authorized operator session for regression assertions."""
    app.dependency_overrides[get_current_user] = lambda: UserRecord(
        id=1, username="admin", role="ADMIN", is_active=True
    )
    yield
    app.dependency_overrides.pop(get_current_user, None)


def test_websocket_connection_and_handshake():
    """Verify that a client connects to /api/v1/ws/monitor and receives connection_established."""
    with client.websocket_connect("/api/v1/ws/monitor") as ws:
        msg = ws.receive_json()
        assert msg["event_type"] == "connection_established"
        assert msg["data"]["status"] == "connected"
        assert msg["data"]["service"] == "NIDS Monitoring"
        assert "timestamp" in msg


def test_websocket_ping_pong():
    """Verify that client ping is acknowledged with a pong response."""
    with client.websocket_connect("/api/v1/ws/monitor") as ws:
        handshake = ws.receive_json()
        assert handshake["event_type"] == "connection_established"

        # Send ping
        ws.send_text("ping")
        pong = ws.receive_json()
        assert pong["event_type"] == "pong"
        assert "timestamp" in pong


def test_prediction_and_alert_broadcast_on_predict():
    """Verify that submitting a prediction persists to DB and broadcasts events over WebSocket."""
    with client.websocket_connect("/api/v1/ws/monitor") as ws:
        handshake = ws.receive_json()
        assert handshake["event_type"] == "connection_established"

        # Submit DoS prediction via REST
        response = client.post("/api/v1/predict", json=SAMPLE_FLOW_DOS)
        assert response.status_code == 200
        rest_data = response.json()

        # WebSocket should receive prediction_created event
        pred_event = ws.receive_json()
        assert pred_event["event_type"] == "prediction_created"
        assert "prediction_id" in pred_event["data"]
        assert pred_event["data"]["predicted_threat"] == rest_data["classification"]["predicted_label"]
        assert pred_event["data"]["risk_level"] == rest_data["risk_assessment"]["risk_level"]

        # If risk is MEDIUM, HIGH, or CRITICAL, an alert_created event must follow
        if rest_data["risk_assessment"]["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL"):
            alert_event = ws.receive_json()
            assert alert_event["event_type"] == "alert_created"
            assert "alert_id" in alert_event["data"]
            assert alert_event["data"]["prediction_id"] == pred_event["data"]["prediction_id"]
            assert alert_event["data"]["severity"] in ("MEDIUM", "HIGH", "CRITICAL")


def test_no_broadcast_when_persistence_fails():
    """Verify that if database persistence fails, no WebSocket events are emitted."""
    with client.websocket_connect("/api/v1/ws/monitor") as ws:
        handshake = ws.receive_json()
        assert handshake["event_type"] == "connection_established"

        # Mock PersistenceService.save_prediction_and_alert to fail
        with patch(
            "backend.app.services.persistence_service.PersistenceService.save_prediction_and_alert",
            side_effect=Exception("Simulated DB connection drop"),
        ):
            response = client.post("/api/v1/predict", json=SAMPLE_FLOW_BENIGN)
            assert response.status_code == 500

        # Verify no prediction event was broadcast by sending a ping to verify channel is still clear
        ws.send_text("ping")
        pong = ws.receive_json()
        assert pong["event_type"] == "pong"


def test_multiple_clients_and_isolation():
    """Verify multiple WebSocket clients can connect and receive broadcasts simultaneously."""
    with client.websocket_connect("/api/v1/ws/monitor") as ws1:
        assert ws1.receive_json()["event_type"] == "connection_established"

        with client.websocket_connect("/api/v1/ws/monitor") as ws2:
            assert ws2.receive_json()["event_type"] == "connection_established"

            # Broadcast a test event through the manager
            test_event = {
                "event_type": "heartbeat",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            # Use websocket_manager
            asyncio.run(websocket_manager.broadcast(test_event))

            # Both clients must receive the event
            msg1 = ws1.receive_json()
            msg2 = ws2.receive_json()
            assert msg1["event_type"] == "heartbeat"
            assert msg2["event_type"] == "heartbeat"


def test_failed_client_does_not_break_other_clients():
    """Verify that a failing client is isolated and does not disrupt broadcasting to healthy clients."""
    manager = WebSocketManager()

    mock_bad_ws = AsyncMock()
    mock_bad_ws.accept = AsyncMock(return_value=None)
    # Succeeds on connection handshake, fails during broadcast
    mock_bad_ws.send_json = AsyncMock(side_effect=[None, Exception("Socket write error")])

    mock_good_ws = AsyncMock()
    mock_good_ws.accept = AsyncMock(return_value=None)
    mock_good_ws.send_json = AsyncMock(return_value=None)

    # Register both in manager
    asyncio.run(manager.connect(mock_bad_ws))
    asyncio.run(manager.connect(mock_good_ws))
    assert manager.active_count == 2

    # Broadcast event
    test_msg = {"event_type": "heartbeat", "timestamp": "now"}
    sent_count = asyncio.run(manager.broadcast(test_msg))

    # Good client succeeded, bad client removed
    assert sent_count == 1
    assert manager.active_count == 1
    assert mock_good_ws in manager._active_connections
    assert mock_bad_ws not in manager._active_connections


def test_heartbeat_manager_method():
    """Verify that websocket_manager.send_heartbeat broadcasts heartbeat event."""
    with client.websocket_connect("/api/v1/ws/monitor") as ws:
        ws.receive_json()  # handshake

        asyncio.run(websocket_manager.send_heartbeat())
        hb = ws.receive_json()
        assert hb["event_type"] == "heartbeat"
        assert "timestamp" in hb


def test_existing_rest_endpoints_unaffected():
    """Verify that REST endpoints (health, predictions, alerts) continue to operate normally."""
    # Health check
    h_res = client.get("/api/health")
    assert h_res.status_code == 200

    # Predictions query
    p_res = client.get("/api/v1/predictions?limit=5")
    assert p_res.status_code == 200
    assert "items" in p_res.json()

    # Alerts query
    a_res = client.get("/api/v1/alerts?limit=5")
    assert a_res.status_code == 200
    assert "items" in a_res.json()
