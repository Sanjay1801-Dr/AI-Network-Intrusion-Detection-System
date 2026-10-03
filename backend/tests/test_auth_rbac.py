"""Unit and integration tests for Phase 9 Authentication, RBAC, and Secure Operator Access."""

import asyncio
from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.config import settings
from backend.app.core.security import create_access_token, get_password_hash
from backend.app.db.session import Base, get_db
from backend.app.main import app
from backend.app.models.alert import AlertRecord
from backend.app.models.prediction import PredictionRecord
from backend.app.models.user import UserRecord
from backend.app.services.prediction_service import PredictionService

# Setup isolated in-memory SQLite database
test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

SAMPLE_BENIGN_FLOW = {
    "Destination Port": 443,
    "Flow Duration": 245012,
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
}


@pytest.fixture(scope="module", autouse=True)
def setup_auth_test_database():
    """Create isolated schema and seed test operators."""
    Base.metadata.create_all(bind=test_engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    PredictionService.initialize()

    # Seed test users directly
    db = TestingSessionLocal()
    try:
        users = [
            UserRecord(
                username="admin_test",
                password_hash=get_password_hash("AdminPass123!"),
                role="ADMIN",
                is_active=True,
            ),
            UserRecord(
                username="analyst_test",
                password_hash=get_password_hash("AnalystPass123!"),
                role="ANALYST",
                is_active=True,
            ),
            UserRecord(
                username="viewer_test",
                password_hash=get_password_hash("ViewerPass123!"),
                role="VIEWER",
                is_active=True,
            ),
            UserRecord(
                username="disabled_test",
                password_hash=get_password_hash("DisabledPass123!"),
                role="ANALYST",
                is_active=False,
            ),
        ]
        db.add_all(users)
        db.commit()
    finally:
        db.close()

    yield

    Base.metadata.drop_all(bind=test_engine)
    app.dependency_overrides.clear()


@pytest.fixture
def client():
    """Test client without any dependency overrides on get_current_user."""
    # Ensure no auth mock is active in client
    from backend.app.core.dependencies import get_current_user
    app.dependency_overrides.pop(get_current_user, None)
    return TestClient(app)


def get_token_for(client, username, password):
    """Helper to authenticate and return a valid Bearer token."""
    res = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
    )
    assert res.status_code == 200, f"Login failed for {username}: {res.text}"
    return res.json()["access_token"]


# ==============================================================================
# 1. AUTHENTICATION ENDPOINT TESTS
# ==============================================================================

def test_login_success(client):
    """Verify successful login returns valid JWT token and safe user profile."""
    res = client.post(
        "/api/v1/auth/login",
        json={"username": "admin_test", "password": "AdminPass123!"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["username"] == "admin_test"
    assert data["user"]["role"] == "ADMIN"
    assert "password_hash" not in data["user"]


def test_login_invalid_password(client):
    """Verify login with incorrect password returns generic 401 Unauthorized."""
    res = client.post(
        "/api/v1/auth/login",
        json={"username": "admin_test", "password": "WrongPassword999!"},
    )
    assert res.status_code == 401
    data = res.json()
    assert data["error_code"] == "UNAUTHORIZED"
    assert "Invalid username or password" in data["message"]


def test_login_nonexistent_user(client):
    """Verify login with unknown username returns generic 401 Unauthorized."""
    res = client.post(
        "/api/v1/auth/login",
        json={"username": "ghost_user", "password": "AnyPassword123!"},
    )
    assert res.status_code == 401
    data = res.json()
    assert data["error_code"] == "UNAUTHORIZED"
    assert "Invalid username or password" in data["message"]


def test_login_inactive_user_rejected(client):
    """Verify login for deactivated account is rejected with 401."""
    res = client.post(
        "/api/v1/auth/login",
        json={"username": "disabled_test", "password": "DisabledPass123!"},
    )
    assert res.status_code == 401
    data = res.json()
    assert "inactive" in data["message"].lower()


def test_login_missing_credentials(client):
    """Verify malformed login payloads return 422 Unprocessable Entity."""
    res = client.post("/api/v1/auth/login", json={"username": ""})
    assert res.status_code == 422


def test_get_current_user_me_endpoint(client):
    """Verify GET /api/v1/auth/me returns current operator details."""
    token = get_token_for(client, "analyst_test", "AnalystPass123!")
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get("/api/v1/auth/me", headers=headers)
    assert res.status_code == 200
    user_data = res.json()
    assert user_data["username"] == "analyst_test"
    assert user_data["role"] == "ANALYST"
    assert user_data["is_active"] is True
    assert "password_hash" not in user_data


def test_me_unauthenticated_rejected(client):
    """Verify GET /api/v1/auth/me without token returns 401."""
    res = client.get("/api/v1/auth/me")
    assert res.status_code == 401
    assert res.json()["error_code"] == "UNAUTHORIZED"


def test_me_invalid_token_rejected(client):
    """Verify GET /api/v1/auth/me with forged token returns 401."""
    res = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer forged.token.here"})
    assert res.status_code == 401


def test_me_expired_token_rejected(client):
    """Verify GET /api/v1/auth/me with expired token returns 401."""
    expired_token = create_access_token(
        subject=1,
        username="admin_test",
        role="ADMIN",
        expires_delta=timedelta(seconds=-10),  # expired 10 seconds ago
    )
    res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert res.status_code == 401
    assert "expired" in res.json()["message"].lower()


def test_logout_endpoint(client):
    """Verify POST /api/v1/auth/logout acknowledges session termination."""
    token = get_token_for(client, "admin_test", "AdminPass123!")
    res = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert res.json()["status"] == "success"


# ==============================================================================
# 2. ROLE-BASED ACCESS CONTROL (RBAC) ON PROTECTED REST ENDPOINTS
# ==============================================================================

def test_predict_endpoint_rbac(client):
    """Test POST /api/v1/predict RBAC permissions."""
    admin_token = get_token_for(client, "admin_test", "AdminPass123!")
    analyst_token = get_token_for(client, "analyst_test", "AnalystPass123!")
    viewer_token = get_token_for(client, "viewer_test", "ViewerPass123!")

    # 1. Unauthenticated -> 401
    res_no_auth = client.post("/api/v1/predict", json=SAMPLE_BENIGN_FLOW)
    assert res_no_auth.status_code == 401

    # 2. VIEWER role -> 403 Forbidden
    res_viewer = client.post(
        "/api/v1/predict",
        json=SAMPLE_BENIGN_FLOW,
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert res_viewer.status_code == 403
    assert res_viewer.json()["error_code"] == "FORBIDDEN"

    # 3. ANALYST role -> 200 OK
    res_analyst = client.post(
        "/api/v1/predict",
        json=SAMPLE_BENIGN_FLOW,
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert res_analyst.status_code == 200

    # 4. ADMIN role -> 200 OK
    res_admin = client.post(
        "/api/v1/predict",
        json=SAMPLE_BENIGN_FLOW,
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res_admin.status_code == 200


def test_predictions_history_rbac(client):
    """Test GET /api/v1/predictions: all authenticated roles can read."""
    viewer_token = get_token_for(client, "viewer_test", "ViewerPass123!")

    # Unauthenticated -> 401
    assert client.get("/api/v1/predictions").status_code == 401

    # Authenticated VIEWER -> 200 OK
    res = client.get("/api/v1/predictions", headers={"Authorization": f"Bearer {viewer_token}"})
    assert res.status_code == 200
    assert "items" in res.json()


def test_alerts_history_and_details_rbac(client):
    """Test GET /api/v1/alerts and GET /api/v1/alerts/{id}: all authenticated roles can read."""
    viewer_token = get_token_for(client, "viewer_test", "ViewerPass123!")

    # Seed an alert directly in DB
    db = TestingSessionLocal()
    alert = AlertRecord(
        alert_type="NETWORK_INTRUSION",
        severity="HIGH",
        threat_label="DoS",
        anomaly_score=0.85,
        confidence=0.90,
        status="NEW",
        recommended_action="Block traffic",
    )
    db.add(alert)
    db.commit()
    alert_id = alert.id
    db.close()

    # Unauthenticated list -> 401
    assert client.get("/api/v1/alerts").status_code == 401
    # Unauthenticated detail -> 401
    assert client.get(f"/api/v1/alerts/{alert_id}").status_code == 401

    # VIEWER read list -> 200
    res_list = client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {viewer_token}"})
    assert res_list.status_code == 200

    # VIEWER read detail -> 200
    res_detail = client.get(f"/api/v1/alerts/{alert_id}", headers={"Authorization": f"Bearer {viewer_token}"})
    assert res_detail.status_code == 200
    assert res_detail.json()["id"] == alert_id


def test_alert_lifecycle_mutation_rbac(client):
    """Test PATCH acknowledge and resolve: VIEWER gets 403; ANALYST and ADMIN succeed."""
    admin_token = get_token_for(client, "admin_test", "AdminPass123!")
    analyst_token = get_token_for(client, "analyst_test", "AnalystPass123!")
    viewer_token = get_token_for(client, "viewer_test", "ViewerPass123!")

    # Seed alert
    db = TestingSessionLocal()
    alert = AlertRecord(
        alert_type="NETWORK_INTRUSION",
        severity="CRITICAL",
        threat_label="Port Scan",
        anomaly_score=0.95,
        confidence=0.98,
        status="NEW",
        recommended_action="Triage host",
    )
    db.add(alert)
    db.commit()
    alert_id = alert.id
    db.close()

    # 1. Unauthenticated -> 401
    assert client.patch(f"/api/v1/alerts/{alert_id}/acknowledge").status_code == 401
    assert client.patch(f"/api/v1/alerts/{alert_id}/resolve").status_code == 401

    # 2. VIEWER -> 403 Forbidden
    res_viewer_ack = client.patch(
        f"/api/v1/alerts/{alert_id}/acknowledge",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert res_viewer_ack.status_code == 403
    assert res_viewer_ack.json()["error_code"] == "FORBIDDEN"

    res_viewer_res = client.patch(
        f"/api/v1/alerts/{alert_id}/resolve",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert res_viewer_res.status_code == 403
    assert res_viewer_res.json()["error_code"] == "FORBIDDEN"

    # 3. ANALYST -> 200 OK Acknowledge
    res_analyst_ack = client.patch(
        f"/api/v1/alerts/{alert_id}/acknowledge",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert res_analyst_ack.status_code == 200
    assert res_analyst_ack.json()["status"] == "ACKNOWLEDGED"

    # 4. ADMIN -> 200 OK Resolve
    res_admin_res = client.patch(
        f"/api/v1/alerts/{alert_id}/resolve",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res_admin_res.status_code == 200
    assert res_admin_res.json()["status"] == "RESOLVED"


# ==============================================================================
# 3. WEBSOCKET AUTHENTICATION TESTS (HANDSHAKE FRAME ONLY)
# ==============================================================================

def test_websocket_unauthenticated_rejected(client):
    """Verify WebSocket rejects connection when no auth frame is provided (code 1008)."""
    with pytest.raises(Exception):
        with client.websocket_connect("/api/v1/ws/monitor") as ws:
            ws.receive_json()


def test_websocket_invalid_auth_frame_rejected(client):
    """Verify WebSocket connection is closed when an invalid token frame is supplied."""
    with pytest.raises(Exception):
        with client.websocket_connect("/api/v1/ws/monitor") as ws:
            ws.send_json({"type": "auth", "token": "invalid.jwt.token"})
            ws.receive_json()


def test_websocket_expired_token_rejected(client):
    """Verify WebSocket rejects authentication handshake with an expired JWT token."""
    expired_token = create_access_token(
        subject=1,
        username="admin_test",
        role="ADMIN",
        expires_delta=timedelta(seconds=-30),
    )
    with pytest.raises(Exception):
        with client.websocket_connect("/api/v1/ws/monitor") as ws:
            ws.send_json({"type": "auth", "token": expired_token})
            ws.receive_json()


def test_websocket_authenticated_via_handshake_frame(client):
    """Verify WebSocket connects securely by sending an application-level auth handshake frame."""
    token = get_token_for(client, "analyst_test", "AnalystPass123!")
    with client.websocket_connect("/api/v1/ws/monitor") as ws:
        # Send auth frame within 5-second window
        ws.send_json({"type": "auth", "token": token})
        msg = ws.receive_json()
        assert msg["event_type"] == "connection_established"
        assert msg["data"]["authenticated"] is True
        assert msg["data"]["user"]["username"] == "analyst_test"


def test_websocket_query_param_token_not_supported_and_rejected(client):
    """Verify WebSocket does NOT authenticate via URL query parameters (?token=...).
    
    Any client attempting query-param authentication without sending the required
    handshake frame must be rejected.
    """
    token = get_token_for(client, "viewer_test", "ViewerPass123!")
    with pytest.raises(Exception):
        # Query parameter alone must NOT authenticate the socket
        with client.websocket_connect(f"/api/v1/ws/monitor?token={token}") as ws:
            ws.receive_json()

