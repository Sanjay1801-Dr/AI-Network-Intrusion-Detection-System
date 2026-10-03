"""Comprehensive test suite for Phase 11 API Rate Limiting & Abuse Protection."""

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.config import settings, Settings
from backend.app.core.limiter import limiter
from backend.app.core.security import create_access_token, get_password_hash
from backend.app.db.session import Base, get_db
from backend.app.main import app
from backend.app.models.alert import AlertRecord
from backend.app.models.prediction import PredictionRecord
from backend.app.models.user import UserRecord

# Isolated in-memory SQLite database for testing
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
def setup_test_db():
    Base.metadata.create_all(bind=test_engine)
    db = TestingSessionLocal()
    try:
        # Seed test accounts with dynamically hashed passwords
        admin = UserRecord(
            username="rate_admin",
            password_hash=get_password_hash("AdminPassSecure!2026"),
            role="ADMIN",
            is_active=True,
        )
        analyst = UserRecord(
            username="rate_analyst",
            password_hash=get_password_hash("AnalystPassSecure!2026"),
            role="ANALYST",
            is_active=True,
        )
        viewer = UserRecord(
            username="rate_viewer",
            password_hash=get_password_hash("ViewerPassSecure!2026"),
            role="VIEWER",
            is_active=True,
        )
        db.add_all([admin, analyst, viewer])
        db.commit()
    finally:
        db.close()

    def override_get_db():
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    yield
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def admin_token():
    return create_access_token(subject="1", username="rate_admin", role="ADMIN")


@pytest.fixture
def analyst_token():
    return create_access_token(subject="2", username="rate_analyst", role="ANALYST")


@pytest.fixture
def viewer_token():
    return create_access_token(subject="3", username="rate_viewer", role="VIEWER")


# ==============================================================================
# 1. Login Rate Limiting & Brute-Force Tests
# ==============================================================================

def test_login_works_below_rate_limit(client):
    """Test that login succeeds normally when within configured rate limit."""
    res = client.post(
        "/api/v1/auth/login",
        json={"username": "rate_admin", "password": "AdminPassSecure!2026"},
    )
    assert res.status_code == 200
    assert "access_token" in res.json()


def test_login_invalid_credentials_returns_401_before_limit(client):
    """Verify that failed login attempts return 401 until the rate limit is exceeded."""
    res = client.post(
        "/api/v1/auth/login",
        json={"username": "rate_admin", "password": "WrongPasswordAttempt"},
    )
    assert res.status_code == 401
    assert "Invalid username or password" in res.json().get("message", "")


def test_login_rate_limit_exceeded_returns_429(client, monkeypatch):
    """Test that rapid consecutive login attempts trigger HTTP 429 Too Many Requests."""
    monkeypatch.setattr(settings, "RATE_LIMIT_LOGIN", "3/minute")
    limiter.reset()

    # Attempts 1, 2, 3 return 401
    for i in range(3):
        res = client.post(
            "/api/v1/auth/login",
            json={"username": "rate_admin", "password": "WrongPasswordAttempt"},
        )
        assert res.status_code == 401, f"Attempt {i+1} should return 401"

    # Attempt 4 must exceed the 3/minute limit and return 429
    res_exceeded = client.post(
        "/api/v1/auth/login",
        json={"username": "rate_admin", "password": "WrongPasswordAttempt"},
    )
    assert res_exceeded.status_code == 429
    data = res_exceeded.json()
    assert "detail" in data
    assert "Rate limit exceeded" in data["detail"]
    assert "Retry-After" in res_exceeded.headers


# ==============================================================================
# 2. Prediction Rate Limiting Tests
# ==============================================================================

def test_predict_works_below_rate_limit(client, analyst_token):
    """Verify inference endpoint works normally within rate limits."""
    headers = {"Authorization": f"Bearer {analyst_token}"}
    res = client.post("/api/v1/predict", json=SAMPLE_BENIGN_FLOW, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "classification" in data
    assert "predicted_label" in data["classification"]


def test_predict_rate_limit_exceeded_returns_429(client, analyst_token, monkeypatch):
    """Verify excessive inference requests trigger HTTP 429."""
    monkeypatch.setattr(settings, "RATE_LIMIT_PREDICT", "2/minute")
    limiter.reset()
    headers = {"Authorization": f"Bearer {analyst_token}"}

    # First 2 requests succeed
    res1 = client.post("/api/v1/predict", json=SAMPLE_BENIGN_FLOW, headers=headers)
    assert res1.status_code == 200
    res2 = client.post("/api/v1/predict", json=SAMPLE_BENIGN_FLOW, headers=headers)
    assert res2.status_code == 200

    # 3rd request hits rate limit
    res3 = client.post("/api/v1/predict", json=SAMPLE_BENIGN_FLOW, headers=headers)
    assert res3.status_code == 429
    assert res3.json()["detail"] == "Rate limit exceeded. Please try again later."
    assert "Retry-After" in res3.headers


# ==============================================================================
# 3. Read Endpoints Rate Limiting Tests
# ==============================================================================

def test_read_endpoints_work_below_rate_limit(client, viewer_token):
    """Verify read endpoints function normally within rate limits."""
    headers = {"Authorization": f"Bearer {viewer_token}"}
    res_pred = client.get("/api/v1/predictions?limit=5", headers=headers)
    assert res_pred.status_code == 200

    res_alerts = client.get("/api/v1/alerts?limit=5", headers=headers)
    assert res_alerts.status_code == 200

    res_me = client.get("/api/v1/auth/me", headers=headers)
    assert res_me.status_code == 200


def test_read_endpoints_exceeded_returns_429(client, viewer_token, monkeypatch):
    """Verify read-heavy endpoints throttle excessive requests with HTTP 429."""
    monkeypatch.setattr(settings, "RATE_LIMIT_READ", "2/minute")
    limiter.reset()
    headers = {"Authorization": f"Bearer {viewer_token}"}

    res1 = client.get("/api/v1/predictions?limit=2", headers=headers)
    assert res1.status_code == 200
    res2 = client.get("/api/v1/predictions?limit=2", headers=headers)
    assert res2.status_code == 200

    res3 = client.get("/api/v1/predictions?limit=2", headers=headers)
    assert res3.status_code == 429
    assert "Rate limit exceeded" in res3.json()["detail"]


# ==============================================================================
# 4. Mutation Endpoints Rate Limiting & RBAC Tests
# ==============================================================================

def test_mutation_works_below_rate_limit(client, admin_token):
    """Verify authorized mutation succeeds below rate limit."""
    # Seed an alert for mutation
    db = TestingSessionLocal()
    pred = PredictionRecord(
        destination_port=443,
        protocol="6",
        flow_duration=100.0,
        anomaly_label="ANOMALY",
        anomaly_score=-0.45,
        raw_decision_score=-0.15,
        predicted_threat="DoS",
        intrusion_flag=True,
        classification_confidence=0.95,
        risk_level="HIGH",
        recommended_action="Block IP",
    )
    db.add(pred)
    db.commit()

    alert = AlertRecord(
        prediction_id=pred.id,
        severity="HIGH",
        threat_label="DoS",
        anomaly_score=-0.45,
        confidence=0.95,
        status="NEW",
        recommended_action="Block IP",
    )
    db.add(alert)
    db.commit()
    alert_id = alert.id
    db.close()

    headers = {"Authorization": f"Bearer {admin_token}"}
    res = client.patch(f"/api/v1/alerts/{alert_id}/acknowledge", headers=headers)
    assert res.status_code == 200
    assert res.json()["status"] == "ACKNOWLEDGED"


def test_viewer_remains_403_for_mutation_endpoints(client, viewer_token):
    """Verify VIEWER role remains strictly rejected with HTTP 403 on mutation endpoints."""
    headers = {"Authorization": f"Bearer {viewer_token}"}
    res = client.patch("/api/v1/alerts/1/acknowledge", headers=headers)
    assert res.status_code == 403
    assert "Access forbidden" in res.json().get("message", "") or "Insufficient permissions" in res.json().get("message", "")


def test_mutation_rate_limit_exceeded_returns_429(client, admin_token, monkeypatch):
    """Verify mutation endpoints enforce rate limiting on authorized callers."""
    monkeypatch.setattr(settings, "RATE_LIMIT_MUTATION", "1/minute")
    limiter.reset()

    # Seed an alert
    db = TestingSessionLocal()
    pred = PredictionRecord(
        destination_port=80,
        protocol="6",
        flow_duration=100.0,
        anomaly_label="ANOMALY",
        anomaly_score=-0.35,
        raw_decision_score=-0.10,
        predicted_threat="PortScan",
        intrusion_flag=True,
        classification_confidence=0.90,
        risk_level="MEDIUM",
        recommended_action="Investigate",
    )
    db.add(pred)
    db.commit()
    alert = AlertRecord(
        prediction_id=pred.id,
        severity="MEDIUM",
        threat_label="PortScan",
        anomaly_score=-0.35,
        confidence=0.90,
        status="NEW",
        recommended_action="Investigate",
    )
    db.add(alert)
    db.commit()
    alert_id = alert.id
    db.close()

    headers = {"Authorization": f"Bearer {admin_token}"}
    res1 = client.patch(f"/api/v1/alerts/{alert_id}/acknowledge", headers=headers)
    assert res1.status_code == 200

    # 2nd mutation request within 1 minute hits rate limit
    res2 = client.patch(f"/api/v1/alerts/{alert_id}/acknowledge", headers=headers)
    assert res2.status_code == 429
    assert "Rate limit exceeded" in res2.json()["detail"]


# ==============================================================================
# 5. Configuration & Disabling Tests
# ==============================================================================

def test_rate_limiting_can_be_disabled(client, monkeypatch):
    """Test that disabling rate limiting allows requests without 429 throttling."""
    monkeypatch.setattr(limiter, "enabled", False)
    monkeypatch.setattr(settings, "RATE_LIMIT_LOGIN", "1/minute")
    limiter.reset()

    for _ in range(5):
        res = client.post(
            "/api/v1/auth/login",
            json={"username": "rate_admin", "password": "WrongPasswordAttempt"},
        )
        assert res.status_code == 401  # Not 429!

    # Re-enable
    monkeypatch.setattr(limiter, "enabled", True)


def test_environment_values_parsed_correctly():
    """Verify rate limit environment variables parse properly into Settings."""
    cfg = Settings(
        NIDS_RATE_LIMIT_ENABLED=True,
        NIDS_RATE_LIMIT_LOGIN="15/minute",
        NIDS_RATE_LIMIT_PREDICT="120/minute",
        NIDS_RATE_LIMIT_READ="300/minute",
        NIDS_RATE_LIMIT_MUTATION="50/minute",
    )
    assert cfg.RATE_LIMIT_ENABLED is True
    assert cfg.RATE_LIMIT_LOGIN == "15/minute"
    assert cfg.RATE_LIMIT_PREDICT == "120/minute"
    assert cfg.RATE_LIMIT_READ == "300/minute"
    assert cfg.RATE_LIMIT_MUTATION == "50/minute"


def test_invalid_rate_limit_configuration_rejected():
    """Verify malformed rate limit strings are rejected with clear errors."""
    with pytest.raises(ValueError, match="Invalid rate limit format"):
        Settings(NIDS_RATE_LIMIT_LOGIN="invalid_rate_string")

    with pytest.raises(ValueError, match="Invalid rate limit format"):
        Settings(NIDS_RATE_LIMIT_PREDICT="none")


def test_production_rejects_disabled_rate_limit():
    """Verify production mode strictly forbids disabling rate limiting."""
    with pytest.raises(ValueError, match="Rate limiting cannot be disabled in production"):
        Settings(
            NIDS_ENVIRONMENT="production",
            NIDS_JWT_SECRET="a" * 32,
            NIDS_RATE_LIMIT_ENABLED=False,
        )


# ==============================================================================
# 6. Security, Anti-Spoofing & Secret Safety Tests
# ==============================================================================

def test_429_response_does_not_leak_secrets(client, monkeypatch):
    """Verify HTTP 429 response contains clean detail and leaks no sensitive info."""
    monkeypatch.setattr(settings, "RATE_LIMIT_LOGIN", "1/minute")
    limiter.reset()

    client.post("/api/v1/auth/login", json={"username": "a", "password": "b"})
    res = client.post("/api/v1/auth/login", json={"username": "a", "password": "b"})
    assert res.status_code == 429

    raw_text = res.text.lower()
    for sensitive in ("secret", "token", "password", "hash", "traceback", "file \"", "sqlite", "postgres"):
        assert sensitive not in raw_text


def test_rate_limit_headers_injected_on_429(client, monkeypatch):
    """Verify standard rate limit headers (Retry-After, X-RateLimit-*) are present on 429."""
    monkeypatch.setattr(settings, "RATE_LIMIT_LOGIN", "1/minute")
    limiter.reset()

    client.post("/api/v1/auth/login", json={"username": "a", "password": "b"})
    res = client.post("/api/v1/auth/login", json={"username": "a", "password": "b"})
    assert res.status_code == 429

    assert "retry-after" in res.headers
    assert int(res.headers["retry-after"]) >= 1
    assert "x-ratelimit-limit" in res.headers
    assert "x-ratelimit-remaining" in res.headers
    # Confirm security headers from middleware are also present
    assert res.headers.get("x-content-type-options") == "nosniff"
    assert res.headers.get("x-frame-options") == "DENY"


def test_ip_spoofing_via_x_forwarded_for_is_not_trusted(client, monkeypatch):
    """Verify that injecting arbitrary X-Forwarded-For headers does NOT bypass login rate limit."""
    monkeypatch.setattr(settings, "RATE_LIMIT_LOGIN", "2/minute")
    limiter.reset()

    # Request 1 from attacker with forged header
    res1 = client.post(
        "/api/v1/auth/login",
        json={"username": "a", "password": "b"},
        headers={"X-Forwarded-For": "198.51.100.1"},
    )
    assert res1.status_code == 401

    # Request 2 with different forged header
    res2 = client.post(
        "/api/v1/auth/login",
        json={"username": "a", "password": "b"},
        headers={"X-Forwarded-For": "198.51.100.2"},
    )
    assert res2.status_code == 401

    # Request 3 with yet another forged header - must still be throttled because socket IP is tracked
    res3 = client.post(
        "/api/v1/auth/login",
        json={"username": "a", "password": "b"},
        headers={"X-Forwarded-For": "198.51.100.3"},
    )
    assert res3.status_code == 429, "Attacker bypassed rate limiter using spoofed X-Forwarded-For!"
