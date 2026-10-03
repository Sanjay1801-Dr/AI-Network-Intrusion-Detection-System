"""Unit, integration, and security tests for Phase 13 Security Analytics & Threat Intelligence Foundation."""

from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.security import create_access_token, get_password_hash
from backend.app.db.session import Base, get_db, SessionLocal
from backend.app.main import app
from backend.app.models.alert import AlertRecord
from backend.app.models.audit import AuditLogRecord
from backend.app.models.prediction import PredictionRecord
from backend.app.models.user import UserRecord
from backend.app.schemas.audit import AuditAction, AuditOutcome, AuditResourceType
from backend.app.services.audit_service import AuditService
from backend.app.services.prediction_service import PredictionService
from backend.app.services.security_analytics_service import SecurityAnalyticsService
from backend.app.services.threat_intelligence_service import (
    LocalThreatIntelligenceProvider,
    ThreatIntelligenceService,
)

# Setup isolated in-memory SQLite database
test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

TEST_USER_PASSWORD = "StrongSecureTestPassword!99"

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
    "source_ip": "192.0.2.1",
    "destination_ip": "10.0.0.1",
}


@pytest.fixture(scope="module", autouse=True)
def setup_analytics_test_database():
    """Create isolated test database schema, initialize ML inference, and seed test operators."""
    Base.metadata.create_all(bind=test_engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    # Initialize ML Inference engine
    PredictionService.initialize()

    # Seed test operator accounts
    db = TestingSessionLocal()
    hashed_pwd = get_password_hash(TEST_USER_PASSWORD)

    admin_user = UserRecord(username="sec_admin", password_hash=hashed_pwd, role="ADMIN", is_active=True)
    analyst_user = UserRecord(username="sec_analyst", password_hash=hashed_pwd, role="ANALYST", is_active=True)
    viewer_user = UserRecord(username="sec_viewer", password_hash=hashed_pwd, role="VIEWER", is_active=True)

    db.add_all([admin_user, analyst_user, viewer_user])
    db.commit()
    db.refresh(admin_user)
    db.refresh(analyst_user)
    db.refresh(viewer_user)

    # Route audit logging to test database
    AuditService.session_factory = TestingSessionLocal

    yield

    AuditService.session_factory = SessionLocal
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)


def get_token_for(username: str, role: str, user_id: int) -> str:
    """Helper to generate signed test Bearer token."""
    return create_access_token(subject=user_id, username=username, role=role)


# ==============================================================================
# 1. Overview API & Aggregation Tests
# ==============================================================================

def test_analytics_overview_empty_db():
    """Verify overview endpoint returns structured zeroes when no prediction/alert records exist."""
    token = get_token_for("sec_admin", "ADMIN", 1)
    client = TestClient(app)

    response = client.get(
        "/api/v1/analytics/overview",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["total_predictions"] == 0
    assert data["benign_predictions"] == 0
    assert data["malicious_predictions"] == 0
    assert data["anomaly_predictions"] == 0
    assert data["total_alerts"] == 0
    assert data["open_alerts"] == 0
    assert data["resolved_alerts"] == 0
    assert data["failed_logins"] == 0
    assert data["rate_limit_events"] == 0


def test_analytics_overview_populated_aggregation():
    """Verify correct database aggregation of predictions, alerts, and audit security events."""
    db = TestingSessionLocal()

    # Seed 2 benign predictions and 1 malicious intrusion
    p1 = PredictionRecord(
        timestamp=datetime.now(timezone.utc),
        source_ip="192.168.1.10",
        destination_ip="10.0.0.1",
        destination_port=443,
        protocol=6,
        predicted_threat="BENIGN",
        intrusion_flag=False,
        anomaly_score=0.15,
        raw_decision_score=0.25,
        anomaly_label="NORMAL",
        classification_confidence=0.98,
        risk_level="LOW",
        recommended_action="Log and monitor",
    )
    p2 = PredictionRecord(
        timestamp=datetime.now(timezone.utc),
        source_ip="192.168.1.11",
        destination_ip="10.0.0.1",
        destination_port=80,
        protocol=6,
        predicted_threat="BENIGN",
        intrusion_flag=False,
        anomaly_score=0.20,
        raw_decision_score=0.20,
        anomaly_label="NORMAL",
        classification_confidence=0.95,
        risk_level="LOW",
        recommended_action="Log and monitor",
    )
    p3 = PredictionRecord(
        timestamp=datetime.now(timezone.utc),
        source_ip="198.51.100.5",
        destination_ip="10.0.0.1",
        destination_port=22,
        protocol=6,
        predicted_threat="Port Scan",
        intrusion_flag=True,
        anomaly_score=0.88,
        raw_decision_score=-0.42,
        anomaly_label="ANOMALOUS",
        classification_confidence=0.92,
        risk_level="HIGH",
        recommended_action="Block source IP",
    )
    db.add_all([p1, p2, p3])
    db.commit()
    db.refresh(p3)

    # Seed an Alert for the intrusion
    a1 = AlertRecord(
        prediction_id=p3.id,
        created_at=datetime.now(timezone.utc),
        alert_type="NETWORK_INTRUSION",
        threat_label="Port Scan",
        severity="HIGH",
        anomaly_score=0.88,
        confidence=0.92,
        source_ip="198.51.100.5",
        status="NEW",
        recommended_action="Block IP",
    )
    db.add(a1)

    # Seed audit logs: 1 failed login and 1 rate limit event
    audit1 = AuditLogRecord(
        timestamp=datetime.now(timezone.utc),
        action=AuditAction.LOGIN_FAILURE.value,
        resource_type=AuditResourceType.AUTH.value,
        outcome=AuditOutcome.FAILURE.value,
        status_code=401,
    )
    audit2 = AuditLogRecord(
        timestamp=datetime.now(timezone.utc),
        action=AuditAction.RATE_LIMIT_EXCEEDED.value,
        resource_type=AuditResourceType.SYSTEM.value,
        outcome=AuditOutcome.FAILURE.value,
        status_code=429,
    )
    db.add_all([audit1, audit2])
    db.commit()
    db.close()

    token = get_token_for("sec_analyst", "ANALYST", 2)
    client = TestClient(app)

    response = client.get(
        "/api/v1/analytics/overview",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["total_predictions"] == 3
    assert data["benign_predictions"] == 2
    assert data["malicious_predictions"] == 1
    assert data["anomaly_predictions"] == 1
    assert data["total_alerts"] == 1
    assert data["open_alerts"] == 1
    assert data["high_alerts"] == 1
    assert data["failed_logins"] == 1
    assert data["rate_limit_events"] == 1


# ==============================================================================
# 2. Threat Distribution API Tests
# ==============================================================================

def test_threat_distribution_aggregation():
    """Verify threat categories and severity distributions accurately reflect database records."""
    token = get_token_for("sec_admin", "ADMIN", 1)
    client = TestClient(app)

    response = client.get(
        "/api/v1/analytics/threat-distribution",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()

    assert "threat_categories" in data
    assert "severity" in data

    # Check threat categories
    categories = {item["category"]: item["count"] for item in data["threat_categories"]}
    assert categories.get("BENIGN") == 2
    assert categories.get("Port Scan") == 1

    # Check severity
    severities = {item["severity"]: item["count"] for item in data["severity"]}
    assert severities.get("LOW") == 2
    assert severities.get("HIGH") == 1


# ==============================================================================
# 3. Security Timeline API Tests
# ==============================================================================

def test_security_timeline_ranges():
    """Verify security timeline supports configurable ranges and bounded buckets."""
    token = get_token_for("sec_viewer", "VIEWER", 3)
    client = TestClient(app)

    # Valid range 24h
    res_24h = client.get(
        "/api/v1/analytics/timeline?time_range=24h&limit=50",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res_24h.status_code == 200
    data_24h = res_24h.json()
    assert data_24h["time_range"] == "24h"
    assert "timeline" in data_24h
    assert isinstance(data_24h["timeline"], list)

    # Valid range 7d
    res_7d = client.get(
        "/api/v1/analytics/timeline?time_range=7d&limit=20",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res_7d.status_code == 200

    # Invalid range should raise 422
    res_bad = client.get(
        "/api/v1/analytics/timeline?time_range=invalid_range",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res_bad.status_code == 422


# ==============================================================================
# 4. Top Threat Sources Tests
# ==============================================================================

def test_top_sources_aggregation():
    """Verify source IP metrics: count, malicious count, highest severity, and dominant threat."""
    token = get_token_for("sec_analyst", "ANALYST", 2)
    client = TestClient(app)

    response = client.get(
        "/api/v1/analytics/top-sources?limit=10",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert isinstance(data["items"], list)
    assert len(data["items"]) > 0

    # Source 198.51.100.5 had 1 prediction, which was malicious Port Scan with HIGH severity
    found = [s for s in data["items"] if s["source_ip"] == "198.51.100.5"]
    assert len(found) == 1
    assert found[0]["prediction_count"] == 1
    assert found[0]["malicious_count"] == 1
    assert found[0]["highest_severity"] == "HIGH"
    assert found[0]["most_common_threat"] == "Port Scan"


# ==============================================================================
# 5. Threat Intelligence Tests
# ==============================================================================

def test_threat_intelligence_local_demo_hit():
    """Verify known RFC 5737 demo IP returns LOCAL_DEMO_INTELLIGENCE metadata."""
    token = get_token_for("sec_analyst", "ANALYST", 2)
    client = TestClient(app)

    response = client.get(
        "/api/v1/threat-intelligence/ip/192.0.2.1",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["ip"] == "192.0.2.1"
    assert data["found"] is True
    assert data["source"] == "LOCAL_DEMO_INTELLIGENCE"
    assert data["reputation"] == "MALICIOUS"
    assert data["confidence"] == 0.95
    assert "DoS" in data["categories"]


def test_threat_intelligence_unknown_ip():
    """Verify unknown IP safely returns found=False without error."""
    token = get_token_for("sec_viewer", "VIEWER", 3)
    client = TestClient(app)

    response = client.get(
        "/api/v1/threat-intelligence/ip/192.0.2.222",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["ip"] == "192.0.2.222"
    assert data["found"] is False
    assert data["source"] == "LOCAL_DEMO_INTELLIGENCE"
    assert data["reputation"] == "UNKNOWN"
    assert data["confidence"] == 0.0


def test_threat_intelligence_invalid_ip_rejected():
    """Verify syntactically invalid IP address strings are rejected with 422."""
    token = get_token_for("sec_admin", "ADMIN", 1)
    client = TestClient(app)

    response = client.get(
        "/api/v1/threat-intelligence/ip/999.999.999.999",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 422
    data = response.json()
    assert "Invalid IP address format" in data.get("message", "")


def test_local_threat_intelligence_provider_unit():
    """Unit test local provider interface methods directly."""
    provider = LocalThreatIntelligenceProvider()

    hit = provider.lookup_ip("198.51.100.42")
    assert hit is not None
    assert hit["reputation"] == "MALICIOUS"
    assert "Port Scan" in hit["categories"]

    miss = provider.lookup_ip("10.0.0.99")
    assert miss is None


# ==============================================================================
# 6. Prediction Explainability Tests
# ==============================================================================

def test_rule_based_explainability_deterministic():
    """Verify deterministic risk reasons derived from prediction values without fabrication."""
    # Test case 1: High severity intrusion
    high_pred = PredictionRecord(
        id=99,
        timestamp=datetime.now(timezone.utc),
        destination_port=22,
        protocol=6,
        predicted_threat="Port Scan",
        intrusion_flag=True,
        anomaly_score=0.91,
        raw_decision_score=-0.45,
        anomaly_label="ANOMALOUS",
        classification_confidence=0.94,
        risk_level="HIGH",
        recommended_action="Block IP",
    )
    reasons = SecurityAnalyticsService.generate_prediction_explanation(high_pred)
    assert isinstance(reasons, list)
    assert len(reasons) >= 3
    assert any("anomaly divergence" in r.lower() or "anomaly score" in r.lower() for r in reasons)
    assert any("classified" in r.lower() for r in reasons)

    # Test case 2: Benign nominal flow
    low_pred = PredictionRecord(
        id=100,
        timestamp=datetime.now(timezone.utc),
        destination_port=443,
        protocol=6,
        predicted_threat="BENIGN",
        intrusion_flag=False,
        anomaly_score=0.08,
        raw_decision_score=0.35,
        anomaly_label="NORMAL",
        classification_confidence=0.99,
        risk_level="LOW",
        recommended_action="Log and monitor",
    )
    reasons_low = SecurityAnalyticsService.generate_prediction_explanation(low_pred)
    assert isinstance(reasons_low, list)
    assert len(reasons_low) >= 1
    assert any("baseline benign" in r.lower() for r in reasons_low)
    assert not any("anomaly divergence" in r.lower() for r in reasons_low)


def test_predict_endpoint_contains_explanation():
    """Verify POST /api/v1/predict response incorporates deterministic explanation block."""
    token = get_token_for("sec_analyst", "ANALYST", 2)
    client = TestClient(app)

    response = client.post(
        "/api/v1/predict",
        json=SAMPLE_BENIGN_FLOW,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "explanation" in data
    assert data["explanation"]["method"] == "Rule-based prediction explanation"
    assert "risk_reasons" in data["explanation"]


# ==============================================================================
# 7. Analyst Investigation Endpoint Tests
# ==============================================================================

def test_investigate_valid_prediction():
    """Verify investigation endpoint returns forensic summary, explanation, alert, and threat intel."""
    token = get_token_for("sec_analyst", "ANALYST", 2)
    client = TestClient(app)

    # Query existing prediction ID from previous tests
    db = TestingSessionLocal()
    pred = db.query(PredictionRecord).filter(PredictionRecord.predicted_threat == "Port Scan").first()
    assert pred is not None
    pred_id = pred.id
    db.close()

    response = client.get(
        f"/api/v1/analytics/investigate/{pred_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["prediction_id"] == pred_id
    assert data["threat_category"] == "Port Scan"
    assert data["severity"] == "HIGH"
    assert "risk_reasons" in data
    assert isinstance(data["risk_reasons"], list)
    assert data["related_alert"] is not None
    assert data["related_alert"]["threat_label"] == "Port Scan"


def test_investigate_missing_prediction_404():
    """Verify querying non-existent prediction ID yields safe 404 response."""
    token = get_token_for("sec_admin", "ADMIN", 1)
    client = TestClient(app)

    response = client.get(
        "/api/v1/analytics/investigate/999999",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404
    data = response.json()
    assert "not found" in data.get("message", "").lower()


# ==============================================================================
# 8. RBAC & Authentication Tests
# ==============================================================================

def test_analytics_rbac_roles_allowed():
    """Verify ADMIN, ANALYST, and VIEWER roles can access read-only analytics."""
    client = TestClient(app)

    for role, u_id in [("ADMIN", 1), ("ANALYST", 2), ("VIEWER", 3)]:
        token = get_token_for(f"sec_{role.lower()}", role, u_id)
        res = client.get(
            "/api/v1/analytics/overview",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 200, f"Role {role} should be allowed to view analytics overview"


def test_analytics_unauthenticated_rejected():
    """Verify unauthenticated requests to all analytics endpoints are rejected with 401."""
    client = TestClient(app)

    endpoints = [
        "/api/v1/analytics/overview",
        "/api/v1/analytics/threat-distribution",
        "/api/v1/analytics/timeline",
        "/api/v1/analytics/top-sources",
        "/api/v1/analytics/investigate/1",
        "/api/v1/threat-intelligence/ip/192.0.2.1",
    ]

    for ep in endpoints:
        res = client.get(ep)
        assert res.status_code == 401, f"Unauthenticated request to {ep} must return 401"


# ==============================================================================
# 9. Audit Integration & Security Sanitization Tests
# ==============================================================================

def test_analytics_audit_events_logged():
    """Verify ANALYTICS_VIEWED, THREAT_INTELLIGENCE_LOOKUP, and INVESTIGATION_VIEWED audit logs."""
    token = get_token_for("sec_analyst", "ANALYST", 2)
    client = TestClient(app)

    # 1. Trigger overview -> ANALYTICS_VIEWED
    client.get("/api/v1/analytics/overview", headers={"Authorization": f"Bearer {token}"})

    # 2. Trigger threat intelligence lookup -> THREAT_INTELLIGENCE_LOOKUP
    client.get("/api/v1/threat-intelligence/ip/192.0.2.1", headers={"Authorization": f"Bearer {token}"})

    # 3. Trigger investigation -> INVESTIGATION_VIEWED
    db = TestingSessionLocal()
    pred = db.query(PredictionRecord).first()
    assert pred is not None
    client.get(f"/api/v1/analytics/investigate/{pred.id}", headers={"Authorization": f"Bearer {token}"})

    # Verify audit log records in database
    audit_actions = [log.action for log in db.query(AuditLogRecord).all()]
    db.close()

    assert AuditAction.ANALYTICS_VIEWED.value in audit_actions
    assert AuditAction.THREAT_INTELLIGENCE_LOOKUP.value in audit_actions
    assert AuditAction.INVESTIGATION_VIEWED.value in audit_actions


def test_responses_contain_no_secrets():
    """Verify analytics responses do not expose credentials, JWTs, hashes, or auth tokens."""
    token = get_token_for("sec_admin", "ADMIN", 1)
    client = TestClient(app)

    urls = [
        "/api/v1/analytics/overview",
        "/api/v1/analytics/threat-distribution",
        "/api/v1/analytics/timeline",
        "/api/v1/analytics/top-sources",
        "/api/v1/threat-intelligence/ip/192.0.2.1",
    ]

    for url in urls:
        res = client.get(url, headers={"Authorization": f"Bearer {token}"})
        body_text = res.text.lower()

        assert "password_hash" not in body_text
        assert "authorization" not in body_text
        assert "bearer" not in body_text
        assert "secret_key" not in body_text
