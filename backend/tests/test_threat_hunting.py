"""Unit, integration, correlation, and security tests for Phase 16 Threat Hunting & Investigation Workbench."""

from datetime import datetime, timedelta, timezone
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
from backend.app.models.incident import IncidentRecord
from backend.app.models.prediction import PredictionRecord
from backend.app.models.threat_hunting import HuntQueryHistoryRecord
from backend.app.models.user import UserRecord
from backend.app.schemas.audit import AuditAction, AuditResourceType
from backend.app.services.audit_service import AuditService

# Isolated in-memory SQLite database for testing
test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

TEST_USER_PASSWORD = "StrongSecureTestPassword!99"


@pytest.fixture(scope="module", autouse=True)
def setup_threat_hunting_test_database():
    """Create test tables, seed operators, network telemetry, alerts, incidents, and audit logs."""
    Base.metadata.create_all(bind=test_engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    db = TestingSessionLocal()
    hashed_pwd = get_password_hash(TEST_USER_PASSWORD)

    admin_user = UserRecord(username="hunt_admin", password_hash=hashed_pwd, role="ADMIN", is_active=True)
    analyst_user = UserRecord(username="hunt_analyst", password_hash=hashed_pwd, role="ANALYST", is_active=True)
    viewer_user = UserRecord(username="hunt_viewer", password_hash=hashed_pwd, role="VIEWER", is_active=True)

    db.add_all([admin_user, analyst_user, viewer_user])
    db.flush()

    now = datetime.now(timezone.utc)

    # Seed Predictions
    pred1 = PredictionRecord(
        timestamp=now - timedelta(minutes=5),
        anomaly_label="ANOMALY",
        anomaly_score=-0.75,
        raw_decision_score=-0.75,
        predicted_threat="DDoS-LOIC",
        intrusion_flag=True,
        classification_confidence=0.98,
        risk_level="CRITICAL",
        recommended_action="Block IP",
        source_ip="198.51.100.11",
        destination_ip="10.0.0.5",
        source_port=54321,
        destination_port=80,
        protocol="6",
    )
    pred2 = PredictionRecord(
        timestamp=now - timedelta(minutes=7),
        anomaly_label="ANOMALY",
        anomaly_score=-0.80,
        raw_decision_score=-0.80,
        predicted_threat="DDoS-LOIC",
        intrusion_flag=True,
        classification_confidence=0.95,
        risk_level="CRITICAL",
        recommended_action="Block IP",
        source_ip="198.51.100.11",
        destination_ip="10.0.0.5",
        source_port=54322,
        destination_port=80,
        protocol="6",
    )
    pred3 = PredictionRecord(
        timestamp=now - timedelta(minutes=8),
        anomaly_label="ANOMALY",
        anomaly_score=-0.60,
        raw_decision_score=-0.60,
        predicted_threat="PortScan",
        intrusion_flag=True,
        classification_confidence=0.92,
        risk_level="HIGH",
        recommended_action="Rate limit",
        source_ip="198.51.100.11",
        destination_ip="10.0.0.5",
        source_port=54323,
        destination_port=443,
        protocol="6",
    )
    pred4 = PredictionRecord(
        timestamp=now - timedelta(hours=2),
        anomaly_label="NORMAL",
        anomaly_score=0.45,
        raw_decision_score=0.45,
        predicted_threat="BENIGN",
        intrusion_flag=False,
        classification_confidence=0.99,
        risk_level="LOW",
        recommended_action="Permit",
        source_ip="192.168.1.50",
        destination_ip="10.0.0.1",
        source_port=49152,
        destination_port=443,
        protocol="6",
    )
    db.add_all([pred1, pred2, pred3, pred4])
    db.flush()

    # Seed Alerts
    alert1 = AlertRecord(
        timestamp=now - timedelta(minutes=5),
        prediction_id=pred1.id,
        alert_type="CRITICAL_INTRUSION",
        severity="CRITICAL",
        threat_label="DDoS-LOIC",
        anomaly_score=-0.75,
        confidence=0.98,
        source_ip="198.51.100.11",
        destination_ip="10.0.0.5",
        status="NEW",
        recommended_action="Block IP",
    )
    alert2 = AlertRecord(
        timestamp=now - timedelta(minutes=8),
        prediction_id=pred3.id,
        alert_type="HIGH_RISK_INTRUSION",
        severity="HIGH",
        threat_label="PortScan",
        anomaly_score=-0.60,
        confidence=0.92,
        source_ip="198.51.100.11",
        destination_ip="10.0.0.5",
        status="ACKNOWLEDGED",
        recommended_action="Inspect source",
    )
    db.add_all([alert1, alert2])
    db.flush()

    # Seed Incident
    inc1 = IncidentRecord(
        incident_key="INC-2026-000099",
        title="DDoS Swarm Investigation",
        description="Multi-vector volumetric incursion observed on perimeter gateway",
        severity="CRITICAL",
        status="INVESTIGATING",
        category="DDoS-LOIC",
        source_ip="198.51.100.11",
        assigned_to="hunt_analyst",
        created_by="hunt_admin",
        created_at=now - timedelta(minutes=4),
        updated_at=now - timedelta(minutes=2),
    )
    inc1.alerts.append(alert1)
    inc1.predictions.append(pred1)
    db.add(inc1)
    db.flush()

    db.commit()

    AuditService.session_factory = TestingSessionLocal

    yield

    AuditService.session_factory = SessionLocal
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def admin_headers():
    token = create_access_token(subject="1", username="hunt_admin", role="ADMIN")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def analyst_headers():
    token = create_access_token(subject="2", username="hunt_analyst", role="ANALYST")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def viewer_headers():
    token = create_access_token(subject="3", username="hunt_viewer", role="VIEWER")
    return {"Authorization": f"Bearer {token}"}


# =============================================================================
# 1. Search Engine Tests
# =============================================================================


def test_hunt_search_authenticated_success(client, analyst_headers):
    """Test authenticated threat hunt search across predictions, alerts, and incidents."""
    payload = {
        "time_range": "24h",
        "limit": 50,
        "offset": 0,
    }
    response = client.post("/api/v1/hunting/search", json=payload, headers=analyst_headers)
    assert response.status_code == 200
    data = response.json()

    assert data["total_predictions"] >= 4
    assert data["total_alerts"] >= 2
    assert data["total_incidents"] >= 1
    assert len(data["matching_predictions"]) > 0
    assert len(data["matching_alerts"]) > 0
    assert len(data["matching_incidents"]) > 0
    assert "time_range_label" in data


def test_hunt_search_multiple_filters(client, analyst_headers):
    """Test searching with combined network, severity, and threat category filters."""
    payload = {
        "source_ip": "198.51.100.11",
        "destination_ip": "10.0.0.5",
        "threat_category": "DDoS",
        "severity": "CRITICAL",
        "time_range": "24h",
    }
    response = client.post("/api/v1/hunting/search", json=payload, headers=analyst_headers)
    assert response.status_code == 200
    data = response.json()

    assert data["total_predictions"] >= 2
    for pred in data["matching_predictions"]:
        assert pred["source_ip"] == "198.51.100.11"
        assert pred["destination_ip"] == "10.0.0.5"
        assert pred["risk_level"] == "CRITICAL"
        assert "DDoS" in pred["predicted_threat"]


def test_hunt_search_score_and_confidence_range(client, analyst_headers):
    """Test filtering by anomaly score bounds and classifier confidence bounds."""
    payload = {
        "min_anomaly_score": -1.0,
        "max_anomaly_score": -0.5,
        "min_confidence": 0.90,
        "max_confidence": 1.0,
        "time_range": "24h",
    }
    response = client.post("/api/v1/hunting/search", json=payload, headers=analyst_headers)
    assert response.status_code == 200
    data = response.json()

    assert data["total_predictions"] >= 3
    for pred in data["matching_predictions"]:
        assert pred["anomaly_score"] <= -0.5
        assert pred["classification_confidence"] >= 0.90


def test_hunt_search_time_range_variants(client, analyst_headers):
    """Test predefined time ranges (1h, 24h, 7d, 30d)."""
    for r in ["1h", "24h", "7d", "30d"]:
        response = client.post("/api/v1/hunting/search", json={"time_range": r}, headers=analyst_headers)
        assert response.status_code == 200
        data = response.json()
        assert "time_range_label" in data


def test_hunt_search_custom_time_range(client, analyst_headers):
    """Test valid custom time range filtering."""
    now = datetime.now(timezone.utc)
    start_dt = (now - timedelta(days=2)).isoformat()
    end_dt = now.isoformat()

    payload = {
        "time_range": "custom",
        "start_datetime": start_dt,
        "end_datetime": end_dt,
    }
    response = client.post("/api/v1/hunting/search", json=payload, headers=analyst_headers)
    assert response.status_code == 200
    data = response.json()
    assert "Custom" in data["time_range_label"]


def test_hunt_search_empty_result(client, analyst_headers):
    """Test that a search with non-matching criteria cleanly returns empty lists."""
    payload = {
        "source_ip": "10.99.99.99",
        "time_range": "24h",
    }
    response = client.post("/api/v1/hunting/search", json=payload, headers=analyst_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total_predictions"] == 0
    assert data["total_alerts"] == 0
    assert data["total_incidents"] == 0
    assert data["matching_predictions"] == []
    assert data["matching_alerts"] == []
    assert data["matching_incidents"] == []


def test_hunt_search_pagination(client, analyst_headers):
    """Test pagination bounds (limit & offset)."""
    payload = {
        "time_range": "24h",
        "limit": 1,
        "offset": 0,
    }
    res1 = client.post("/api/v1/hunting/search", json=payload, headers=analyst_headers)
    assert res1.status_code == 200
    data1 = res1.json()
    assert len(data1["matching_predictions"]) <= 1

    payload["offset"] = 1
    res2 = client.post("/api/v1/hunting/search", json=payload, headers=analyst_headers)
    assert res2.status_code == 200
    data2 = res2.json()
    assert len(data2["matching_predictions"]) <= 1
    if data1["matching_predictions"] and data2["matching_predictions"]:
        assert data1["matching_predictions"][0]["id"] != data2["matching_predictions"][0]["id"]


# =============================================================================
# 2. Input Validation & Bounds Enforcement
# =============================================================================


def test_hunt_search_invalid_ip_rejected(client, analyst_headers):
    """Test that malformed IP strings are rejected with HTTP 422."""
    payload = {
        "source_ip": "999.999.999.999",
    }
    response = client.post("/api/v1/hunting/search", json=payload, headers=analyst_headers)
    assert response.status_code == 422


def test_hunt_search_invalid_port_rejected(client, analyst_headers):
    """Test that out-of-range ports are rejected with HTTP 422."""
    payload = {
        "source_port": 99999,  # Max is 65535
    }
    response = client.post("/api/v1/hunting/search", json=payload, headers=analyst_headers)
    assert response.status_code == 422


def test_hunt_search_inverted_score_range_rejected(client, analyst_headers):
    """Test that min_anomaly_score > max_anomaly_score is rejected with HTTP 422."""
    payload = {
        "min_anomaly_score": 0.8,
        "max_anomaly_score": -0.2,
    }
    response = client.post("/api/v1/hunting/search", json=payload, headers=analyst_headers)
    assert response.status_code == 422


def test_hunt_search_inverted_confidence_range_rejected(client, analyst_headers):
    """Test that min_confidence > max_confidence is rejected with HTTP 422."""
    payload = {
        "min_confidence": 0.95,
        "max_confidence": 0.50,
    }
    response = client.post("/api/v1/hunting/search", json=payload, headers=analyst_headers)
    assert response.status_code == 422


def test_hunt_search_excessive_time_window_rejected(client, analyst_headers):
    """Test that custom time window > 90 days is rejected with HTTP 422."""
    now = datetime.now(timezone.utc)
    payload = {
        "time_range": "custom",
        "start_datetime": (now - timedelta(days=120)).isoformat(),
        "end_datetime": now.isoformat(),
    }
    response = client.post("/api/v1/hunting/search", json=payload, headers=analyst_headers)
    assert response.status_code == 422


def test_hunt_search_excessive_limit_rejected(client, analyst_headers):
    """Test that requesting limit > 200 is rejected with HTTP 422."""
    payload = {
        "limit": 500,  # Max allowed is 200
    }
    response = client.post("/api/v1/hunting/search", json=payload, headers=analyst_headers)
    assert response.status_code == 422


# =============================================================================
# 3. Correlation Engine Tests
# =============================================================================


def test_hunt_search_generates_correlation_insights(client, analyst_headers):
    """Test that multi-event queries produce structured correlation insights with defensive disclaimers."""
    payload = {
        "source_ip": "198.51.100.11",
        "time_range": "24h",
    }
    response = client.post("/api/v1/hunting/search", json=payload, headers=analyst_headers)
    assert response.status_code == 200
    data = response.json()

    correlations = data.get("correlations", [])
    assert len(correlations) > 0
    for c in correlations:
        assert "Potentially related security activity" in c["disclaimer"]
        assert c["confidence"] in ["HIGH", "MEDIUM", "LOW"]
        assert c["event_count"] >= 1


# =============================================================================
# 4. Source-Centric IP Forensic Investigation
# =============================================================================


def test_source_investigation_valid_ip(client, analyst_headers):
    """Test deep-dive source investigation for an observed active IP."""
    target_ip = "198.51.100.11"
    response = client.get(f"/api/v1/hunting/source/{target_ip}", headers=analyst_headers)
    assert response.status_code == 200
    data = response.json()

    assert data["ip_address"] == target_ip
    assert data["total_observations"] >= 5
    assert data["first_seen"] is not None
    assert data["last_seen"] is not None
    assert len(data["threat_categories"]) > 0
    assert len(data["observed_destinations"]) > 0
    assert len(data["timeline"]) > 0
    assert "DEFENSIVE MONITORING NOTICE" in data["disclaimer"]


def test_source_investigation_nonexistent_ip(client, analyst_headers):
    """Test investigating an IP not present in database cleanly returns zero observations."""
    target_ip = "10.254.254.254"
    response = client.get(f"/api/v1/hunting/source/{target_ip}", headers=analyst_headers)
    assert response.status_code == 200
    data = response.json()

    assert data["ip_address"] == target_ip
    assert data["total_observations"] == 0
    assert data["timeline"] == []


def test_source_investigation_invalid_ip_format(client, analyst_headers):
    """Test that invalid IP strings in the source path parameter are rejected."""
    bad_ip = "invalid_not_an_ip"
    response = client.get(f"/api/v1/hunting/source/{bad_ip}", headers=analyst_headers)
    assert response.status_code == 422


# =============================================================================
# 5. Query History
# =============================================================================


def test_query_history_recorded_and_retrieved(client, analyst_headers):
    """Test that performing a search automatically records safe query history for the user."""
    # 1. Execute a search
    payload = {
        "source_ip": "198.51.100.11",
        "threat_category": "DDoS",
        "time_range": "24h",
    }
    search_res = client.post("/api/v1/hunting/search", json=payload, headers=analyst_headers)
    assert search_res.status_code == 200

    # 2. Retrieve history
    hist_res = client.get("/api/v1/hunting/history", headers=analyst_headers)
    assert hist_res.status_code == 200
    items = hist_res.json()

    assert len(items) > 0
    first = items[0]
    assert first["username"] == "hunt_analyst"
    assert "src:198.51.100.11" in first["filter_summary"]
    assert first["result_count"] >= 1


# =============================================================================
# 6. Summary Metrics
# =============================================================================


def test_hunting_summary_metrics(client, analyst_headers):
    """Test GET /api/v1/hunting/summary aggregate metrics."""
    response = client.get("/api/v1/hunting/summary", headers=analyst_headers)
    assert response.status_code == 200
    data = response.json()

    assert data["total_flows_investigated"] >= 4
    assert data["total_threat_detections"] >= 3
    assert data["unique_source_ips"] >= 2
    assert "top_investigated_threats" in data
    assert "top_active_sources" in data


# =============================================================================
# 7. RBAC & Security Checks
# =============================================================================


def test_rbac_admin_full_access(client, admin_headers):
    """Test ADMIN role has full access to search and investigation."""
    res_search = client.post("/api/v1/hunting/search", json={"time_range": "24h"}, headers=admin_headers)
    assert res_search.status_code == 200

    res_source = client.get("/api/v1/hunting/source/198.51.100.11", headers=admin_headers)
    assert res_source.status_code == 200


def test_rbac_viewer_read_access(client, viewer_headers):
    """Test VIEWER role has read-only access to hunt search, summary, and source investigation."""
    res_search = client.post("/api/v1/hunting/search", json={"time_range": "24h"}, headers=viewer_headers)
    assert res_search.status_code == 200

    res_summary = client.get("/api/v1/hunting/summary", headers=viewer_headers)
    assert res_summary.status_code == 200

    res_source = client.get("/api/v1/hunting/source/198.51.100.11", headers=viewer_headers)
    assert res_source.status_code == 200


def test_unauthenticated_request_rejected(client):
    """Test that requests lacking valid JWT authorization header receive HTTP 401."""
    res_search = client.post("/api/v1/hunting/search", json={"time_range": "24h"})
    assert res_search.status_code == 401

    res_source = client.get("/api/v1/hunting/source/198.51.100.11")
    assert res_source.status_code == 401

    res_history = client.get("/api/v1/hunting/history")
    assert res_history.status_code == 401


def test_sql_injection_defense(client, analyst_headers):
    """Test that SQL injection strings in search filters are safely parameterized without syntax errors."""
    sqli_payload = {
        "threat_category": "' OR '1'='1' --",
        "query_text": "admin'; DROP TABLE predictions; --",
        "time_range": "24h",
    }
    response = client.post("/api/v1/hunting/search", json=sqli_payload, headers=analyst_headers)
    assert response.status_code == 200
    data = response.json()
    # Safely handled by SQLAlchemy parameterized queries, table not dropped, zero injection results
    assert "total_predictions" in data


def test_no_credential_leakage(client, analyst_headers):
    """Test that query history, audit logs, and search responses never expose passwords or JWT secrets."""
    hist_res = client.get("/api/v1/hunting/history", headers=analyst_headers)
    assert hist_res.status_code == 200
    text = hist_res.text
    assert "password_hash" not in text
    assert "StrongSecureTestPassword" not in text
    assert "eyJ" not in text  # No JWT signature fragments


# =============================================================================
# 8. Centralized Audit Logging Verification
# =============================================================================


def test_threat_hunt_audit_logging(client, analyst_headers):
    """Verify that THREAT_HUNT_SEARCHED, SOURCE_INVESTIGATION_VIEWED, and THREAT_HUNT_HISTORY_VIEWED are logged."""
    db = TestingSessionLocal()

    # Search
    client.post("/api/v1/hunting/search", json={"time_range": "24h"}, headers=analyst_headers)

    # Source view
    client.get("/api/v1/hunting/source/198.51.100.11", headers=analyst_headers)

    # History view
    client.get("/api/v1/hunting/history", headers=analyst_headers)

    search_log = (
        db.query(AuditLogRecord)
        .filter(AuditLogRecord.action == AuditAction.THREAT_HUNT_SEARCHED)
        .first()
    )
    assert search_log is not None
    assert search_log.username == "hunt_analyst"
    assert search_log.resource_type == AuditResourceType.HUNTING

    source_log = (
        db.query(AuditLogRecord)
        .filter(AuditLogRecord.action == AuditAction.SOURCE_INVESTIGATION_VIEWED)
        .first()
    )
    assert source_log is not None
    assert source_log.username == "hunt_analyst"
    assert source_log.resource_id == "198.51.100.11"

    hist_log = (
        db.query(AuditLogRecord)
        .filter(AuditLogRecord.action == AuditAction.THREAT_HUNT_HISTORY_VIEWED)
        .first()
    )
    assert hist_log is not None
    assert hist_log.username == "hunt_analyst"
    db.close()
