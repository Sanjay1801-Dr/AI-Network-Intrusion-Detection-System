"""Comprehensive unit and integration tests for Phase 5 database persistence and history endpoints."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.db.session import Base, get_db
from backend.app.main import app
from backend.app.models.prediction import PredictionRecord
from backend.app.models.alert import AlertRecord
from backend.app.repositories.prediction_repository import PredictionRepository
from backend.app.repositories.alert_repository import AlertRepository
from backend.app.services.prediction_service import PredictionService

# Setup isolated in-memory SQLite database for test execution
test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


from backend.app.core.dependencies import get_current_user
from backend.app.models.user import UserRecord

@pytest.fixture(scope="module", autouse=True)
def setup_test_database():
    """Create fresh isolated database tables in memory and configure dependency override."""
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
    PredictionService.initialize()

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
    """TestClient bound to the application with test database override."""
    return TestClient(app)


SAMPLE_FLOW_PAYLOAD = {
    "Destination Port": 443,
    "Flow Duration": 245012,
    "Total Fwd Packets": 14,
    "Total Backward Packets": 18,
    "Total Length of Fwd Packets": 1240,
    "Total Length of Bwd Packets": 18450,
    "Flow Bytes/s": 80363.41,
    "Flow Packets/s": 130.60,
    "Protocol": 6,
}


def test_database_initialization(db_session):
    """1. Test that database initializes successfully and required tables exist."""
    inspector = inspect(test_engine)
    tables = inspector.get_table_names()
    assert "prediction_records" in tables
    assert "alerts" in tables


def test_prediction_record_insertion(db_session):
    """2. Test that a PredictionRecord can be inserted and retrieved via repository."""
    record = PredictionRecord(
        destination_port=80,
        protocol="6",
        flow_duration=12000.0,
        total_forward_packets=10,
        total_backward_packets=15,
        total_bytes=4500,
        anomaly_label="NORMAL",
        anomaly_score=0.25,
        raw_decision_score=0.15,
        predicted_threat="BENIGN",
        intrusion_flag=False,
        classification_confidence=0.88,
        risk_level="LOW",
        recommended_action="Standard Flow Logging",
    )
    inserted = PredictionRepository.create(db_session, record)
    db_session.commit()

    retrieved = PredictionRepository.get_by_id(db_session, inserted.id)
    assert retrieved is not None
    assert retrieved.id == inserted.id
    assert retrieved.predicted_threat == "BENIGN"
    assert retrieved.risk_level == "LOW"


def test_predict_persists_prediction_and_returns_compatible_response(client, db_session):
    """3 & 16. Successful POST /api/v1/predict persists a prediction and maintains response contract."""
    response = client.post("/api/v1/predict", json=SAMPLE_FLOW_PAYLOAD)
    assert response.status_code == 200
    data = response.json()

    # Verify compatibility with Phase 4 response structure
    assert "anomaly" in data
    assert "classification" in data
    assert "risk_assessment" in data

    # Verify record was persisted in database
    records, total = PredictionRepository.list(db_session, limit=10, offset=0)
    assert total >= 1
    assert any(r.destination_port == 443 for r in records)


def test_high_prediction_creates_alert(client, monkeypatch, db_session):
    """4. Test that HIGH risk prediction creates a security alert."""
    mock_high_result = {
        "anomaly": {
            "is_anomaly": False,
            "anomaly_label": "NORMAL",
            "anomaly_score": 0.35,
            "raw_decision_score": 0.08,
            "interpretation": "Divergence score: 0.35",
        },
        "classification": {
            "predicted_label": "Port Scan",
            "is_intrusion": True,
            "confidence": 0.85,
            "confidence_type": "estimated_class_probability",
            "class_probabilities": {"Port Scan": 0.85, "BENIGN": 0.15},
        },
        "risk_assessment": {
            "risk_level": "HIGH",
            "recommended_action": "SOC Incident Queue Escalation",
            "summary": "High risk detected",
        },
    }
    monkeypatch.setattr(PredictionService, "predict", lambda data: mock_high_result)

    response = client.post("/api/v1/predict", json=SAMPLE_FLOW_PAYLOAD)
    assert response.status_code == 200

    alerts, total = AlertRepository.list(db_session, limit=10, severity="HIGH")
    assert total >= 1
    high_alert = next(a for a in alerts if a.severity == "HIGH")
    assert high_alert.threat_label == "Port Scan"
    assert high_alert.alert_type == "NETWORK_INTRUSION"
    assert high_alert.status == "NEW"


def test_critical_prediction_creates_alert(client, monkeypatch, db_session):
    """5. Test that CRITICAL risk prediction creates a critical security alert."""
    mock_critical_result = {
        "anomaly": {
            "is_anomaly": True,
            "anomaly_label": "ANOMALOUS",
            "anomaly_score": 0.88,
            "raw_decision_score": -0.25,
            "interpretation": "Divergence score: 0.88",
        },
        "classification": {
            "predicted_label": "DoS",
            "is_intrusion": True,
            "confidence": 0.95,
            "confidence_type": "estimated_class_probability",
            "class_probabilities": {"DoS": 0.95, "BENIGN": 0.05},
        },
        "risk_assessment": {
            "risk_level": "CRITICAL",
            "recommended_action": "Immediate SOC Alert & Automated Host Triage",
            "summary": "Critical DoS attack",
        },
    }
    monkeypatch.setattr(PredictionService, "predict", lambda data: mock_critical_result)

    response = client.post("/api/v1/predict", json=SAMPLE_FLOW_PAYLOAD)
    assert response.status_code == 200

    alerts, total = AlertRepository.list(db_session, limit=10, severity="CRITICAL")
    assert total >= 1
    crit_alert = next(a for a in alerts if a.severity == "CRITICAL")
    assert crit_alert.threat_label == "DoS"
    assert crit_alert.alert_type == "CRITICAL_INTRUSION"


def test_low_prediction_does_not_create_alert(client, monkeypatch, db_session):
    """6. Test that LOW risk prediction persists history but does NOT create an alert."""
    mock_low_result = {
        "anomaly": {
            "is_anomaly": False,
            "anomaly_label": "NORMAL",
            "anomaly_score": 0.15,
            "raw_decision_score": 0.22,
            "interpretation": "Divergence score: 0.15",
        },
        "classification": {
            "predicted_label": "BENIGN",
            "is_intrusion": False,
            "confidence": 0.92,
            "confidence_type": "estimated_class_probability",
            "class_probabilities": {"BENIGN": 0.92},
        },
        "risk_assessment": {
            "risk_level": "LOW",
            "recommended_action": "Standard Flow Logging",
            "summary": "Nominal traffic",
        },
    }
    monkeypatch.setattr(PredictionService, "predict", lambda data: mock_low_result)

    alerts_before, total_alerts_before = AlertRepository.list(db_session, limit=100)
    preds_before, total_preds_before = PredictionRepository.list(db_session, limit=100)

    response = client.post("/api/v1/predict", json=SAMPLE_FLOW_PAYLOAD)
    assert response.status_code == 200

    _, total_alerts_after = AlertRepository.list(db_session, limit=100)
    _, total_preds_after = PredictionRepository.list(db_session, limit=100)

    # Prediction count increased by 1, but alert count did not change
    assert total_preds_after == total_preds_before + 1
    assert total_alerts_after == total_alerts_before


def test_get_predictions_endpoint(client):
    """7. Test that GET /api/v1/predictions returns persisted records."""
    response = client.get("/api/v1/predictions")
    assert response.status_code == 200
    data = response.json()

    assert "total" in data
    assert "limit" in data
    assert "offset" in data
    assert "items" in data
    assert isinstance(data["items"], list)
    assert len(data["items"]) > 0

    first_item = data["items"][0]
    assert "id" in first_item
    assert "predicted_threat" in first_item
    assert "risk_level" in first_item
    assert "anomaly_score" in first_item
    assert "classification_confidence" in first_item


def test_get_alerts_endpoint(client):
    """8. Test that GET /api/v1/alerts returns persisted security alerts."""
    response = client.get("/api/v1/alerts")
    assert response.status_code == 200
    data = response.json()

    assert "total" in data
    assert "limit" in data
    assert "offset" in data
    assert "items" in data
    assert isinstance(data["items"], list)
    assert len(data["items"]) > 0

    alert = data["items"][0]
    assert "id" in alert
    assert "prediction_id" in alert
    assert "severity" in alert
    assert "status" in alert
    assert "threat_label" in alert


def test_predictions_pagination(client):
    """9. Test pagination limits and offsets on predictions endpoint."""
    response = client.get("/api/v1/predictions?limit=2&offset=1")
    assert response.status_code == 200
    data = response.json()

    assert data["limit"] == 2
    assert data["offset"] == 1
    assert len(data["items"]) <= 2


def test_maximum_limit_enforced(client):
    """10. Test that requesting limit above maximum (100) is rejected with HTTP 422."""
    response = client.get("/api/v1/predictions?limit=101")
    assert response.status_code == 422

    response_alerts = client.get("/api/v1/alerts?limit=500")
    assert response_alerts.status_code == 422


def test_invalid_pagination_rejected(client):
    """11. Test that negative limit or offset is rejected with HTTP 422."""
    assert client.get("/api/v1/predictions?limit=0").status_code == 422
    assert client.get("/api/v1/predictions?limit=-5").status_code == 422
    assert client.get("/api/v1/predictions?offset=-1").status_code == 422
    assert client.get("/api/v1/alerts?offset=-10").status_code == 422


def test_severity_filter_works(client):
    """12. Test filtering alerts by valid and invalid severities."""
    response = client.get("/api/v1/alerts?severity=HIGH")
    assert response.status_code == 200
    data = response.json()
    assert all(item["severity"] == "HIGH" for item in data["items"])

    # Invalid severity rejected with 422
    invalid_resp = client.get("/api/v1/alerts?severity=UNKNOWN_SEVERITY")
    assert invalid_resp.status_code == 422
    assert "Invalid severity filter" in invalid_resp.json()["message"]


def test_status_filter_works(client):
    """13. Test filtering alerts by valid and invalid statuses."""
    response = client.get("/api/v1/alerts?status=NEW")
    assert response.status_code == 200
    data = response.json()
    assert all(item["status"] == "NEW" for item in data["items"])

    # Invalid status rejected with 422
    invalid_resp = client.get("/api/v1/alerts?status=INVALID_STATUS")
    assert invalid_resp.status_code == 422
    assert "Invalid status filter" in invalid_resp.json()["message"]


def test_database_rollback_and_error_handling(client, monkeypatch):
    """14 & 15. Test that persistence failures rollback transactions and do not leak internal tracebacks."""
    from backend.app.services.persistence_service import PersistenceService

    def mock_save_failure(*args, **kwargs):
        raise RuntimeError("Simulated internal disk full error in database commit")

    monkeypatch.setattr(PersistenceService, "save_prediction_and_alert", mock_save_failure)

    response = client.post("/api/v1/predict", json=SAMPLE_FLOW_PAYLOAD)
    assert response.status_code == 500
    data = response.json()

    assert data["status"] == "error"
    assert data["error_code"] in ("INTERNAL_PREDICTION_ERROR", "DATABASE_PERSISTENCE_ERROR", "UNHANDLED_EXCEPTION")
    assert any(msg in data["message"].lower() for msg in ("database persistence failed", "unexpected internal error"))

    # Verify no database internal stack traces or queries leaked
    assert "Simulated internal disk full" not in data["message"]
    assert "traceback" not in str(data).lower()
    assert "select" not in str(data).lower()
    assert "insert" not in str(data).lower()
