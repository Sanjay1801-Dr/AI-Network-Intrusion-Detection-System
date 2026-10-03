"""Unit and integration tests for Phase 12 Advanced Security Monitoring & Audit Logging."""

import asyncio
from datetime import datetime, timezone
import json
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
from backend.app.models.audit import AuditLogRecord
from backend.app.models.prediction import PredictionRecord
from backend.app.models.user import UserRecord
from backend.app.schemas.audit import AuditAction, AuditOutcome, AuditResourceType
from backend.app.services.audit_service import AuditService, sanitize_audit_details
from backend.app.services.prediction_service import PredictionService

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
}


@pytest.fixture(scope="module", autouse=True)
def setup_audit_test_database():
    """Create isolated test database schema and seed test operators."""
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

    admin_user = UserRecord(username="audit_admin", password_hash=hashed_pwd, role="ADMIN", is_active=True)
    analyst_user = UserRecord(username="audit_analyst", password_hash=hashed_pwd, role="ANALYST", is_active=True)
    viewer_user = UserRecord(username="audit_viewer", password_hash=hashed_pwd, role="VIEWER", is_active=True)

    db.add_all([admin_user, analyst_user, viewer_user])
    db.commit()
    db.refresh(admin_user)
    db.refresh(analyst_user)
    db.refresh(viewer_user)
    # Set AuditService session factory to test engine session
    from backend.app.db.session import SessionLocal
    AuditService.session_factory = TestingSessionLocal

    yield

    AuditService.session_factory = SessionLocal
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)


def get_token_for(username: str, role: str, user_id: int) -> str:
    """Helper to generate signed test Bearer token."""
    return create_access_token(subject=user_id, username=username, role=role)


# ==============================================================================
# 1. Audit Persistence & Sanitization Unit Tests
# ==============================================================================

def test_audit_record_creation_and_fields():
    """Verify AuditLogRecord model instantiation, field persistence, and default values."""
    db = TestingSessionLocal()
    record = AuditLogRecord(
        action=AuditAction.SECURITY_ERROR.value,
        resource_type=AuditResourceType.SYSTEM.value,
        outcome=AuditOutcome.FAILURE.value,
        username="test_operator",
        user_role="ADMIN",
        resource_id="res-101",
        ip_address="192.168.1.100",
        request_method="POST",
        request_path="/api/v1/test",
        status_code=500,
        details=json.dumps({"info": "Diagnostic error"}),
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    assert record.id is not None
    assert record.timestamp is not None
    assert record.action == AuditAction.SECURITY_ERROR.value
    assert record.outcome == AuditOutcome.FAILURE.value
    assert record.username == "test_operator"
    assert record.resource_id == "res-101"
    db.close()


def test_sanitize_audit_details_scrubs_secrets():
    """Verify recursive details scrubber strips password, token, and secret keys."""
    raw_details = {
        "operation": "user_auth",
        "password": "RawSuperSecretPassword",
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy",
        "nested": {
            "secret_key": "my_top_secret",
            "safe_attribute": 42,
        },
        "allowed_info": "benign_data",
    }

    sanitized_str = sanitize_audit_details(raw_details)
    assert sanitized_str is not None
    parsed = json.loads(sanitized_str)

    assert parsed["password"] == "[REDACTED]"
    assert parsed["access_token"] == "[REDACTED]"
    assert parsed["nested"]["secret_key"] == "[REDACTED]"
    assert parsed["nested"]["safe_attribute"] == 42
    assert parsed["allowed_info"] == "benign_data"


def test_sanitize_audit_details_rejects_bearer_string():
    """Verify string details containing Bearer token or passwords are masked."""
    str_detail = "Authorization Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    sanitized = sanitize_audit_details(str_detail)
    assert "Bearer" not in sanitized
    assert "Sanitized" in sanitized


# ==============================================================================
# 2. Authentication Auditing Tests
# ==============================================================================

def test_successful_login_creates_login_success():
    """Verify valid login creates a LOGIN_SUCCESS audit log."""
    db = TestingSessionLocal()
    initial_count = db.query(AuditLogRecord).filter(AuditLogRecord.action == AuditAction.LOGIN_SUCCESS.value).count()
    db.close()

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/auth/login",
            json={"username": "audit_admin", "password": TEST_USER_PASSWORD},
        )
        assert res.status_code == 200

    db = TestingSessionLocal()
    new_count = db.query(AuditLogRecord).filter(AuditLogRecord.action == AuditAction.LOGIN_SUCCESS.value).count()
    assert new_count == initial_count + 1

    latest_record = (
        db.query(AuditLogRecord)
        .filter(AuditLogRecord.action == AuditAction.LOGIN_SUCCESS.value)
        .order_by(AuditLogRecord.id.desc())
        .first()
    )
    assert latest_record.username == "audit_admin"
    assert latest_record.outcome == AuditOutcome.SUCCESS.value
    assert latest_record.status_code == 200
    assert TEST_USER_PASSWORD not in (latest_record.details or "")
    db.close()


def test_failed_login_creates_login_failure():
    """Verify invalid password creates a LOGIN_FAILURE audit log."""
    db = TestingSessionLocal()
    initial_count = db.query(AuditLogRecord).filter(AuditLogRecord.action == AuditAction.LOGIN_FAILURE.value).count()
    db.close()

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/auth/login",
            json={"username": "audit_admin", "password": "WrongPasswordAttempt!"},
        )
        assert res.status_code == 401

    db = TestingSessionLocal()
    new_count = db.query(AuditLogRecord).filter(AuditLogRecord.action == AuditAction.LOGIN_FAILURE.value).count()
    assert new_count == initial_count + 1

    latest_record = (
        db.query(AuditLogRecord)
        .filter(AuditLogRecord.action == AuditAction.LOGIN_FAILURE.value)
        .order_by(AuditLogRecord.id.desc())
        .first()
    )
    assert latest_record.username == "audit_admin"
    assert latest_record.outcome == AuditOutcome.FAILURE.value
    assert latest_record.status_code == 401
    assert "WrongPasswordAttempt!" not in (latest_record.details or "")
    db.close()


def test_logout_creates_logout_event():
    """Verify operator logout creates a LOGOUT audit log."""
    token = get_token_for(username="audit_admin", role="ADMIN", user_id=1)

    db = TestingSessionLocal()
    initial_count = db.query(AuditLogRecord).filter(AuditLogRecord.action == AuditAction.LOGOUT.value).count()
    db.close()

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res.status_code == 200

    db = TestingSessionLocal()
    new_count = db.query(AuditLogRecord).filter(AuditLogRecord.action == AuditAction.LOGOUT.value).count()
    assert new_count == initial_count + 1

    latest = db.query(AuditLogRecord).filter(AuditLogRecord.action == AuditAction.LOGOUT.value).order_by(AuditLogRecord.id.desc()).first()
    assert latest.username == "audit_admin"
    assert latest.outcome == AuditOutcome.SUCCESS.value
    db.close()


# ==============================================================================
# 3. RBAC & Authorization Auditing Tests
# ==============================================================================

def test_forbidden_viewer_mutation_creates_access_denied():
    """Verify VIEWER role attempting prediction creates ACCESS_DENIED audit log."""
    viewer_token = get_token_for(username="audit_viewer", role="VIEWER", user_id=3)

    db = TestingSessionLocal()
    initial_denied = db.query(AuditLogRecord).filter(AuditLogRecord.action == AuditAction.ACCESS_DENIED.value).count()
    db.close()

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/predict",
            headers={"Authorization": f"Bearer {viewer_token}"},
            json=SAMPLE_BENIGN_FLOW,
        )
        assert res.status_code == 403

    db = TestingSessionLocal()
    new_denied = db.query(AuditLogRecord).filter(AuditLogRecord.action == AuditAction.ACCESS_DENIED.value).count()
    assert new_denied == initial_denied + 1

    latest = db.query(AuditLogRecord).filter(AuditLogRecord.action == AuditAction.ACCESS_DENIED.value).order_by(AuditLogRecord.id.desc()).first()
    assert latest.username == "audit_viewer"
    assert latest.user_role == "VIEWER"
    assert latest.outcome == AuditOutcome.DENIED.value
    assert latest.status_code == 403
    assert latest.request_path == "/api/v1/predict"
    db.close()


def test_authorized_analyst_operation_does_not_create_access_denied():
    """Verify authorized ANALYST role succeeds without generating ACCESS_DENIED."""
    analyst_token = get_token_for(username="audit_analyst", role="ANALYST", user_id=2)

    db = TestingSessionLocal()
    initial_denied = db.query(AuditLogRecord).filter(AuditLogRecord.action == AuditAction.ACCESS_DENIED.value).count()
    db.close()

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/predict",
            headers={"Authorization": f"Bearer {analyst_token}"},
            json=SAMPLE_BENIGN_FLOW,
        )
        assert res.status_code == 200

    db = TestingSessionLocal()
    new_denied = db.query(AuditLogRecord).filter(AuditLogRecord.action == AuditAction.ACCESS_DENIED.value).count()
    assert new_denied == initial_denied
    db.close()


# ==============================================================================
# 4. Prediction Auditing Tests
# ==============================================================================

def test_successful_prediction_creates_prediction_created_audit():
    """Verify successful prediction creates PREDICTION_CREATED audit record with safe metadata."""
    analyst_token = get_token_for(username="audit_analyst", role="ANALYST", user_id=2)

    with TestClient(app) as client:
        res = client.post(
            "/api/v1/predict",
            headers={"Authorization": f"Bearer {analyst_token}"},
            json=SAMPLE_BENIGN_FLOW,
        )
        assert res.status_code == 200

    db = TestingSessionLocal()
    latest_pred_audit = (
        db.query(AuditLogRecord)
        .filter(AuditLogRecord.action == AuditAction.PREDICTION_CREATED.value)
        .order_by(AuditLogRecord.id.desc())
        .first()
    )

    assert latest_pred_audit is not None
    assert latest_pred_audit.username == "audit_analyst"
    assert latest_pred_audit.outcome == AuditOutcome.SUCCESS.value
    assert latest_pred_audit.resource_type == AuditResourceType.PREDICTION.value
    assert latest_pred_audit.resource_id is not None

    # Full network flow payload must NOT be in audit details
    details = json.loads(latest_pred_audit.details)
    assert "threat_category" in details
    assert "severity" in details
    assert "Flow Duration" not in details
    assert "Destination Port" not in details
    db.close()


# ==============================================================================
# 5. Alert Lifecycle Auditing Tests
# ==============================================================================

def test_alert_lifecycle_creates_audit_records():
    """Verify alert acknowledgement and resolution create corresponding audit logs."""
    analyst_token = get_token_for(username="audit_analyst", role="ANALYST", user_id=2)

    # Seed an alert directly in DB
    db = TestingSessionLocal()
    alert = AlertRecord(
        alert_type="NETWORK_INTRUSION",
        severity="HIGH",
        threat_label="DoS",
        anomaly_score=0.88,
        confidence=0.92,
        status="NEW",
        recommended_action="Block Source IP",
        created_at=datetime.now(timezone.utc),
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    alert_id = alert.id
    db.close()

    with TestClient(app) as client:
        # Acknowledge
        ack_res = client.patch(
            f"/api/v1/alerts/{alert_id}/acknowledge",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert ack_res.status_code == 200

        # Resolve
        res_res = client.patch(
            f"/api/v1/alerts/{alert_id}/resolve",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert res_res.status_code == 200

    db = TestingSessionLocal()
    ack_audit = (
        db.query(AuditLogRecord)
        .filter(
            AuditLogRecord.action == AuditAction.ALERT_ACKNOWLEDGED.value,
            AuditLogRecord.resource_id == str(alert_id),
        )
        .first()
    )
    assert ack_audit is not None
    assert ack_audit.username == "audit_analyst"
    assert ack_audit.outcome == AuditOutcome.SUCCESS.value
    ack_details = json.loads(ack_audit.details)
    assert ack_details["previous_status"] == "NEW"
    assert ack_details["new_status"] == "ACKNOWLEDGED"

    res_audit = (
        db.query(AuditLogRecord)
        .filter(
            AuditLogRecord.action == AuditAction.ALERT_RESOLVED.value,
            AuditLogRecord.resource_id == str(alert_id),
        )
        .first()
    )
    assert res_audit is not None
    assert res_audit.username == "audit_analyst"
    assert res_audit.outcome == AuditOutcome.SUCCESS.value
    res_details = json.loads(res_audit.details)
    assert res_details["previous_status"] == "ACKNOWLEDGED"
    assert res_details["new_status"] == "RESOLVED"
    db.close()


# ==============================================================================
# 6. WebSocket Auditing Tests
# ==============================================================================

def test_websocket_successful_handshake_creates_audit_record():
    """Verify valid WebSocket authentication handshake creates WEBSOCKET_AUTH_SUCCESS."""
    admin_token = get_token_for(username="audit_admin", role="ADMIN", user_id=1)

    db = TestingSessionLocal()
    initial_count = db.query(AuditLogRecord).filter(AuditLogRecord.action == AuditAction.WEBSOCKET_AUTH_SUCCESS.value).count()
    db.close()

    with TestClient(app) as client:
        with client.websocket_connect("/api/v1/ws/monitor") as ws:
            ws.send_text(json.dumps({"type": "auth", "token": admin_token}))
            established = json.loads(ws.receive_text())
            assert established.get("event_type") == "connection_established"

    db = TestingSessionLocal()
    new_count = db.query(AuditLogRecord).filter(AuditLogRecord.action == AuditAction.WEBSOCKET_AUTH_SUCCESS.value).count()
    assert new_count == initial_count + 1

    latest = (
        db.query(AuditLogRecord)
        .filter(AuditLogRecord.action == AuditAction.WEBSOCKET_AUTH_SUCCESS.value)
        .order_by(AuditLogRecord.id.desc())
        .first()
    )
    assert latest.username == "audit_admin"
    assert latest.outcome == AuditOutcome.SUCCESS.value
    assert latest.status_code == 101
    db.close()


def test_websocket_missing_handshake_creates_audit_failure():
    """Verify invalid or missing WebSocket handshake creates WEBSOCKET_AUTH_FAILURE."""
    db = TestingSessionLocal()
    initial_fail = db.query(AuditLogRecord).filter(AuditLogRecord.action == AuditAction.WEBSOCKET_AUTH_FAILURE.value).count()
    db.close()

    with TestClient(app) as client:
        try:
            with client.websocket_connect("/api/v1/ws/monitor") as ws:
                ws.send_text(json.dumps({"type": "invalid_type"}))
                ws.receive_text()
        except Exception:
            pass

    db = TestingSessionLocal()
    new_fail = db.query(AuditLogRecord).filter(AuditLogRecord.action == AuditAction.WEBSOCKET_AUTH_FAILURE.value).count()
    assert new_fail >= initial_fail + 1
    db.close()


# ==============================================================================
# 7. Rate Limiting Auditing Tests
# ==============================================================================

def test_rate_limit_exceeded_creates_audit_record():
    """Verify HTTP 429 response creates a RATE_LIMIT_EXCEEDED audit record."""
    db = TestingSessionLocal()
    initial_rate_logs = db.query(AuditLogRecord).filter(AuditLogRecord.action == AuditAction.RATE_LIMIT_EXCEEDED.value).count()
    db.close()

    # Trigger rate limiter on login
    with TestClient(app) as client:
        limit_str = settings.RATE_LIMIT_LOGIN.split("/")[0]
        limit_count = int(limit_str) + 5
        hit_429 = False
        for _ in range(limit_count):
            resp = client.post(
                "/api/v1/auth/login",
                json={"username": "throttle_user", "password": "wrong_pwd_value"},
            )
            if resp.status_code == 429:
                hit_429 = True
                break

        assert hit_429 is True

    db = TestingSessionLocal()
    new_rate_logs = db.query(AuditLogRecord).filter(AuditLogRecord.action == AuditAction.RATE_LIMIT_EXCEEDED.value).count()
    assert new_rate_logs > initial_rate_logs

    latest = (
        db.query(AuditLogRecord)
        .filter(AuditLogRecord.action == AuditAction.RATE_LIMIT_EXCEEDED.value)
        .order_by(AuditLogRecord.id.desc())
        .first()
    )
    assert latest.status_code == 429
    assert latest.outcome == AuditOutcome.DENIED.value
    db.close()


# ==============================================================================
# 8. Strict Security & Privacy Invariant Tests
# ==============================================================================

def test_audit_records_never_leak_secrets():
    """Verify that NO audit log contains passwords, authorization headers, or secrets."""
    db = TestingSessionLocal()
    all_logs = db.query(AuditLogRecord).all()
    assert len(all_logs) > 0

    for log in all_logs:
        details_text = str(log.details or "").lower()

        # Invariant checks
        assert TEST_USER_PASSWORD.lower() not in details_text
        assert "bearer " not in details_text
        assert "authorization" not in details_text
        assert "password_hash" not in details_text
        assert "client_secret" not in details_text

    db.close()


# ==============================================================================
# 9. Audit API Endpoints Tests
# ==============================================================================

def test_get_audit_logs_unauthenticated_rejected():
    """Verify unauthenticated access to /api/v1/audit-logs returns HTTP 401."""
    with TestClient(app) as client:
        res = client.get("/api/v1/audit-logs")
        assert res.status_code == 401


def test_get_audit_logs_authenticated_with_pagination():
    """Verify authenticated operators can query paginated audit logs."""
    analyst_token = get_token_for(username="audit_analyst", role="ANALYST", user_id=2)

    with TestClient(app) as client:
        res = client.get(
            "/api/v1/audit-logs?limit=10&offset=0",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert res.status_code == 200
        data = res.json()
        assert "total" in data
        assert "limit" in data
        assert data["limit"] == 10
        assert "items" in data
        assert isinstance(data["items"], list)
        assert len(data["items"]) <= 10


def test_get_audit_logs_newest_first_ordering():
    """Verify audit log records are ordered chronologically newest-first."""
    admin_token = get_token_for(username="audit_admin", role="ADMIN", user_id=1)

    with TestClient(app) as client:
        res = client.get(
            "/api/v1/audit-logs?limit=50",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert res.status_code == 200
        items = res.json()["items"]
        if len(items) >= 2:
            for i in range(len(items) - 1):
                t1 = datetime.fromisoformat(items[i]["timestamp"])
                t2 = datetime.fromisoformat(items[i + 1]["timestamp"])
                assert t1 >= t2


def test_get_audit_logs_filters():
    """Verify filtering by action, outcome, and resource type."""
    admin_token = get_token_for(username="audit_admin", role="ADMIN", user_id=1)

    with TestClient(app) as client:
        res = client.get(
            "/api/v1/audit-logs?action=LOGIN_SUCCESS",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert res.status_code == 200
        for item in res.json()["items"]:
            assert item["action"] == "LOGIN_SUCCESS"

        res_outcome = client.get(
            "/api/v1/audit-logs?outcome=DENIED",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert res_outcome.status_code == 200
        for item in res_outcome.json()["items"]:
            assert item["outcome"] == "DENIED"


def test_get_security_summary_endpoint():
    """Verify /api/v1/audit-logs/summary returns telemetry counter numbers."""
    admin_token = get_token_for(username="audit_admin", role="ADMIN", user_id=1)

    with TestClient(app) as client:
        res = client.get(
            "/api/v1/audit-logs/summary",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert res.status_code == 200
        data = res.json()
        assert "total_events" in data
        assert "failed_logins" in data
        assert "access_denied" in data
        assert "rate_limit_exceeded" in data
        assert isinstance(data["total_events"], int)
        assert data["total_events"] > 0
