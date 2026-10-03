"""Unit, integration, and security tests for Phase 14 Real-Time SOC Incident Response Workflow."""

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
from backend.app.models.incident import IncidentRecord, IncidentNoteRecord
from backend.app.models.prediction import PredictionRecord
from backend.app.models.user import UserRecord
from backend.app.schemas.audit import AuditAction, AuditResourceType
from backend.app.schemas.incident import IncidentStatus
from backend.app.services.audit_service import AuditService
from backend.app.services.incident_service import IncidentService

# Setup isolated in-memory SQLite database
test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

TEST_USER_PASSWORD = "StrongSecureTestPassword!99"


@pytest.fixture(scope="module", autouse=True)
def setup_incident_test_database():
    """Create isolated test database schema and seed test operators."""
    Base.metadata.create_all(bind=test_engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    # Seed test operator accounts
    db = TestingSessionLocal()
    hashed_pwd = get_password_hash(TEST_USER_PASSWORD)

    admin_user = UserRecord(username="inc_admin", password_hash=hashed_pwd, role="ADMIN", is_active=True)
    analyst_user = UserRecord(username="inc_analyst", password_hash=hashed_pwd, role="ANALYST", is_active=True)
    inactive_analyst = UserRecord(username="inc_inactive", password_hash=hashed_pwd, role="ANALYST", is_active=False)
    viewer_user = UserRecord(username="inc_viewer", password_hash=hashed_pwd, role="VIEWER", is_active=True)

    db.add_all([admin_user, analyst_user, inactive_analyst, viewer_user])

    # Seed a sample prediction and alert
    prediction = PredictionRecord(
        timestamp=datetime.now(timezone.utc),
        anomaly_label="ANOMALY",
        anomaly_score=-0.45,
        raw_decision_score=-0.45,
        predicted_threat="DDoS-LOIC",
        intrusion_flag=True,
        classification_confidence=0.96,
        risk_level="CRITICAL",
        recommended_action="Block source IP",
        source_ip="198.51.100.44",
        destination_ip="10.0.0.1",
    )
    db.add(prediction)
    db.flush()

    alert = AlertRecord(
        timestamp=datetime.now(timezone.utc),
        prediction_id=prediction.id,
        alert_type="CRITICAL_INTRUSION",
        severity="CRITICAL",
        threat_label="DDoS-LOIC",
        anomaly_score=-0.45,
        confidence=0.96,
        source_ip="198.51.100.44",
        destination_ip="10.0.0.1",
        status="NEW",
        recommended_action="Isolate host immediately",
    )
    db.add(alert)

    db.commit()

    # Route audit logging to test database
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
    token = create_access_token(subject="1", username="inc_admin", role="ADMIN")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def analyst_headers():
    token = create_access_token(subject="2", username="inc_analyst", role="ANALYST")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def viewer_headers():
    token = create_access_token(subject="4", username="inc_viewer", role="VIEWER")
    return {"Authorization": f"Bearer {token}"}


# -------------------------------------------------------------------------
# 1. Incident Creation Tests
# -------------------------------------------------------------------------

def test_create_incident_from_alert(client, analyst_headers):
    """Analyst creates incident from an active alert; inherits severity, category, and source_ip."""
    response = client.post(
        "/api/v1/incidents",
        headers=analyst_headers,
        json={
            "title": "DDoS Volumetric Incursion Detected",
            "description": "High volume attack on web application",
            "alert_id": 1,
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["incident_key"].startswith("INC-")
    assert data["title"] == "DDoS Volumetric Incursion Detected"
    assert data["severity"] == "CRITICAL"
    assert data["category"] == "DDoS-LOIC"
    assert data["status"] == "OPEN"
    assert data["source_ip"] == "198.51.100.44"
    assert data["created_by"] == "inc_analyst"


def test_duplicate_active_incident_prevention(client, analyst_headers):
    """Creating another incident from the same alert while one is active returns 409 Conflict."""
    response = client.post(
        "/api/v1/incidents",
        headers=analyst_headers,
        json={
            "title": "Duplicate Incident Attempt",
            "description": "Should be rejected because incident already active",
            "alert_id": 1,
        },
    )
    assert response.status_code == 409
    err = response.json().get("message") or response.json().get("detail") or ""
    assert "already exists for alert" in err.lower()


def test_create_incident_from_prediction(client, admin_headers):
    """Admin creates incident directly from a prediction."""
    response = client.post(
        "/api/v1/incidents",
        headers=admin_headers,
        json={
            "title": "Suspicious Flow Investigation",
            "description": "Investigating high anomaly flow",
            "prediction_id": 1,
            "severity": "HIGH",
            "category": "Anomaly-Investigation",
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["incident_key"].startswith("INC-")
    assert data["severity"] == "HIGH"
    assert data["source_ip"] == "198.51.100.44"
    assert data["created_by"] == "inc_admin"


def test_create_incident_invalid_source_ids(client, analyst_headers):
    """Supplying non-existent alert_id or prediction_id returns 404."""
    resp1 = client.post(
        "/api/v1/incidents",
        headers=analyst_headers,
        json={"title": "Bad Alert", "alert_id": 99999},
    )
    assert resp1.status_code == 404

    resp2 = client.post(
        "/api/v1/incidents",
        headers=analyst_headers,
        json={"title": "Bad Pred", "prediction_id": 99999},
    )
    assert resp2.status_code == 404


# -------------------------------------------------------------------------
# 2. Status Lifecycle & State Machine Tests
# -------------------------------------------------------------------------

def test_incident_status_valid_lifecycle_transitions(client, analyst_headers):
    """Step through valid lifecycle: OPEN -> ACKNOWLEDGED -> INVESTIGATING -> CONTAINED -> RESOLVED."""
    # Create fresh incident
    create_resp = client.post(
        "/api/v1/incidents",
        headers=analyst_headers,
        json={"title": "Lifecycle Test Case", "severity": "MEDIUM", "category": "PortScan"},
    )
    assert create_resp.status_code == 201
    inc_id = create_resp.json()["id"]

    # 1. OPEN -> ACKNOWLEDGED
    r1 = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        headers=analyst_headers,
        json={"new_status": "ACKNOWLEDGED"},
    )
    assert r1.status_code == 200
    assert r1.json()["status"] == "ACKNOWLEDGED"
    assert r1.json()["acknowledged_at"] is not None

    # 2. ACKNOWLEDGED -> INVESTIGATING
    r2 = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        headers=analyst_headers,
        json={"new_status": "INVESTIGATING"},
    )
    assert r2.status_code == 200
    assert r2.json()["status"] == "INVESTIGATING"
    assert r2.json()["investigation_started_at"] is not None

    # 3. INVESTIGATING -> CONTAINED
    r3 = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        headers=analyst_headers,
        json={"new_status": "CONTAINED"},
    )
    assert r3.status_code == 200
    assert r3.json()["status"] == "CONTAINED"

    # 4. CONTAINED -> RESOLVED (requires resolution_summary)
    r4 = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        headers=analyst_headers,
        json={
            "new_status": "RESOLVED",
            "resolution_summary": "Malicious source IP was isolated on firewall and confirmed benign thereafter.",
        },
    )
    assert r4.status_code == 200
    assert r4.json()["status"] == "RESOLVED"
    assert r4.json()["resolved_at"] is not None
    assert "firewall" in r4.json()["resolution_summary"]


def test_direct_transition_to_resolved(client, analyst_headers):
    """Direct transitions from OPEN/ACKNOWLEDGED/INVESTIGATING to RESOLVED are allowed with summary."""
    create_resp = client.post(
        "/api/v1/incidents",
        headers=analyst_headers,
        json={"title": "Direct Resolve Test", "severity": "LOW", "category": "FalsePositive"},
    )
    inc_id = create_resp.json()["id"]

    # Direct OPEN -> RESOLVED
    res = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        headers=analyst_headers,
        json={
            "new_status": "RESOLVED",
            "resolution_summary": "Verified as benign scheduled administrative vulnerability scan.",
        },
    )
    assert res.status_code == 200
    assert res.json()["status"] == "RESOLVED"


def test_invalid_status_transitions_return_409(client, analyst_headers):
    """Invalid transitions return 409 Conflict."""
    create_resp = client.post(
        "/api/v1/incidents",
        headers=analyst_headers,
        json={"title": "Conflict State Test", "severity": "LOW"},
    )
    inc_id = create_resp.json()["id"]

    # 1. OPEN -> CONTAINED is not allowed directly
    res1 = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        headers=analyst_headers,
        json={"new_status": "CONTAINED"},
    )
    assert res1.status_code == 409

    # 2. Resolve it
    client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        headers=analyst_headers,
        json={"new_status": "RESOLVED", "resolution_summary": "Resolution completed."},
    )

    # 3. Terminal state RESOLVED -> OPEN or INVESTIGATING is not allowed
    res2 = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        headers=analyst_headers,
        json={"new_status": "INVESTIGATING"},
    )
    assert res2.status_code == 409


def test_resolve_without_summary_rejected(client, analyst_headers):
    """Attempting to resolve an incident without a resolution_summary returns 422 Unprocessable Entity."""
    create_resp = client.post(
        "/api/v1/incidents",
        headers=analyst_headers,
        json={"title": "No Summary Test", "severity": "LOW"},
    )
    inc_id = create_resp.json()["id"]

    res = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        headers=analyst_headers,
        json={"new_status": "RESOLVED"},
    )
    assert res.status_code == 422


# -------------------------------------------------------------------------
# 3. Incident Assignment Tests
# -------------------------------------------------------------------------

def test_assign_incident_to_valid_analyst(client, admin_headers):
    """Admin assigns incident to active analyst."""
    create_resp = client.post(
        "/api/v1/incidents",
        headers=admin_headers,
        json={"title": "Assignment Test Case", "severity": "HIGH"},
    )
    inc_id = create_resp.json()["id"]

    res = client.patch(
        f"/api/v1/incidents/{inc_id}/assign",
        headers=admin_headers,
        json={"assigned_to": "inc_analyst"},
    )
    assert res.status_code == 200
    assert res.json()["assigned_to"] == "inc_analyst"


def test_assign_to_inactive_user_rejected(client, admin_headers):
    """Assigning to an inactive user returns 422."""
    create_resp = client.post(
        "/api/v1/incidents",
        headers=admin_headers,
        json={"title": "Inactive Assign Test", "severity": "LOW"},
    )
    inc_id = create_resp.json()["id"]

    res = client.patch(
        f"/api/v1/incidents/{inc_id}/assign",
        headers=admin_headers,
        json={"assigned_to": "inc_inactive"},
    )
    assert res.status_code == 422
    err = res.json().get("message") or res.json().get("detail") or ""
    assert "inactive" in err.lower()


def test_assign_to_viewer_rejected(client, admin_headers):
    """Assigning to a user with VIEWER role returns 422."""
    create_resp = client.post(
        "/api/v1/incidents",
        headers=admin_headers,
        json={"title": "Viewer Assign Test", "severity": "LOW"},
    )
    inc_id = create_resp.json()["id"]

    res = client.patch(
        f"/api/v1/incidents/{inc_id}/assign",
        headers=admin_headers,
        json={"assigned_to": "inc_viewer"},
    )
    assert res.status_code == 422
    err = res.json().get("message") or res.json().get("detail") or ""
    assert "viewer role" in err.lower()


def test_assign_to_nonexistent_user_rejected(client, admin_headers):
    """Assigning to non-existent username returns 404."""
    create_resp = client.post(
        "/api/v1/incidents",
        headers=admin_headers,
        json={"title": "Nonexistent Assign Test"},
    )
    inc_id = create_resp.json()["id"]

    res = client.patch(
        f"/api/v1/incidents/{inc_id}/assign",
        headers=admin_headers,
        json={"assigned_to": "ghost_operator"},
    )
    assert res.status_code == 404


# -------------------------------------------------------------------------
# 4. Incident Notes Tests
# -------------------------------------------------------------------------

def test_add_and_retrieve_incident_notes(client, analyst_headers):
    """Add analyst notes and retrieve them in chronological order."""
    create_resp = client.post(
        "/api/v1/incidents",
        headers=analyst_headers,
        json={"title": "Notes Test Case"},
    )
    inc_id = create_resp.json()["id"]

    # Add Note 1
    n1 = client.post(
        f"/api/v1/incidents/{inc_id}/notes",
        headers=analyst_headers,
        json={"note": "Initial triage: confirmed high packet rate from external ASN."},
    )
    assert n1.status_code == 201
    assert n1.json()["author"] == "inc_analyst"

    # Add Note 2
    n2 = client.post(
        f"/api/v1/incidents/{inc_id}/notes",
        headers=analyst_headers,
        json={"note": "Enforced upstream rate-limit rule on perimeter router."},
    )
    assert n2.status_code == 201

    # Retrieve Notes
    get_res = client.get(
        f"/api/v1/incidents/{inc_id}/notes",
        headers=analyst_headers,
    )
    assert get_res.status_code == 200
    notes = get_res.json()
    assert len(notes) == 2
    assert any("triage" in n["note"] for n in notes)
    assert any("perimeter router" in n["note"] for n in notes)


def test_empty_note_rejected(client, analyst_headers):
    """Empty or whitespace-only note returns 422."""
    create_resp = client.post(
        "/api/v1/incidents",
        headers=analyst_headers,
        json={"title": "Empty Note Test"},
    )
    inc_id = create_resp.json()["id"]

    res = client.post(
        f"/api/v1/incidents/{inc_id}/notes",
        headers=analyst_headers,
        json={"note": "    "},
    )
    assert res.status_code == 422


# -------------------------------------------------------------------------
# 5. RBAC & Access Control Tests
# -------------------------------------------------------------------------

def test_viewer_forbidden_to_mutate_incidents(client, viewer_headers, analyst_headers):
    """VIEWER role is read-only and cannot create, assign, change status, or add notes."""
    # First create an incident as analyst
    create_resp = client.post(
        "/api/v1/incidents",
        headers=analyst_headers,
        json={"title": "RBAC Protection Case"},
    )
    inc_id = create_resp.json()["id"]

    # Viewer cannot create
    r_create = client.post(
        "/api/v1/incidents",
        headers=viewer_headers,
        json={"title": "Unauthorized Incident"},
    )
    assert r_create.status_code == 403

    # Viewer cannot assign
    r_assign = client.patch(
        f"/api/v1/incidents/{inc_id}/assign",
        headers=viewer_headers,
        json={"assigned_to": "inc_analyst"},
    )
    assert r_assign.status_code == 403

    # Viewer cannot change status
    r_status = client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        headers=viewer_headers,
        json={"new_status": "ACKNOWLEDGED"},
    )
    assert r_status.status_code == 403

    # Viewer cannot add note
    r_note = client.post(
        f"/api/v1/incidents/{inc_id}/notes",
        headers=viewer_headers,
        json={"note": "Unauthorized note from viewer"},
    )
    assert r_note.status_code == 403


def test_viewer_allowed_to_read_incidents(client, viewer_headers, analyst_headers):
    """VIEWER role can read incidents list, incident detail, notes, and timeline."""
    create_resp = client.post(
        "/api/v1/incidents",
        headers=analyst_headers,
        json={"title": "Read Test Case"},
    )
    inc_id = create_resp.json()["id"]

    # 1. List
    r_list = client.get("/api/v1/incidents", headers=viewer_headers)
    assert r_list.status_code == 200
    assert r_list.json()["total"] >= 1

    # 2. Detail
    r_detail = client.get(f"/api/v1/incidents/{inc_id}", headers=viewer_headers)
    assert r_detail.status_code == 200
    assert r_detail.json()["id"] == inc_id

    # 3. Notes
    r_notes = client.get(f"/api/v1/incidents/{inc_id}/notes", headers=viewer_headers)
    assert r_notes.status_code == 200

    # 4. Timeline
    r_tl = client.get(f"/api/v1/incidents/{inc_id}/timeline", headers=viewer_headers)
    assert r_tl.status_code == 200


def test_unauthenticated_requests_rejected(client):
    """Unauthenticated requests without JWT header return 401."""
    assert client.get("/api/v1/incidents").status_code == 401
    assert client.post("/api/v1/incidents", json={"title": "No Auth"}).status_code == 401
    assert client.get("/api/v1/incidents/1").status_code == 401
    assert client.get("/api/v1/incidents/summary").status_code == 401


# -------------------------------------------------------------------------
# 6. Timeline & Audit Integration Tests
# -------------------------------------------------------------------------

def test_incident_timeline_assembly(client, analyst_headers):
    """Timeline accurately records creation, assignment, status change, and notes."""
    # 1. Create
    c_res = client.post(
        "/api/v1/incidents",
        headers=analyst_headers,
        json={"title": "Timeline Test Incident", "severity": "HIGH"},
    )
    inc_id = c_res.json()["id"]

    # 2. Assign
    client.patch(
        f"/api/v1/incidents/{inc_id}/assign",
        headers=analyst_headers,
        json={"assigned_to": "inc_analyst"},
    )

    # 3. Status Change
    client.patch(
        f"/api/v1/incidents/{inc_id}/status",
        headers=analyst_headers,
        json={"new_status": "ACKNOWLEDGED"},
    )

    # 4. Note
    client.post(
        f"/api/v1/incidents/{inc_id}/notes",
        headers=analyst_headers,
        json={"note": "Initial triage confirmed threat pattern."},
    )

    # 5. Fetch timeline
    tl_res = client.get(f"/api/v1/incidents/{inc_id}/timeline", headers=analyst_headers)
    assert tl_res.status_code == 200
    events = tl_res.json()["events"]
    assert len(events) >= 4

    event_types = [e["event_type"] for e in events]
    assert "INCIDENT_CREATED" in event_types
    assert "INCIDENT_ASSIGNED" in event_types
    assert "INCIDENT_NOTE_ADDED" in event_types


def test_audit_logs_emitted_for_incident_operations():
    """Verify that audit service logged structured events with no credential leakage."""
    db = TestingSessionLocal()
    try:
        incident_audits = (
            db.query(AuditLogRecord)
            .filter(AuditLogRecord.resource_type == AuditResourceType.INCIDENT)
            .all()
        )
        assert len(incident_audits) > 0

        actions = {a.action for a in incident_audits}
        assert AuditAction.INCIDENT_CREATED in actions

        # Verify no JWT / password / token in details
        for record in incident_audits:
            details_str = str(record.details or {})
            assert "Bearer" not in details_str
            assert "password" not in details_str.lower()
    finally:
        db.close()


def test_incident_summary_kpi_metrics(client, analyst_headers):
    """GET /api/v1/incidents/summary returns accurate aggregated metrics."""
    res = client.get("/api/v1/incidents/summary", headers=analyst_headers)
    assert res.status_code == 200
    data = res.json()
    assert "total_incidents" in data
    assert "open_incidents" in data
    assert "investigating_incidents" in data
    assert "critical_incidents" in data
    assert "high_incidents" in data
    assert "resolved_incidents" in data
    assert "recently_resolved" in data
    assert data["total_incidents"] >= 1
