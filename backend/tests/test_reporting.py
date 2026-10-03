"""Unit, integration, and security tests for Phase 15 Automated Security Reporting & Evidence Export."""

from datetime import datetime, timedelta, timezone
import io
import zipfile
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
from backend.app.services.audit_service import AuditService

# Setup isolated in-memory SQLite database
test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

TEST_USER_PASSWORD = "StrongSecureTestPassword!99"


@pytest.fixture(scope="module", autouse=True)
def setup_reporting_test_database():
    """Create isolated test database schema, seed test operators and operational datasets."""
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

    admin_user = UserRecord(username="rep_admin", password_hash=hashed_pwd, role="ADMIN", is_active=True)
    analyst_user = UserRecord(username="rep_analyst", password_hash=hashed_pwd, role="ANALYST", is_active=True)
    viewer_user = UserRecord(username="rep_viewer", password_hash=hashed_pwd, role="VIEWER", is_active=True)

    db.add_all([admin_user, analyst_user, viewer_user])
    db.flush()

    now = datetime.now(timezone.utc)

    # Seed Predictions
    pred1 = PredictionRecord(
        timestamp=now - timedelta(hours=2),
        anomaly_label="ANOMALY",
        anomaly_score=-0.65,
        raw_decision_score=-0.65,
        predicted_threat="DDoS-LOIC",
        intrusion_flag=True,
        classification_confidence=0.98,
        risk_level="CRITICAL",
        recommended_action="Block source IP",
        source_ip="198.51.100.77",
        destination_ip="10.0.0.5",
        destination_port=80,
        protocol="6",
    )
    pred2 = PredictionRecord(
        timestamp=now - timedelta(hours=5),
        anomaly_label="NORMAL",
        anomaly_score=0.35,
        raw_decision_score=0.35,
        predicted_threat="BENIGN",
        intrusion_flag=False,
        classification_confidence=0.99,
        risk_level="LOW",
        recommended_action="Permit flow",
        source_ip="192.168.1.100",
        destination_ip="10.0.0.1",
        destination_port=443,
        protocol="6",
    )
    db.add_all([pred1, pred2])
    db.flush()

    # Seed Alert
    alert1 = AlertRecord(
        timestamp=now - timedelta(hours=2),
        prediction_id=pred1.id,
        alert_type="CRITICAL_INTRUSION",
        severity="CRITICAL",
        threat_label="DDoS-LOIC",
        anomaly_score=-0.65,
        confidence=0.98,
        source_ip="198.51.100.77",
        destination_ip="10.0.0.5",
        status="ACKNOWLEDGED",
        recommended_action="Apply rate limit rule",
        acknowledged_at=now - timedelta(hours=1, minutes=45),
    )
    db.add(alert1)
    db.flush()

    # Seed Incident
    inc1 = IncidentRecord(
        incident_key="INC-2026-000001",
        title="DDoS Attack Campaign Incursion",
        description="High volume SYN flood targeting perimeter web application",
        severity="CRITICAL",
        status="INVESTIGATING",
        category="DDoS-LOIC",
        source_ip="198.51.100.77",
        assigned_to="rep_analyst",
        created_by="rep_admin",
        created_at=now - timedelta(hours=2),
        updated_at=now - timedelta(hours=1),
        acknowledged_at=now - timedelta(hours=1, minutes=50),
        investigation_started_at=now - timedelta(hours=1, minutes=40),
    )
    inc1.alerts.append(alert1)
    inc1.predictions.append(pred1)
    db.add(inc1)
    db.flush()

    # Seed Incident Note
    note1 = IncidentNoteRecord(
        incident_id=inc1.id,
        author="rep_analyst",
        note="Perimeter mitigation rule applied; attack traffic dropped at border router.",
        created_at=now - timedelta(hours=1, minutes=30),
        updated_at=now - timedelta(hours=1, minutes=30),
    )
    db.add(note1)

    # Seed Audit Log
    audit1 = AuditLogRecord(
        timestamp=now - timedelta(hours=2),
        username="rep_admin",
        user_role="ADMIN",
        action="INCIDENT_CREATED",
        resource_type="INCIDENT",
        resource_id=str(inc1.id),
        outcome="SUCCESS",
        ip_address="127.0.0.1",
        request_method="POST",
        request_path="/api/v1/incidents",
        status_code=201,
        details='{"incident_id": 1, "key": "INC-2026-000001"}',
    )
    db.add(audit1)

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
    token = create_access_token(subject="1", username="rep_admin", role="ADMIN")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def analyst_headers():
    token = create_access_token(subject="2", username="rep_analyst", role="ANALYST")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def viewer_headers():
    token = create_access_token(subject="3", username="rep_viewer", role="VIEWER")
    return {"Authorization": f"Bearer {token}"}


# -------------------------------------------------------------------------
# 1. Security Report Generation Tests
# -------------------------------------------------------------------------

def test_security_report_json_default_24h(client, analyst_headers):
    """Generate default JSON security assessment report."""
    response = client.get("/api/v1/reports/security", headers=analyst_headers)
    assert response.status_code == 200
    data = response.json()

    assert data["report_title"] == "NIDS SOC Operational Security & Threat Assessment Report"
    assert "time_range" in data
    assert "executive_summary" in data

    ex = data["executive_summary"]
    assert ex["total_predictions"] >= 2
    assert ex["total_threats"] >= 1
    assert ex["total_alerts"] >= 1
    assert ex["total_incidents"] >= 1
    assert "CRITICAL" in ex["alerts_by_severity"]

    # Verify snapshots
    assert len(data["incidents"]) >= 1
    assert len(data["alerts"]) >= 1
    assert len(data["predictions"]) >= 2
    assert len(data["important_findings"]) >= 1
    assert "CONFIDENTIAL" in data["disclaimer"]


def test_security_report_time_ranges(client, admin_headers):
    """Test standard time ranges: last_1h, last_7d, last_30d."""
    for tr in ["last_1h", "last_7d", "last_30d"]:
        resp = client.get(f"/api/v1/reports/security?time_range={tr}", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "executive_summary" in data


def test_security_report_custom_date_range(client, analyst_headers):
    """Test custom date range filtering."""
    now = datetime.now(timezone.utc)
    start_str = (now - timedelta(days=2)).isoformat()
    end_str = now.isoformat()

    resp = client.get(
        f"/api/v1/reports/security?time_range=custom&start_date={start_str}&end_date={end_str}",
        headers=analyst_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "Custom" in data["time_range"]


def test_security_report_invalid_custom_range_rejected(client, analyst_headers):
    """Providing start_date >= end_date returns 422 Unprocessable Content."""
    now = datetime.now(timezone.utc)
    start_str = now.isoformat()
    end_str = (now - timedelta(days=1)).isoformat()

    resp = client.get(
        f"/api/v1/reports/security?time_range=custom&start_date={start_str}&end_date={end_str}",
        headers=analyst_headers,
    )
    assert resp.status_code == 422
    err = resp.json().get("message") or resp.json().get("detail") or ""
    assert "earlier" in err.lower()


def test_security_report_csv_generation(client, analyst_headers):
    """Generate security report as CSV stream."""
    resp = client.get("/api/v1/reports/security?format=csv", headers=analyst_headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert "attachment; filename=" in resp.headers.get("content-disposition", "")
    content = resp.text
    assert "Incident_Key" in content
    assert "INC-2026-000001" in content


def test_security_report_pdf_generation(client, analyst_headers):
    """Generate security report as PDF binary stream."""
    resp = client.get("/api/v1/reports/security?format=pdf", headers=analyst_headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert "attachment; filename=" in resp.headers.get("content-disposition", "")
    pdf_bytes = resp.content
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 1000


# -------------------------------------------------------------------------
# 2. Dataset Exports Tests
# -------------------------------------------------------------------------

def test_export_predictions_dataset_csv_and_json(client, analyst_headers):
    """Export predictions in CSV and JSON formats."""
    # CSV
    r_csv = client.get("/api/v1/reports/predictions?format=csv", headers=analyst_headers)
    assert r_csv.status_code == 200
    assert "Predicted_Threat" in r_csv.text
    assert "DDoS-LOIC" in r_csv.text

    # JSON
    r_json = client.get("/api/v1/reports/predictions?format=json", headers=analyst_headers)
    assert r_json.status_code == 200
    assert "predictions" in r_json.json()
    assert r_json.json()["count"] >= 2


def test_export_alerts_dataset_csv_and_json(client, analyst_headers):
    """Export alerts in CSV and JSON formats."""
    # CSV
    r_csv = client.get("/api/v1/reports/alerts?format=csv", headers=analyst_headers)
    assert r_csv.status_code == 200
    assert "Threat_Label" in r_csv.text
    assert "DDoS-LOIC" in r_csv.text

    # JSON
    r_json = client.get("/api/v1/reports/alerts?format=json", headers=analyst_headers)
    assert r_json.status_code == 200
    assert "alerts" in r_json.json()
    assert r_json.json()["count"] >= 1


def test_export_incidents_dataset_csv_and_json(client, analyst_headers):
    """Export incidents in CSV and JSON formats."""
    # CSV
    r_csv = client.get("/api/v1/reports/incidents?format=csv", headers=analyst_headers)
    assert r_csv.status_code == 200
    assert "Incident_Key" in r_csv.text
    assert "INC-2026-000001" in r_csv.text

    # JSON
    r_json = client.get("/api/v1/reports/incidents?format=json", headers=analyst_headers)
    assert r_json.status_code == 200
    assert "incidents" in r_json.json()
    assert r_json.json()["count"] >= 1


def test_export_audit_logs_dataset_csv(client, admin_headers):
    """Export audit events as CSV."""
    resp = client.get("/api/v1/reports/audit-logs", headers=admin_headers)
    assert resp.status_code == 200
    assert "Audit_ID" in resp.text
    assert "Action" in resp.text


# -------------------------------------------------------------------------
# 3. Incident Forensic Evidence Export Tests
# -------------------------------------------------------------------------

def test_export_incident_evidence_json(client, analyst_headers):
    """Export comprehensive incident evidence package in JSON format."""
    resp = client.get("/api/v1/reports/incidents/1/evidence?format=json", headers=analyst_headers)
    assert resp.status_code == 200
    evidence = resp.json()

    assert evidence["incident_key"] == "INC-2026-000001"
    assert evidence["severity"] == "CRITICAL"
    assert evidence["status"] == "INVESTIGATING"
    assert len(evidence["related_alerts"]) >= 1
    assert len(evidence["related_predictions"]) >= 1
    assert len(evidence["notes"]) >= 1
    assert len(evidence["timeline"]) >= 1
    assert "evidence_hash_sha256" in evidence
    assert len(evidence["evidence_hash_sha256"]) == 64  # SHA256 hex string
    assert "CHAIN OF CUSTODY" in evidence["disclaimer"]


def test_export_incident_evidence_zip(client, analyst_headers):
    """Export forensic evidence package as a validated in-memory ZIP bundle."""
    resp = client.get("/api/v1/reports/incidents/1/evidence?format=zip", headers=analyst_headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"
    assert "attachment; filename=" in resp.headers.get("content-disposition", "")

    # Validate ZIP integrity and file archive structure
    zip_bytes = resp.content
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        namelist = zf.namelist()
        assert "incident_overview.json" in namelist
        assert "correlated_alerts.json" in namelist
        assert "correlated_predictions.json" in namelist
        assert "analyst_notes.json" in namelist
        assert "incident_timeline.json" in namelist
        assert "audit_trail.json" in namelist
        assert "manifest.txt" in namelist

        # Inspect manifest content
        manifest_text = zf.read("manifest.txt").decode("utf-8")
        assert "INC-2026-000001" in manifest_text
        assert "SHA-256 Checksum" in manifest_text


def test_export_incident_evidence_nonexistent_returns_404(client, analyst_headers):
    """Requesting evidence for non-existent incident ID returns 404."""
    resp = client.get("/api/v1/reports/incidents/99999/evidence", headers=analyst_headers)
    assert resp.status_code == 404


# -------------------------------------------------------------------------
# 4. RBAC & Access Control Tests
# -------------------------------------------------------------------------

def test_rbac_reporting_access_allowed_for_all_roles(client, admin_headers, analyst_headers, viewer_headers):
    """ADMIN, ANALYST, and VIEWER roles are all authorized to generate reports and export evidence."""
    # 1. Admin
    r1 = client.get("/api/v1/reports/security", headers=admin_headers)
    assert r1.status_code == 200

    # 2. Analyst
    r2 = client.get("/api/v1/reports/security", headers=analyst_headers)
    assert r2.status_code == 200

    # 3. Viewer
    r3 = client.get("/api/v1/reports/security", headers=viewer_headers)
    assert r3.status_code == 200

    # 4. Viewer Evidence
    r4 = client.get("/api/v1/reports/incidents/1/evidence", headers=viewer_headers)
    assert r4.status_code == 200


def test_unauthenticated_requests_rejected(client):
    """Requests without valid JWT Bearer header return 401."""
    assert client.get("/api/v1/reports/security").status_code == 401
    assert client.get("/api/v1/reports/predictions").status_code == 401
    assert client.get("/api/v1/reports/alerts").status_code == 401
    assert client.get("/api/v1/reports/incidents").status_code == 401
    assert client.get("/api/v1/reports/incidents/1/evidence").status_code == 401


# -------------------------------------------------------------------------
# 5. Security & Privacy Guarantees
# -------------------------------------------------------------------------

def test_no_credentials_leaked_in_reports_and_evidence(client, admin_headers):
    """Verify that generated JSON and CSV reports never contain passwords, tokens, or JWTs."""
    # 1. Check Security Report JSON
    r_json = client.get("/api/v1/reports/security", headers=admin_headers)
    content_str = r_json.text
    assert "Bearer" not in content_str
    assert "password" not in content_str.lower()
    assert "secret" not in content_str.lower()

    # 2. Check Evidence Export JSON
    r_ev = client.get("/api/v1/reports/incidents/1/evidence", headers=admin_headers)
    ev_str = r_ev.text
    assert "Bearer" not in ev_str
    assert "password" not in ev_str.lower()
    assert "secret" not in ev_str.lower()


# -------------------------------------------------------------------------
# 6. Audit Logging Integration Tests
# -------------------------------------------------------------------------

def test_audit_logging_for_reports_and_evidence(client, analyst_headers):
    """Verify that reporting and evidence operations emit structured audit logs."""
    # Trigger report generation
    client.get("/api/v1/reports/security?format=json", headers=analyst_headers)

    # Trigger CSV export
    client.get("/api/v1/reports/alerts?format=csv", headers=analyst_headers)

    # Trigger Evidence export
    client.get("/api/v1/reports/incidents/1/evidence?format=json", headers=analyst_headers)

    db = TestingSessionLocal()
    try:
        report_audits = (
            db.query(AuditLogRecord)
            .filter(AuditLogRecord.resource_type.in_([AuditResourceType.REPORT, AuditResourceType.EVIDENCE]))
            .all()
        )
        assert len(report_audits) >= 3

        actions = {a.action for a in report_audits}
        assert AuditAction.REPORT_GENERATED in actions or AuditAction.REPORT_EXPORTED in actions
        assert AuditAction.INCIDENT_EVIDENCE_EXPORTED in actions

        # Verify no JWT / password in details
        for rec in report_audits:
            details_str = str(rec.details or {})
            assert "Bearer" not in details_str
            assert "password" not in details_str.lower()
    finally:
        db.close()
