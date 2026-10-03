# Phase 8 — Alert Lifecycle Management & Incident Response

## 1. Overview

Phase 8 elevates the AI-Based Network Intrusion Detection System (NIDS) from passive alert logging to active **alert lifecycle management and SOC incident response**.

Security operators can now investigate anomalous incident telemetry, review correlated AI inference metadata, and track the alert through a finite state machine:

```text
       ┌──────────────┐
       │     NEW      │
       └──────┬───────┘
              │  \
Acknowledge   │   \  Direct Resolve
              ▼    \
 ┌─────────────────┐\
 │  ACKNOWLEDGED   │ │
 └────────┬────────┘ │
          │          │
  Resolve │          │
          ▼          ▼
       ┌──────────────┐
       │   RESOLVED   │ (Terminal State)
       └──────────────┘
```

---

## 2. Finite State Machine & Valid Transitions

All transitions are strictly validated on the backend. The backend is the sole authority for lifecycle state transitions; frontend status requests cannot bypass state validation.

### Permitted Transitions
| Source State | Target State | Endpoint Trigger | Audit Timestamps Updated |
| :--- | :--- | :--- | :--- |
| `NEW` | `ACKNOWLEDGED` | `PATCH /api/v1/alerts/{id}/acknowledge` | `acknowledged_at` = UTC now, `resolved_at` = null |
| `ACKNOWLEDGED` | `RESOLVED` | `PATCH /api/v1/alerts/{id}/resolve` | `resolved_at` = UTC now, `acknowledged_at` preserved |
| `NEW` | `RESOLVED` | `PATCH /api/v1/alerts/{id}/resolve` | `resolved_at` = UTC now, `acknowledged_at` = null |

### Disallowed Transitions (HTTP 409 Conflict)
- `RESOLVED → ACKNOWLEDGED`: Re-opening or acknowledging a resolved alert is rejected.
- `RESOLVED → NEW`: Reverting terminal alerts to new status is rejected.
- `ACKNOWLEDGED → ACKNOWLEDGED`: Redundant acknowledgment attempts return HTTP 409.
- `RESOLVED → RESOLVED`: Redundant resolution attempts return HTTP 409.
- Nonexistent alert ID returns `HTTP 404 Not Found`.

---

## 3. Database Schema Changes

The `AlertRecord` SQLAlchemy model in `backend/app/models/alert.py` was extended with two audit timestamp columns:

```python
class AlertRecord(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    prediction_id = Column(Integer, ForeignKey("prediction_records.id", ondelete="CASCADE"), nullable=True, index=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)
    alert_type = Column(String(50), nullable=False, default="NETWORK_INTRUSION")
    severity = Column(String(20), nullable=False, index=True)
    threat_label = Column(String(50), nullable=False, index=True)
    anomaly_score = Column(Float, nullable=False)
    confidence = Column(Float, nullable=False)
    source_ip = Column(String(45), nullable=True)
    destination_ip = Column(String(45), nullable=True)
    status = Column(String(30), default="NEW", index=True, nullable=False)
    recommended_action = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)

    # Phase 8 Audit Timestamp Fields
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    prediction = relationship("PredictionRecord", back_populates="alerts")
```

### Audit Timestamp Semantics
1. **Creation**: `created_at` records the UTC insertion time. `acknowledged_at` and `resolved_at` default to `NULL`.
2. **Acknowledgment**: `acknowledged_at` is set to current UTC time. `created_at` remains immutable.
3. **Resolution from ACKNOWLEDGED**: `resolved_at` is set to current UTC time. The previous `acknowledged_at` value is strictly preserved.
4. **Resolution directly from NEW**: `resolved_at` is set to current UTC time. `acknowledged_at` remains `NULL`.

---

## 4. REST Endpoints

### 4.1. Single Alert Lookup & Investigation
```http
GET /api/v1/alerts/{alert_id}
```
* **Status Codes**:
  - `200 OK`: Returns complete alert record with correlated `prediction` metadata if linked.
  - `404 Not Found`: Alert ID does not exist.
* **Response Example**:
```json
{
  "id": 20,
  "prediction_id": 48,
  "timestamp": "2026-10-03T14:09:50.892000+00:00",
  "alert_type": "NETWORK_INTRUSION",
  "severity": "MEDIUM",
  "threat_label": "DoS",
  "anomaly_score": 0.825,
  "confidence": 0.942,
  "source_ip": "198.51.100.22",
  "destination_ip": "10.0.0.5",
  "status": "NEW",
  "recommended_action": "Apply firewall rate limiting to destination port 80.",
  "created_at": "2026-10-03T14:09:50.892000+00:00",
  "acknowledged_at": null,
  "resolved_at": null,
  "prediction": {
    "id": 48,
    "predicted_threat": "DoS",
    "anomaly_label": "ANOMALY",
    "anomaly_score": 0.825,
    "classification_confidence": 0.942,
    "risk_level": "MEDIUM",
    "recommended_action": "Apply firewall rate limiting to destination port 80.",
    "flow_duration": 12050.0,
    "total_bytes": 51000,
    "source_ip": "198.51.100.22",
    "destination_ip": "10.0.0.5",
    "destination_port": 80,
    "protocol": "6",
    "created_at": "2026-10-03T14:09:50.880000+00:00"
  }
}
```

### 4.2. Acknowledge Alert
```http
PATCH /api/v1/alerts/{alert_id}/acknowledge
```
* **Precondition**: `status == "NEW"`.
* **Action**: Sets `status = "ACKNOWLEDGED"` and `acknowledged_at = utc_now()`.
* **Post-commit**: Broadcasts `alert_acknowledged` event over WebSocket.
* **Status Codes**:
  - `200 OK`: Transition successful.
  - `404 Not Found`: Alert does not exist.
  - `409 Conflict`: Alert is already `ACKNOWLEDGED` or in terminal state `RESOLVED`.

### 4.3. Resolve Alert
```http
PATCH /api/v1/alerts/{alert_id}/resolve
```
* **Precondition**: `status in ("NEW", "ACKNOWLEDGED")`.
* **Action**: Sets `status = "RESOLVED"` and `resolved_at = utc_now()`. Preserves existing `acknowledged_at`.
* **Post-commit**: Broadcasts `alert_resolved` event over WebSocket.
* **Status Codes**:
  - `200 OK`: Transition successful.
  - `404 Not Found`: Alert does not exist.
  - `409 Conflict`: Alert is already in terminal status `RESOLVED`.

---

## 5. WebSocket Lifecycle Events

Broadcasts occur **strictly after** the database commit succeeds. If the database transaction aborts or encounters an error, no lifecycle WebSocket event is transmitted.

### 5.1. `alert_acknowledged` Event
```json
{
  "event_type": "alert_acknowledged",
  "timestamp": "2026-10-03T14:30:00+00:00",
  "data": {
    "alert_id": 20,
    "prediction_id": 48,
    "severity": "MEDIUM",
    "status": "ACKNOWLEDGED",
    "acknowledged_at": "2026-10-03T14:30:00+00:00"
  }
}
```

### 5.2. `alert_resolved` Event
```json
{
  "event_type": "alert_resolved",
  "timestamp": "2026-10-03T14:35:00+00:00",
  "data": {
    "alert_id": 20,
    "prediction_id": 48,
    "severity": "MEDIUM",
    "status": "RESOLVED",
    "resolved_at": "2026-10-03T14:35:00+00:00"
  }
}
```

---

## 6. Frontend Architecture & UI Workflow

### 6.1. Centralized API Service (`frontend/src/services/api.js`)
All alert communication is encapsulated:
- `api.getAlert(alertId)`
- `api.acknowledgeAlert(alertId)`
- `api.resolveAlert(alertId)`
- Sanitized `ApiError` class with specific detection for `HTTP 409 (STATE_CONFLICT)`.

### 6.2. Alert Management Page (`frontend/src/pages/SecurityAlerts.jsx`)
1. **Filters**: Status (`ALL`, `NEW`, `ACKNOWLEDGED`, `RESOLVED`), Severity (`ALL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), and Page Size.
2. **Context-Sensitive Lifecycle Actions**:
   - `NEW` alert: Displays `[Acknowledge]` and `[Resolve]` buttons.
   - `ACKNOWLEDGED` alert: Displays `[Resolve]` button.
   - `RESOLVED` alert: Displays immutable `Resolved` status badge.
3. **Concurrency & Loading State**: Buttons disable and display loading state during active requests to prevent duplicate submissions.
4. **Optimistic/Immediate UI Update**: Table row updates immediately upon API response without reloading the page.
5. **Real-time Synchronization**: Subscribes to WebSocket lifecycle events and dynamically updates alert status and timestamps in-place.

### 6.3. Incident Investigation Modal (`frontend/src/components/AlertDetailsModal.jsx`)
Allows operators to drill down into an alert to inspect:
- Prominently highlighted Recommended SOC Action.
- AI Threat Detection Telemetry (identified threat, classifier confidence, anomaly score).
- UTC Lifecycle Audit Timestamps (`created_at`, `acknowledged_at`, `resolved_at`).
- Correlated Network Flow Telemetry (IP endpoints, service port, protocol, flow duration, transferred bytes).
- Direct triage action controls (`Acknowledge`, `Resolve`) inside the modal.

---

## 7. Security & Integrity Controls

1. **Server-Side Authoritative State**: Client cannot set arbitrary alert statuses. Transitions are governed solely by `AlertService`.
2. **Transaction Isolation**: Lifecycle updates execute inside explicit SQLAlchemy transactions with immediate rollback upon failure.
3. **No Information Leakage**: Error responses sanitize Python stack traces and database internal exceptions.
4. **WebSocket Safety**: WebSockets operate in push-only notification mode; incoming client messages cannot alter lifecycle states or execute commands.
5. **Data Protection**: Raw packet buffers or internal credentials are never persisted or serialized in API responses.

---

## 8. Verification & Test Suite

The test suite validates both unit isolation and end-to-end integration:
* **70 total automated backend tests passing** (57 existing baseline + 13 Phase 8 tests).
* **Alert Lifecycle Tests**:
  - `NEW → ACKNOWLEDGED` state transition & timestamp verification.
  - `ACKNOWLEDGED → RESOLVED` state transition & timestamp preservation.
  - `NEW → RESOLVED` direct resolution transition.
  - `RESOLVED → ACKNOWLEDGED` and `RESOLVED → NEW` rejection (409 Conflict).
  - Redundant transitions rejection (409 Conflict).
  - Nonexistent alert lookup (404 Not Found).
  - Detailed single-alert query with correlated prediction metadata.
* **Fault Isolation & Transaction Guards**:
  - Verification that DB transaction failure suppresses WebSocket lifecycle emission.
  - Multi-client WebSocket broadcast with broken client isolation.
* **Frontend Verification**:
  - `npm run build` succeeds with zero errors.
  - Live manual E2E test with real browser WebSocket event handling.

---

## 9. Known Limitations & Strict Scope Boundaries

* **No Authentication/RBAC**: Authentication, operator roles, and multi-tenant access control are deferred to later phases.
* **No External Dispatchers**: External webhooks, SMS, email, or automated firewall blocking are not implemented in this phase.
* **ML Model Untouched**: Inference pipelines and weights remain frozen from Phase 3.
