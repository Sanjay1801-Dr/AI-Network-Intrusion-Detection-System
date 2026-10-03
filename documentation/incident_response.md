# Phase 14 — Real-Time SOC Operations & Incident Response Workflow

## 1. Overview

Phase 14 transforms the AI-Based Network Intrusion Detection System (NIDS) from an alert detection and security analytics engine into an end-to-end **Security Operations Center (SOC) Incident Response Console**.

Operators can now:
1. Detect serious security alerts or anomalous predictions
2. Open structured incident cases (`INC-YYYY-XXXXXX`)
3. Correlate triggering alerts and AI predictions without data duplication
4. Assign incident cases to authorized operators (`ADMIN` and `ANALYST`)
5. Advance incidents through a deterministic state machine
6. Record timestamped forensic analyst notes
7. Inspect a unified chronological timeline
8. Enforce containment and document resolution summaries
9. Audit every operational action with privacy guarantees
10. Receive live WebSocket push notifications across distributed SOC browser sessions

---

## 2. Incident Status Lifecycle & State Machine

Incidents adhere to a deterministic state machine:

```text
       ┌────────────────────────┐
       │          OPEN          │
       └───────────┬────────────┘
         │         │           │
         │         │           ▼
         │         ▼      ┌──────────┐
         │   ACKNOWLEDGED │ RESOLVED │ (Terminal State)
         │         │      └──────────┘
         │         ▼           ▲
         │   INVESTIGATING     │
         │         │           │
         ▼         ▼           │
       ┌────────────────┐      │
       │   CONTAINED    ├──────┘
       └────────────────┘
```

### Permitted State Transitions
| Current Status | Allowed Target Status | Direct Resolve Allowed? | Audit Timestamps Updated |
| :--- | :--- | :---: | :--- |
| `OPEN` | `ACKNOWLEDGED`, `RESOLVED` | Yes | `acknowledged_at` (if ACK), `resolved_at` (if RESOLVED) |
| `ACKNOWLEDGED` | `INVESTIGATING`, `CONTAINED`, `RESOLVED` | Yes | `investigation_started_at` (if INV), `resolved_at` (if RESOLVED) |
| `INVESTIGATING` | `CONTAINED`, `RESOLVED` | Yes | `resolved_at` (if RESOLVED) |
| `CONTAINED` | `RESOLVED` | Yes | `resolved_at` |
| `RESOLVED` | *None (Terminal)* | N/A | None (Immutable) |

### State Validation Rules
- **Invalid Transitions**: Any transition outside the defined matrix returns `HTTP 409 Conflict`.
- **Resolution Summary Requirement**: Transitioning to `RESOLVED` strictly requires a `resolution_summary` of at least 5 characters; otherwise, `HTTP 422 Unprocessable Content` is returned.
- **Terminal State**: `RESOLVED` is terminal. Re-opening or modifying resolved incidents is prohibited.

---

## 3. Database Architecture & Relationships

### 3.1 Model Definitions
The database schema introduces 4 new tables:

1. **`incidents`** (`IncidentRecord`):
   - `id`: Primary key integer
   - `incident_key`: Unique sequential identifier (`INC-2026-000001`) with index
   - `title`: Incident headline
   - `description`: Detailed incident description
   - `severity`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`
   - `status`: `OPEN`, `ACKNOWLEDGED`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`
   - `category`: Threat taxonomy label (e.g., `DDoS-LOIC`, `PortScan`)
   - `source_ip`: Correlated network endpoint
   - `assigned_to`: Username of assigned operator
   - `created_by`: Username of case creator
   - `created_at`, `updated_at`: UTC timestamps
   - `acknowledged_at`, `investigation_started_at`, `resolved_at`: Lifecycle timestamps
   - `resolution_summary`: Post-incident remediation summary

2. **`incident_alerts`** (Association Table):
   - Foreign keys linking `incident_id` and `alert_id`.
   - Prevents duplicating alert records.

3. **`incident_predictions`** (Association Table):
   - Foreign keys linking `incident_id` and `prediction_id`.
   - Preserves underlying network flow telemetry link.

4. **`incident_notes`** (`IncidentNoteRecord`):
   - `id`: Primary key integer
   - `incident_id`: Foreign key to `incidents.id`
   - `author`: Operator username
   - `note`: Forensic note body (1–5000 characters)
   - `created_at`, `updated_at`: UTC timestamps

### 3.2 Duplicate Active Incident Prevention
When opening an incident from an existing security alert:
- The system checks if an active incident (`OPEN`, `ACKNOWLEDGED`, `INVESTIGATING`, `CONTAINED`) already exists for that alert.
- If found, creation is rejected with `HTTP 409 Conflict`, referencing the active incident key.

---

## 4. REST API Specification

All endpoints are mounted under `/api/v1/incidents` and require valid JWT Bearer authentication.

| Method | Endpoint | Description | Role Required | Rate Limit |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/incidents` | Create a new incident case (optionally linking alert/prediction) | `ADMIN`, `ANALYST` | Mutation limit |
| `GET` | `/api/v1/incidents` | Paginated search with status, severity, category, assignee filters | All authenticated | Read limit |
| `GET` | `/api/v1/incidents/summary` | Aggregate KPI counters for SOC dashboard | All authenticated | Read limit |
| `GET` | `/api/v1/incidents/{id}` | Detailed incident view with linked alerts, predictions, and notes | All authenticated | Read limit |
| `PATCH` | `/api/v1/incidents/{id}/status` | Execute state machine transition | `ADMIN`, `ANALYST` | Mutation limit |
| `PATCH` | `/api/v1/incidents/{id}/assign` | Reassign incident to active operator | `ADMIN`, `ANALYST` | Mutation limit |
| `POST` | `/api/v1/incidents/{id}/notes` | Append forensic note to incident | `ADMIN`, `ANALYST` | Mutation limit |
| `GET` | `/api/v1/incidents/{id}/notes` | List analyst notes (newest first) | All authenticated | Read limit |
| `GET` | `/api/v1/incidents/{id}/timeline` | Unified chronological incident timeline | All authenticated | Read limit |

---

## 5. Role-Based Access Control (RBAC) Matrix

| Operation | ADMIN | ANALYST | VIEWER | Unauthenticated |
| :--- | :---: | :---: | :---: | :---: |
| View Incidents / Summary / Details | Allowed | Allowed | Allowed | `401 Unauthorized` |
| View Incident Notes & Timeline | Allowed | Allowed | Allowed | `401 Unauthorized` |
| Create Incident | Allowed | Allowed | `403 Forbidden` | `401 Unauthorized` |
| Assign Operator | Allowed | Allowed | `403 Forbidden` | `401 Unauthorized` |
| Change Incident Status | Allowed | Allowed | `403 Forbidden` | `401 Unauthorized` |
| Add Analyst Note | Allowed | Allowed | `403 Forbidden` | `401 Unauthorized` |

### Assignment Rules
- Target assigned user must exist in the database.
- Target user must be `is_active = True`.
- Target user cannot have `VIEWER` role (only `ADMIN` or `ANALYST`).

---

## 6. Audit Trail Integration (Phase 12 Extension)

The Phase 12 security audit system has been extended with the following actions:
- `INCIDENT_CREATED`: Emitted upon opening a new incident.
- `INCIDENT_ASSIGNED`: Emitted when an incident is reassigned.
- `INCIDENT_STATUS_CHANGED`: Emitted on every state transition.
- `INCIDENT_NOTE_ADDED`: Emitted when an analyst records a note (note bodies are scrubbed to prevent sensitive data leakage; only `note_length` is recorded).
- `INCIDENT_VIEWED`: Emitted when an operator accesses deep incident details.

All audit entries record:
- Timestamp (UTC)
- Actor username and role
- Client IP address
- Request path and HTTP method
- Resource type (`INCIDENT`) and ID
- Sanitized metadata dictionary

---

## 7. Real-Time WebSocket Events

Using the existing Phase 7 WebSocket channel (`/api/v1/ws/monitor`), the system broadcasts real-time SOC notifications:

| Event Type | Trigger | Broadcast Payload |
| :--- | :--- | :--- |
| `incident_created` | Incident opened | ID, key, title, severity, category, source IP, creator |
| `incident_status_changed` | State transition | ID, key, previous status, new status, resolution summary |
| `incident_assigned` | Operator assignment | ID, key, assigned operator, assigner |
| `incident_note_added` | Analyst note posted | Incident ID, note ID, author, timestamp |

All WebSocket broadcasts occur only after successful database commit.

---

## 8. Frontend SOC Console

The React frontend includes:
1. **Incident Console (`/incidents`)**:
   - KPI metric cards: Open Incidents, Investigating, Critical, High, Resolved.
   - Filter toolbar: Status, Severity, Category, Assignee.
   - Incidents table with live status badges.
   - Case opening modal.
2. **Forensic Incident Details Modal**:
   - Case summary and network source metadata.
   - Operator quick-action bar: Acknowledge, Investigate, Contain, Resolve (with mandatory summary modal), Reassign.
   - Analyst notes feed with submission form.
   - Unified interactive timeline showing state transitions, audit logs, and correlated alerts/predictions.
3. **Alerts Integration (`/alerts`)**:
   - "Case" action button on alert rows to open pre-filled incident modal with conflict detection.
4. **Dashboard Summary (`/`)**:
   - "Incident Response Summary" widget displaying active case load and quick link to Incident Console.
