# Phase 12 — Structured Security Audit Logging & Security Monitoring Foundation

## Overview

Phase 12 introduces a structured security audit trail and security monitoring telemetry for the **AI-Based Network Intrusion Detection System (NIDS)**. It provides complete visibility into security-sensitive operator actions and system access patterns, establishing an accountable audit foundation while strictly safeguarding sensitive credentials.

The audit system answers key forensic questions:
- **Who** performed an action? (authenticated operator username, role, client peer IP)
- **What** action was performed? (standardized audit taxonomy action, HTTP method, endpoint)
- **When** did it happen? (timezone-aware UTC timestamp)
- **Which resource** was affected? (resource type and target identifier)
- **What was the outcome?** (`SUCCESS`, `FAILURE`, or `DENIED` with status code)
- **What safe contextual metadata exists?** (sanitized JSON details with zero sensitive tokens)

---

## 1. Audit Event Taxonomy

Audit events are standardized via `AuditAction` and `AuditResourceType` enums to eliminate arbitrary strings and ensure reliable querying:

| Category | Audit Action | Resource Type | Description |
| :--- | :--- | :--- | :--- |
| **Authentication** | `LOGIN_SUCCESS` | `AUTH` | Operator successfully authenticated credentials and received a JWT |
| | `LOGIN_FAILURE` | `AUTH` | Authentication failed due to invalid credentials or inactive account |
| | `LOGOUT` | `AUTH` | Operator session explicitly terminated |
| **Authorization** | `ACCESS_DENIED` | `ACCESS_CONTROL` | Authenticated caller attempted an operation exceeding their RBAC role (HTTP 403) |
| **AI Inference** | `PREDICTION_CREATED` | `PREDICTION` | AI dual-stage inference completed, persisted, and broadcast |
| **Alert Management** | `ALERT_ACKNOWLEDGED` | `ALERT` | Operator transitioned alert lifecycle from `NEW` to `ACKNOWLEDGED` |
| | `ALERT_RESOLVED` | `ALERT` | Operator transitioned alert lifecycle from `NEW`/`ACKNOWLEDGED` to `RESOLVED` |
| **WebSocket Stream** | `WEBSOCKET_AUTH_SUCCESS` | `WEBSOCKET` | Valid handshake frame verified within 5-second window |
| | `WEBSOCKET_AUTH_FAILURE` | `WEBSOCKET` | Connection rejected due to missing, invalid, or expired handshake frame |
| **Rate Limiting** | `RATE_LIMIT_EXCEEDED` | `RATE_LIMIT` | Request throttled by SlowAPI abuse protection rules (HTTP 429) |
| **Defensive System** | `SECURITY_ERROR` | `SYSTEM` | Recoverable security or audit persistence operational error |

---

## 2. Database Schema (`audit_logs`)

The audit log is stored in the relational database (`audit_logs` table), with composite indexes to support performant time-series querying and filtering:

```sql
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    username VARCHAR(50),
    user_role VARCHAR(20),
    action VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id VARCHAR(50),
    outcome VARCHAR(20) NOT NULL,
    ip_address VARCHAR(45),
    request_method VARCHAR(10),
    request_path VARCHAR(255),
    status_code INT,
    details TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_username ON audit_logs(username);
CREATE INDEX idx_audit_action ON audit_logs(action);
CREATE INDEX idx_audit_outcome ON audit_logs(outcome);
CREATE INDEX idx_audit_resource_type ON audit_logs(resource_type);
```

### Stored Attributes
- `timestamp`: UTC timestamp when the action occurred.
- `username`: Operator username, or `NULL` for unauthenticated client attempts.
- `user_role`: Operator role (`ADMIN`, `ANALYST`, `VIEWER`) when known.
- `action`: Standardized event string from the taxonomy.
- `resource_type`: Categorization of targeted resource (`AUTH`, `PREDICTION`, `ALERT`, etc.).
- `resource_id`: Primary identifier of affected entity (e.g. prediction ID or alert ID).
- `outcome`: Action outcome status (`SUCCESS`, `FAILURE`, or `DENIED`).
- `ip_address`: Unspoofed socket peer IP address of the caller.
- `request_method`: HTTP method (e.g., `GET`, `POST`, `PATCH`) or `WEBSOCKET`.
- `request_path`: Request URI path.
- `status_code`: Resulting HTTP response status (e.g. `200`, `401`, `403`, `429`).
- `details`: Sanitized JSON text string containing safe contextual metadata.

---

## 3. Strict Security & Privacy Guarantees

The audit system enforces strict data privacy rules to prevent credential or payload leakage:
1. **Forbidden Keys Scrubbing**: A recursive sanitizer (`sanitize_audit_details`) automatically replaces forbidden keys (`password`, `password_hash`, `hashed_password`, `token`, `access_token`, `authorization`, `secret`, `secret_key`, `cookie`, `jwt`, `credentials`) with `[REDACTED]`.
2. **String Scrutiny**: Unstructured detail strings containing literal bearer markers or token fragments are masked.
3. **No Network Flow Payloads**: Full network flow telemetry payloads are stored only in prediction tables; audit records store only safe summary metadata (threat category, risk level, anomaly score).
4. **Append-Oriented Integrity**: The audit trail exposes read-only query endpoints; write endpoints for audit logs are not exposed.
5. **Non-Disruptive Failure Isolation**: Failures in audit logging are safely trapped and logged; they never crash the primary security operation (login, prediction, alert transition).

---

## 4. API Endpoints

### 4.1 Query Security Audit Logs
- **Endpoint**: `GET /api/v1/audit-logs`
- **Authorization**: Required (`ADMIN`, `ANALYST`, or `VIEWER`)
- **Query Parameters**:
  - `limit` (int, default: 20, max: 100): Page size.
  - `offset` (int, default: 0): Records to skip.
  - `username` (string, optional): Case-insensitive partial username match.
  - `action` (string, optional): Exact action match (e.g. `ACCESS_DENIED`).
  - `outcome` (string, optional): `SUCCESS` | `FAILURE` | `DENIED`.
  - `resource_type` (string, optional): Target resource category.
  - `start_time` / `end_time` (ISO datetime, optional): Timestamp range filter.
- **Ordering**: Deterministic newest-first (`timestamp.desc()`).

#### Example Response:
```json
{
  "total": 42,
  "limit": 20,
  "offset": 0,
  "items": [
    {
      "id": 105,
      "timestamp": "2026-10-04T00:15:00.123456Z",
      "username": "operator1",
      "user_role": "ANALYST",
      "action": "ALERT_ACKNOWLEDGED",
      "resource_type": "ALERT",
      "resource_id": "14",
      "outcome": "SUCCESS",
      "ip_address": "127.0.0.1",
      "request_method": "PATCH",
      "request_path": "/api/v1/alerts/14/acknowledge",
      "status_code": 200,
      "details": "{\"alert_id\": 14, \"previous_status\": \"NEW\", \"new_status\": \"ACKNOWLEDGED\", \"severity\": \"HIGH\"}",
      "created_at": "2026-10-04T00:15:00.123456Z"
    }
  ]
}
```

### 4.2 Security Monitoring Summary
- **Endpoint**: `GET /api/v1/audit-logs/summary`
- **Authorization**: Required (`ADMIN`, `ANALYST`, `VIEWER`)
- **Response**: Aggregated counts for SOC dashboard overview:
```json
{
  "total_events": 142,
  "failed_logins": 3,
  "access_denied": 1,
  "rate_limit_exceeded": 2
}
```

---

## 5. Frontend Integration

### 5.1 Security Audit Logs Page (`frontend/src/pages/AuditLogs.jsx`)
- Dedicated **Security Audit Logs** page added to authenticated navigation.
- Multi-dimensional filters (Username, Action taxonomy, Outcome, Resource).
- Bounded pagination with previous/next page navigation.
- Color-coded badges for action types and outcomes.
- Deep inspection modal displaying parsed sanitized JSON context without truncation.
- Controlled manual refresh action without automatic polling loops.

### 5.2 Dashboard Security Summary Card (`frontend/src/pages/Dashboard.jsx`)
- Displays real-time aggregated security metrics fetched directly from `GET /api/v1/audit-logs/summary`:
  - Total Audit Events recorded in database.
  - Failed Logins count.
  - Access Denied (HTTP 403) count.
  - Rate Limit Throttles (HTTP 429) count.

---

## 6. Retention Considerations & Known Limitations

- **Storage Growth**: In high-throughput network environments, continuous flow predictions generate audit entries. In production, a scheduled retention job (e.g. retaining 90 days of logs or archiving older records to cold storage) should be established.
- **Single-Node Local Database**: Uses SQLite for development, portable to PostgreSQL. Distributed SIEM aggregation (e.g., Elasticsearch, Splunk, Kafka) is out of scope for Phase 12.
- **Append-Oriented**: Database writes are strictly append-oriented with no user-exposed mutation or deletion endpoints.
