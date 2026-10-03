# Phase 15 — Automated Security Reporting & Evidence Export

## 1. Overview

Phase 15 introduces an **Automated Security Reporting & Forensic Evidence Export module** for the AI-Based Network Intrusion Detection System (NIDS).

This capability enables authenticated SOC operators and compliance auditors to:
1. Compile on-demand executive security assessments covering ML predictions, threat classifications, correlated alerts, incidents, and audit records.
2. Select standard operational timeframes (`last_1h`, `last_24h`, `last_7d`, `last_30d`) or custom date ranges.
3. Export executive-ready **PDF reports**, machine-readable **JSON payloads**, or tabular **CSV datasets**.
4. Generate cryptographically signed, tamper-evident **Incident Evidence Packages** in JSON or multi-file ZIP format for formal chain of custody.
5. Filter exports by threat severity and category.
6. Enforce strict bounded limits to prevent denial-of-service, memory exhaustion, or uncontrolled database extraction.
7. Audit all report generation and export actions while strictly preventing credential leakage.

---

## 2. Reporting Architecture

The reporting module operates directly on existing persisted operational tables without external SaaS dependencies or third-party infrastructure:

```text
 ┌───────────────────────────────────────────────────────────────┐
 │               NIDS Relational Persistence Layer               │
 │  (predictions_records, alerts, incidents, notes, audit_logs)  │
 └───────────────────────────────┬───────────────────────────────┘
                                 │
                                 ▼
 ┌───────────────────────────────────────────────────────────────┐
 │                       ReportingService                        │
 │  - Time window bounding & RFC datetime normalization          │
 │  - Severity / Category filtering & aggregation                │
 │  - Anomaly density & resolution rate calculations             │
 │  - SHA-256 evidence package signing                           │
 └───────┬───────────────────────┼───────────────────────┬───────┘
         │                       │                       │
         ▼                       ▼                       ▼
 ┌───────────────┐       ┌───────────────┐       ┌───────────────┐
 │  JSON Report  │       │  CSV Exports  │       │  ReportLab    │
 │   & Evidence  │       │  (Tabular)    │       │  PDF Engine   │
 └───────────────┘       └───────────────┘       └───────────────┘
```

---

## 3. Supported Report Types & Formats

### 3.1 Executive Security Assessment Report
A comprehensive report summarizing operational security health within a specified timeframe:
- **Executive Security Summary**: Total flows evaluated, anomalies detected, alerts triggered, incident cases opened/resolved.
- **Threat Vector Breakdown**: Top detected attack vectors (e.g., `DDoS-LOIC`, `PortScan`, `FTP-Patator`).
- **Attacking Source IP Analysis**: Top ingress source addresses with event counts.
- **Incident Response Metrics**: Active investigation status and resolution velocity.
- **Correlated Alerts & Incidents Snapshot**: Tabular snapshot of recent events.
- **Executive Key Findings**: Rule-based analytical observations highlighting critical risks.
- **Defensive Disclaimer**: Clarifies that metrics represent monitored telemetry.

Available in:
- **`JSON`**: Full structured envelope for programmatic consumers and frontend rendering.
- **`PDF`**: Clean, professional vector PDF generated with ReportLab.
- **`CSV`**: Standard RFC 4180 comma-separated values for spreadsheet tools.

### 3.2 Individual Dataset CSV Exports
Dedicated endpoints for streaming raw operational datasets:
- **Predictions CSV**: Evaluated flows with anomaly scores, threat labels, classification confidences, and network 5-tuple info.
- **Alerts CSV**: Triggered security alerts with severity, status, timestamps, and network endpoints.
- **Incidents CSV**: Case management records with key, title, status, assigned analyst, and resolution notes.
- **Audit Trail CSV**: Compliance log events with actor, action, outcome, and resource IDs (sanitized of sensitive tokens).

### 3.3 Forensic Incident Evidence Package
For a selected incident case (`incident_id`), compiles a complete chain-of-custody evidence package containing:
- Incident summary, timestamps, and lifecycle progression
- Operator assignment and analyst case notes
- Linked alerts and underlying flow predictions
- Unified chronological event timeline
- Correlated Phase 12 security audit trail entries
- **Cryptographic Integrity Hash (SHA-256)**: Computed over canonical JSON serialization of all evidence items
- Available in **`JSON`** or **`ZIP`** (containing `incident_overview.json`, `correlated_alerts.json`, `correlated_predictions.json`, `analyst_notes.json`, `incident_timeline.json`, `audit_trail.json`, and `manifest.txt`)

---

## 4. REST API Specification

All endpoints are mounted under `/api/v1/reports` and require Bearer JWT authentication:

| Method | Endpoint | Query Parameters | Description | Role Required |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/reports/security` | `time_range`, `format`, `start_date`, `end_date`, `severity`, `category`, `limit` | Generate security assessment report (JSON/CSV/PDF) | `ADMIN`, `ANALYST`, `VIEWER` |
| `GET` | `/api/v1/reports/predictions` | `time_range`, `format`, `start_date`, `end_date`, `severity`, `category`, `limit` | Export flow predictions dataset (CSV/JSON) | `ADMIN`, `ANALYST`, `VIEWER` |
| `GET` | `/api/v1/reports/alerts` | `time_range`, `format`, `start_date`, `end_date`, `severity`, `category`, `limit` | Export security alerts dataset (CSV/JSON) | `ADMIN`, `ANALYST`, `VIEWER` |
| `GET` | `/api/v1/reports/incidents` | `time_range`, `format`, `start_date`, `end_date`, `severity`, `category`, `limit` | Export incident cases dataset (CSV/JSON) | `ADMIN`, `ANALYST`, `VIEWER` |
| `GET` | `/api/v1/reports/audit-logs` | `time_range`, `start_date`, `end_date`, `limit` | Export security audit log events (CSV) | `ADMIN`, `ANALYST`, `VIEWER` |
| `GET` | `/api/v1/reports/incidents/{id}/evidence` | `format` (`json` or `zip`) | Export tamper-evident forensic package for incident | `ADMIN`, `ANALYST`, `VIEWER` |

---

## 5. Role-Based Access Control (RBAC)

All authenticated operator roles (`ADMIN`, `ANALYST`, `VIEWER`) are authorized to generate reports and export evidence:
- **`ADMIN`**: Full reporting and evidence-export access.
- **`ANALYST`**: Full reporting and evidence-export access.
- **`VIEWER`**: Read-only reporting and evidence-export access.
- **Unauthenticated / Anonymous**: Strictly blocked with `HTTP 401 Unauthorized`.

> **Separation of Concerns:** Read-only `VIEWER` users can export reports and evidence packages for analysis, but retain zero privileges to create, assign, mutate, or resolve incident cases.

---

## 6. Audit Trail Integration

The Phase 12 security audit system is extended with new actions:
- `REPORT_GENERATED`: Emitted when a user requests an in-browser report preview.
- `REPORT_EXPORTED`: Emitted when an operator downloads PDF, CSV, or dataset files.
- `INCIDENT_EVIDENCE_EXPORTED`: Emitted when an operator exports an incident evidence package.

**Audit Event Metadata**:
- Actor username and role
- Client IP address and HTTP method
- Resource type (`REPORT` or `EVIDENCE`)
- Requested format (`pdf`, `csv`, `json`, `zip`)
- Time range descriptor
- Evidence SHA-256 hash (for evidence exports)

**Strict Privacy Guarantee**:
- Passwords, hashes, JWT tokens, and Authorization headers are NEVER recorded in audit metadata.
- Generated report bodies and raw file streams are NEVER stored inside the database audit table.

---

## 7. Security Protections & Bounded Query Limits

1. **Bounded Query Size (`MAX_REPORT_ITEMS = 1000`)**:
   - Queries are bounded to prevent denial-of-service, excessive memory consumption, or unbounded database dumps.
2. **Custom Time Range Bounds (`MAX_CUSTOM_RANGE_DAYS = 90`)**:
   - Custom start and end dates are checked: `start_date < end_date` is required.
   - Ranges exceeding 90 days are rejected with `HTTP 422 Unprocessable Content`.
3. **Path Traversal Protection**:
   - Filenames are constructed internally using sanitized slugs and timestamps.
   - User input is never concatenated into filesystem paths.
4. **In-Memory Streaming**:
   - PDF, CSV, and ZIP files are generated in-memory using `io.BytesIO` and `io.StringIO`.
   - No sensitive report files are persisted on disk or left in temporary directories.

---

## 8. Frontend User Experience

1. **Security Reports Page (`/reports`)**:
   - Integrated into the primary SOC navigation bar (`FileDown` icon).
   - Time window selector with custom date pickers.
   - Severity and category filtering.
   - Direct action buttons: "Generate Preview", "Export Executive PDF", "Export JSON", "Export CSV".
   - Dataset quick export cards for Predictions, Alerts, Incidents, and Audit Logs.
   - Live preview rendering executive KPI cards, important findings, and snapshot tables.
2. **Incident Details Evidence Export**:
   - On the `IncidentDetails` modal, operators have "Evidence JSON" and "Evidence ZIP" buttons.
   - Instant download with progress and success feedback.
