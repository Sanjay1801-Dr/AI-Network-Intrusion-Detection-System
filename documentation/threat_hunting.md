# Phase 16 — Advanced Threat Hunting & Investigation Workbench

## 1. Overview

Phase 16 introduces an **Advanced Threat Hunting & Investigation Workbench** for the AI-Based Network Intrusion Detection System (NIDS).

This capability enables Security Operations Center (SOC) analysts to conduct defensive, hypothesis-driven investigations across historical network flows, detected anomalies, triaged alerts, incident response cases, and security audit logs. 

Key capabilities include:
1. **Multi-Dimensional Search Engine**: Bounded, parameterized queries across network telemetry (source/destination IP, ports, protocols), AI detections (threat category, severity, composite risk, anomaly scores, classifier confidence), lifecycle states, and free-text tags.
2. **Deterministic Correlation Engine**: Multi-event relationship synthesis identifying network convergence across ports, temporal bursts (<= 10 minutes), and linked incident cases, explicitly tagged with defensive disclaimer notices.
3. **Source-Centric Forensic Profiling**: Deep-dive analysis of individual ingress or internal host IPs, displaying first/last seen timestamps, threat category breakdown, severity distributions, top destination endpoints, and a unified chronological timeline.
4. **Lightweight Query History**: Sanitized local persistence of analyst query parameters enabling rapid reload of complex multi-attribute searches without storing credentials or sensitive tokens.
5. **Phase 13 Investigation Integration**: Seamless deep-dive into individual flow inferences, feature telemetry, rule-based explanations, and reputation indicators via the unified investigation modal.
6. **Strict Security Controls**: Enforced parameter validation (RFC IPv4/IPv6 verification, port ranges 1–65535, anomaly scores -1.0 to 1.0, maximum 90-day custom window, maximum 200 items per entity slice) and complete SQL injection immunity via SQLAlchemy ORM.
7. **Centralized Audit Logging**: Full audit trail recording hunt searches, source investigations, and history views with safe metadata summaries.

---

## 2. Threat Hunting Architecture

The Threat Hunting Workbench operates directly on existing relational persistence structures without external SIEM, SOAR, Redis, or cloud dependencies:

```text
 ┌─────────────────────────────────────────────────────────────────────────┐
 │                   NIDS Relational Persistence Engine                    │
 │  (predictions_records, alerts, incidents, audit_logs, hunt_query_hist)  │
 └───────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
 ┌─────────────────────────────────────────────────────────────────────────┐
 │                       ThreatHuntingService                              │
 │  - Parameterized Query Execution & Window Normalization                 │
 │  - Bounded Multi-Entity Slices (Predictions, Alerts, Incidents)         │
 │  - Correlation Synthesis (Network Convergence, Temporal Bursts)         │
 │  - Source-Centric Host Profiling & Chronological Timeline Assembly      │
 │  - Sanitized Query History Persistence (Per-User Bounded to 50 Items)   │
 └───────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
 ┌─────────────────────────────────────────────────────────────────────────┐
 │                     FastAPI REST Endpoints (/hunting)                   │
 │  - POST /api/v1/hunting/search (Search & Correlation)                   │
 │  - GET  /api/v1/hunting/summary (Telemetry KPIs)                        │
 │  - GET  /api/v1/hunting/source/{ip} (Source Host Forensic Profile)      │
 │  - GET  /api/v1/hunting/history (Operator Query History)                │
 └───────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
 ┌─────────────────────────────────────────────────────────────────────────┐
 │                React Frontend (ThreatHunting.jsx)                       │
 │  - Query Builder & Filter Panel (Time, Network, Detection, Lifecycle)   │
 │  - Real-Time Correlation Insights Callout Cards                         │
 │  - Tabbed Results Matrix (Flow Inferences, Alerts, Incidents)           │
 │  - Source Forensic Investigation Modal & Chronological Timeline         │
 │  - One-Click Query History Reloader Drawer                              │
 └─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Search Engine & Supported Filters

All queries are executed through `POST /api/v1/hunting/search` using the `ThreatHuntSearchRequest` schema. Raw SQL injection is impossible as every query uses strict SQLAlchemy parameterized operations.

### 3.1 Network Filters
- `source_ip`: Validated IPv4 or IPv6 address (e.g. `198.51.100.11`).
- `destination_ip`: Validated IPv4 or IPv6 address (e.g. `10.0.0.5`).
- `source_port`: Network source port (`1` – `65535`).
- `destination_port`: Network destination port (`1` – `65535`).
- `protocol`: Transport layer protocol name or numeric identifier (e.g. `TCP`, `UDP`, `6`, `17`).

### 3.2 Detection & ML Metric Filters
- `threat_category`: Substring search against detected attack labels (e.g. `DoS`, `DDoS`, `PortScan`, `Brute Force`).
- `severity`: Standard severity level (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- `risk_level`: Composite risk tier (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- `min_anomaly_score` / `max_anomaly_score`: Isolation Forest score bounds (`-1.0` to `1.0`).
- `min_confidence` / `max_confidence`: Classifier prediction probability (`0.0` to `1.0`).

### 3.3 Lifecycle State Filters
- `alert_status`: Filter triage state (`NEW`, `ACKNOWLEDGED`, `RESOLVED`, `FALSE_POSITIVE`).
- `incident_status`: Filter incident cases (`OPEN`, `ACKNOWLEDGED`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`).

### 3.4 Temporal Bounding
- `time_range`: Predefined timeframes (`1h`, `24h`, `7d`, `30d`, `custom`).
- `start_datetime` / `end_datetime`: ISO-8601 UTC timestamps (required when `time_range="custom"`). Max allowable custom span is 90 days.

### 3.5 Text Search
- `query_text`: Sanitized substring matching across predicted threat names, anomaly labels, source/destination IPs, alert types, and incident keys.

---

## 4. Correlation Logic

The correlation engine identifies potential relationships among disparate events without claiming proof of attack:

1. **Network Convergence Correlation**:
   - Synthesizes flows originating from the same source IP and targeting identical destination ports or service endpoints.
   - Highlights potential port scans, brute-force sweeps, or targeted application-layer attacks.
2. **Temporal Burst Correlation**:
   - Flags clusters of 3 or more anomalous predictions occurring within a tight window (<= 10 minutes).
   - Identifies rapid volumetric incursions or automated scanning scripts.
3. **Linked Incident Context**:
   - Connects matching alerts and predictions to existing open incident cases.
4. **Mandatory Defensive Notice**:
   - Every correlation finding includes the disclaimer:  
     `"Potentially related security activity. Does not conclusively prove attack attribution."`

---

## 5. API Reference

### 5.1 Execute Threat Hunt Search
- **Endpoint**: `POST /api/v1/hunting/search`
- **RBAC**: `ADMIN`, `ANALYST`, `VIEWER` (Read query)
- **Rate Limit**: Read tier (`120/minute`)
- **Request Body**: `ThreatHuntSearchRequest` JSON
- **Response**: `ThreatHuntSearchResponse` (matching predictions, alerts, incidents, correlations, applied filters, and pagination offsets)
- **Audit Action**: `THREAT_HUNT_SEARCHED`

### 5.2 Workbench Summary Telemetry
- **Endpoint**: `GET /api/v1/hunting/summary`
- **RBAC**: `ADMIN`, `ANALYST`, `VIEWER`
- **Response**: `ThreatHuntingSummaryResponse` (total flows, threat detections, active alerts, open incidents, unique sources, top threats, top active sources)

### 5.3 Source IP Forensic Investigation
- **Endpoint**: `GET /api/v1/hunting/source/{ip_address}`
- **RBAC**: `ADMIN`, `ANALYST`, `VIEWER`
- **Response**: `SourceInvestigationResponse` (first seen, last seen, total observations, threat breakdown, severity distribution, top destination IP:Port pairs, protocols, and unified chronological timeline)
- **Audit Action**: `SOURCE_INVESTIGATION_VIEWED`

### 5.4 Query History
- **Endpoint**: `GET /api/v1/hunting/history?limit=20`
- **RBAC**: `ADMIN`, `ANALYST`, `VIEWER`
- **Response**: `List[HuntQueryHistoryItem]` (id, timestamp, username, filter_summary, filters, result_count)
- **Audit Action**: `THREAT_HUNT_HISTORY_VIEWED`

---

## 6. Role-Based Access Control (RBAC)

Threat hunting enforces the system's centralized authentication and RBAC model:

| Role | Search & Correlation | Source Investigation | Query History View | Mutate Incidents / Alerts |
| :--- | :--- | :--- | :--- | :--- |
| **ADMIN** | Allowed | Allowed | Allowed | Allowed |
| **ANALYST** | Allowed | Allowed | Allowed | Allowed |
| **VIEWER** | Allowed (Read-only) | Allowed (Read-only) | Allowed (Read-only) | **Blocked (403 Forbidden)** |
| **Unauthenticated** | **Blocked (401)** | **Blocked (401)** | **Blocked (401)** | **Blocked (401)** |

---

## 7. Security & Guardrails

1. **Strict Input Sanitization**:
   - IP addresses validated via Python's standard `ipaddress.ip_address`.
   - Ports validated to integer range `1` – `65535`.
   - Anomaly scores bounded `-1.0` to `1.0`.
   - Confidence bounded `0.0` to `1.0`.
   - Datetime range inverted validation (`start_datetime < end_datetime`).
2. **Denial-of-Service Defense**:
   - Maximum result limit per entity slice capped at `200` items.
   - Custom search time windows bounded to maximum `90` days.
   - Query history capped at `50` records per user.
   - API rate limiting applied via SlowAPI (`120/minute`).
3. **No Arbitrary SQL**:
   - Frontend cannot execute arbitrary SQL queries. All queries are strictly compiled by SQLAlchemy ORM with parameter bindings.
4. **Data Privacy & Zero Credential Leakage**:
   - Passwords, hashes, JWT tokens, and Authorization headers are never stored in history records, query parameters, or audit logs.
   - Error messages are defensively sanitized without exposing backend stack traces.

---

## 8. Known Limitations

- **Bounded Entity Limits**: Search results return up to 200 items per entity slice (predictions, alerts, incidents) to prevent memory exhaustion. Analysts should refine time windows or IP filters for large datasets.
- **Local SQLite / PostgreSQL Store**: Correlation is computed in-memory across indexed database slices rather than distributed streaming clusters (Redis/Kafka), keeping the architecture simple, portable, and free of heavyweight dependencies.
- **Defensive Telemetry Interpretation**: Flow correlations reflect statistical colocation and temporal grouping in recorded logs; attribution requires analyst corroboration.
