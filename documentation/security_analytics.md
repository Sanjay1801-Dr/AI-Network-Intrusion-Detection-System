# Phase 13 — Security Analytics & Threat Intelligence Foundation

## Executive Summary

Phase 13 elevates the AI-Based Network Intrusion Detection System (NIDS) from an inference engine into a security analytics and threat-intelligence platform. Building directly on the existing ML models, database persistence, RBAC, rate limiting, and audit logging layers from Phases 1–12, Phase 13 introduces centralized security aggregation, categorical attack distributions, security timelines, originating source telemetry analytics, an extensible threat-intelligence foundation, deterministic rule-based prediction explainability, and forensic investigation workflows.

All analytics operate on locally persisted dataset flows and database records without requiring external paid APIs or cloud dependencies.

---

## 1. Security Analytics Architecture

The security analytics architecture decouples raw database querying from presentation and API transport through a centralized domain service: [`SecurityAnalyticsService`](file:///c:/Users/SANJAY%20SK/Desktop/Network_based/backend/app/services/security_analytics_service.py).

```
                      +---------------------------------------+
                      |   React SOC Analytics Dashboard       |
                      +-------------------+-------------------+
                                          | REST APIs
                                          v
                      +---------------------------------------+
                      |        FastAPI Analytics API          |
                      | (/api/v1/analytics/*, /api/v1/threat*) |
                      +-------------------+-------------------+
                                          |
                        +-----------------+-----------------+
                        |                                   |
                        v                                   v
    +---------------------------------------+ +-----------------------------------+
    |      SecurityAnalyticsService         | |    ThreatIntelligenceService      |
    | - Overview KPIs                       | | - ThreatIntelligenceProvider      |
    | - Threat Distributions                | | - LocalThreatIntelligenceProvider |
    | - Security Event Timeline             | |   (RFC 5737 Demo Telemetry)       |
    | - Top Threat Originating Sources      | +-----------------------------------+
    | - Rule-based Prediction Explanation   |
    | - Forensic Investigation Aggregation  |
    +-------------------+-------------------+
                        |
                        v
    +-------------------------------------------------------+
    |               SQLAlchemy Persistence Layer             |
    |  - PredictionRecord (Predictions & Inferences)        |
    |  - AlertRecord (Incidents & Lifecycle)                |
    |  - AuditLogRecord (Security Events & Access Controls) |
    +-------------------------------------------------------+
```

### Key Architectural Characteristics
- **Centralized Data Aggregation**: Avoids duplicating query logic across endpoints.
- **Database-Level Aggregation**: Uses SQL aggregation functions (`func.count`, `func.upper`, bounded limits) to avoid loading entire tables into server memory.
- **Zero Schema Migrations**: Leverages existing columns (`source_ip`, `destination_ip`, `risk_level`, `anomaly_score`, `threat_label`, `predicted_threat`) already persisted in `prediction_records` and `alerts`.
- **Lightweight Explainability**: Uses deterministic thresholds and rule checks to explain why a flow was flagged without retraining models or introducing unverified SHAP/LIME claims.

---

## 2. API Endpoints Reference

All analytics endpoints require Bearer JWT authentication and adhere to RBAC controls.

| Endpoint | Method | Allowed Roles | Description |
| :--- | :--- | :--- | :--- |
| `/api/v1/analytics/overview` | `GET` | ADMIN, ANALYST, VIEWER | Aggregated KPIs across predictions, alerts, and security audit events. |
| `/api/v1/analytics/threat-distribution` | `GET` | ADMIN, ANALYST, VIEWER | Categorical attack distribution and severity triage counts. |
| `/api/v1/analytics/timeline` | `GET` | ADMIN, ANALYST, VIEWER | Bounded chronological security events grouped into time buckets (`24h`, `7d`, `30d`). |
| `/api/v1/analytics/top-sources` | `GET` | ADMIN, ANALYST, VIEWER | Ranked top originating source IPs, total volume, malicious count, and dominant threat. |
| `/api/v1/analytics/investigate/{prediction_id}` | `GET` | ADMIN, ANALYST, VIEWER | Detailed forensic envelope for a prediction, including explanation, alert, and intel. |
| `/api/v1/threat-intelligence/ip/{ip_address}` | `GET` | ADMIN, ANALYST, VIEWER | Reputation lookup for an IPv4/IPv6 address against the provider base. |

### 2.1 Analytics Overview (`GET /api/v1/analytics/overview`)

**Response:**
```json
{
  "total_predictions": 142,
  "benign_predictions": 118,
  "malicious_predictions": 24,
  "anomaly_predictions": 26,
  "total_alerts": 24,
  "open_alerts": 7,
  "critical_alerts": 4,
  "high_alerts": 12,
  "medium_alerts": 8,
  "resolved_alerts": 15,
  "failed_logins": 2,
  "access_denied": 1,
  "rate_limit_events": 0
}
```

### 2.2 Threat Distribution (`GET /api/v1/analytics/threat-distribution`)

**Response:**
```json
{
  "threat_categories": [
    { "category": "BENIGN", "count": 118, "percentage": 83.1 },
    { "category": "DoS", "count": 14, "percentage": 9.86 },
    { "category": "Port Scan", "count": 8, "percentage": 5.63 },
    { "category": "Bot", "count": 2, "percentage": 1.41 }
  ],
  "severity": [
    { "severity": "CRITICAL", "count": 4, "percentage": 2.82 },
    { "severity": "HIGH", "count": 12, "percentage": 8.45 },
    { "severity": "MEDIUM", "count": 8, "percentage": 5.63 },
    { "severity": "LOW", "count": 118, "percentage": 83.1 }
  ],
  "total_evaluated": 142
}
```

### 2.3 Threat Timeline (`GET /api/v1/analytics/timeline?time_range=7d&limit=50`)

Supports `time_range` query parameter: `24h` (hourly buckets), `7d` (daily buckets), `30d` (daily buckets). Bounded by maximum limit (default 50, maximum 200).

---

## 3. Threat Intelligence Provider Architecture

The threat intelligence module implements a provider abstraction pattern:

```python
class ThreatIntelligenceProvider(ABC):
    @abstractmethod
    def lookup_ip(self, ip_address: str) -> Optional[Dict[str, Any]]: ...
    @abstractmethod
    def lookup_domain(self, domain: str) -> Optional[Dict[str, Any]]: ...
    @abstractmethod
    def lookup_hash(self, file_hash: str) -> Optional[Dict[str, Any]]: ...
```

### 3.1 Local Demonstration Provider (`LocalThreatIntelligenceProvider`)
- Implements `ThreatIntelligenceProvider` using research/RFC 5737 demo IP entries.
- Explicitly tags all responses with `source: "LOCAL_DEMO_INTELLIGENCE"`.
- Never contacts external commercial feeds or third-party paid APIs.
- Strict input validation via Python's standard `ipaddress` module rejects malformed IPs with HTTP 422 before querying.

### 3.2 Extensibility Guarantee
Third-party providers (e.g., MISP, AlienVault OTX, VirusTotal) can be introduced in future phases by implementing `ThreatIntelligenceProvider` and injecting via `ThreatIntelligenceService.set_provider()`. By default, external integrations remain completely disabled.

---

## 4. Rule-Based Prediction Explainability

Prediction explainability provides transparent insight into why a specific network flow was assigned an anomaly score, threat label, and risk level.

> [!NOTE]
> Per architectural guidelines, this system explicitly designates this capability as **Rule-based prediction explanation**. It does not fabricate SHAP, LIME, or surrogate gradient explanations.

### Explanation Factors
1. **Unsupervised Outlier Divergence**: Checks if Isolation Forest anomaly score exceeds severe ($\ge 0.70$) or elevated ($\ge 0.50$) thresholds.
2. **Supervised Threat Designation**: Flags non-benign attack classifications (DoS, Port Scan, Bot, Web Attack).
3. **Model Classifier Confidence**: Evaluates whether Random Forest probability exceeds high-confidence criteria ($\ge 85\%$) or indicates ambiguous classification ($< 50\%$).
4. **Service & Protocol Context**: Identifies sensitive or administrative ports (Port 22 SSH, 23 Telnet, 3389 RDP, 445 SMB) or web application endpoints (Port 80/443).
5. **Flow Volume & TCP Flag Divergence**: Identifies disproportionate SYN/ACK ratios characteristic of volumetric flooding.
6. **Composite Risk Rating**: Contextualizes the triage recommendation (CRITICAL, HIGH, MEDIUM, LOW).

These deterministic risk reasons are returned in `PredictionResponse.explanation.risk_reasons` and presented in the investigation view.

---

## 5. Forensic Investigation Workflow

Analysts can trigger an investigation from either:
- The **Prediction History** table by clicking the **Investigate** button on any record.
- The **Security Analytics** dashboard by drilling into recent suspicious flows.

### Investigation Modal Telemetry
1. **Overview & Classification**: Prediction ID, timestamp, threat label, severity badge, intrusion indicator.
2. **Rule-Based Explanation**: Deterministic bullet points explaining model risk factors.
3. **Network Flow Telemetry**: Source IP, destination IP, service port, protocol, flow duration, packet counts, bytes, and TCP control flags.
4. **Related Alert**: Status, alert ID, severity, and response action if an alert was triggered for this flow.
5. **Correlated Threat Intelligence**: Reputation, confidence score, known threat categories, and first/last seen timestamps from `LOCAL_DEMO_INTELLIGENCE`.

---

## 6. Frontend Security Analytics Dashboard

A dedicated **Security Analytics** view (`frontend/src/pages/SecurityAnalytics.jsx`) is accessible via the main sidebar navigation.

### Features
- **KPI Metrics Ribbon**: Total Predictions, Malicious Attacks, Active Incidents, Critical Incidents, Failed Logins, and Rate-Limit Events.
- **Visual Distributions**:
  - Threat Category Distribution with visual bar graphs and percentage breakdowns.
  - Severity Breakdown with color-coded triage tiers (CRITICAL, HIGH, MEDIUM, LOW).
- **Security Event Timeline**: Chronologically organized activity table with time-range filtering (`24h`, `7d`, `30d`).
- **Top Threat Originating Sources**: Detailed table of source IPs with total flows, malicious count, highest severity, and dominant attack type.
- **Analyst Threat Intelligence Lookup Tool**: Interactive IP lookup console with immediate validation, reputation display, and explicit `LOCAL_DEMO_INTELLIGENCE` badge.

---

## 7. Role-Based Access Control (RBAC)

Phase 13 integrates seamlessly with Phase 9 authentication and RBAC:

| Role | Analytics Overview | Threat Distribution | Timeline & Top Sources | Investigation | Threat Intel Lookup |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **ADMIN** | Allowed | Allowed | Allowed | Allowed | Allowed |
| **ANALYST** | Allowed | Allowed | Allowed | Allowed | Allowed |
| **VIEWER** | Allowed (Read-only) | Allowed (Read-only) | Allowed (Read-only) | Allowed (Read-only) | Allowed (Read-only) |
| **Unauthenticated** | Denied (401) | Denied (401) | Denied (401) | Denied (401) | Denied (401) |

---

## 8. Audit Logging Integration

Phase 13 actions emit structured audit records to the Phase 12 audit trail:
- `ANALYTICS_VIEWED`: Recorded when an operator loads the overview dashboard.
- `THREAT_INTELLIGENCE_LOOKUP`: Recorded with queried IP metadata (excluding sensitive credentials).
- `INVESTIGATION_VIEWED`: Recorded when an analyst accesses forensic details for a prediction ID.

All audit records scrub passwords, JWT tokens, Authorization headers, and internal server paths.

---

## 9. Security & Privacy Safeguards

- **No Credential Leakage**: Endpoint responses exclude `password_hash`, Bearer tokens, and secrets.
- **Defensive Parameter Validation**: IP addresses are validated with `ipaddress.ip_address()`; limit parameters are bounded $[1, 200]$; time ranges are restricted to enumerated values.
- **Bounded Query Execution**: Database queries are capped with explicit limits to prevent denial-of-service via unbounded database scans.
- **Safe Error Formats**: Application exceptions return standardized JSON envelopes without revealing internal traceback or filesystem paths.

---

## 10. Known Limitations

1. **Demonstration Threat Intelligence Base**: The threat intelligence service uses a controlled, local demonstration catalog (`LOCAL_DEMO_INTELLIGENCE`) for offline research. It is not connected to a live commercial feed.
2. **Rule-Based Explainability Scope**: Explainability is derived from heuristic rules and ML feature thresholds; it does not compute exact mathematical Shapley values (SHAP).
3. **Source IP Persistence**: Source IPs are extracted from client-provided flow telemetry. For flows submitted without IP metadata, the top-sources analytics safely displays empty or available safe fields.
