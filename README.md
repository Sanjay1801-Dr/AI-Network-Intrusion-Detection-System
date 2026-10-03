# AI-Based Network Intrusion Detection System (NIDS)

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green.svg)](https://fastapi.tiangolo.com)
[![React 18](https://img.shields.io/badge/React-18.x-61dafb.svg)](https://react.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security Status: Defensive Only](https://img.shields.io/badge/Security-Defensive_Monitoring-critical.svg)](#security-and-ethics-disclaimer)

---

## 1. Project Overview

The **AI-Based Network Intrusion Detection System (NIDS)** is a modular, production-style cybersecurity software platform designed for real-time monitoring and threat mitigation in enterprise networks. The platform ingests network traffic flows, extracts statistical features, identifies behavioral deviations using unsupervised machine learning, classifies specific attack patterns using supervised learning, assigns quantifiable risk severity ratings, and presents actionable intelligence through an intuitive web-based security operations center (SOC) dashboard.

> **Defensive Scope Notice:** This system is engineered exclusively for authorized defensive network monitoring, anomaly detection, and operational incident triage. It does not include active penetration testing, exploitation mechanisms, or offensive tooling.

---

## 2. Project Objectives

1. **Intelligent Ingestion:** Ingest structured network flow telemetry (e.g., NetFlow/IPFIX, PCAP exports, and CSV logs) with minimal processing latency.
2. **Hybrid Machine Learning Pipeline:**
   - **Anomaly Detection:** Detect zero-day and outlier behaviors using unsupervised models (e.g., Isolation Forest).
   - **Threat Classification:** Accurately classify known threat vectors (DoS/DDoS, Port Scanning, Brute Force, Infiltration) via supervised ensembles (Random Forest, Gradient Boosting).
   - **Severity Scoring:** Compute dynamic risk indices (Low, Medium, High, Critical) based on prediction confidence, anomaly score, and destination criticality.
3. **High-Performance API & Persistence:** Expose clean, typed REST endpoints with FastAPI backed by SQLAlchemy ORM with dual-engine flexibility (SQLite for rapid local testing, PostgreSQL for scalable enterprise deployment).
4. **Actionable SOC Dashboard:** Provide network defenders with real-time incident counters, protocol breakdowns, active security alerts, event query filters, and ML model diagnostic monitoring.

---

## 3. Technology Stack

| Layer | Component | Selected Technology | Purpose |
| :--- | :--- | :--- | :--- |
| **Backend API** | Framework | **Python 3.12+ / FastAPI** | High-throughput asynchronous REST API, automatic OpenAPI/Swagger documentation |
| **ORM & DB** | Data Access | **SQLAlchemy 2.0** | Object-relational mapping supporting SQLite (dev) and PostgreSQL (prod) |
| **Data Engine** | Analytics | **Pandas, NumPy** | Vectorized network flow feature extraction and data preparation |
| **Machine Learning**| Algorithms | **Scikit-learn, Joblib** | Isolation Forest (anomaly) and Random Forest (classification), model persistence |
| **Frontend SPA** | Client UI | **React 18 + Vite** | Fast modern frontend architecture with client-side routing and state management |
| **UI & Styling** | Aesthetics | **Vanilla Modern CSS** | Clean glassmorphic SOC dark theme, cyber-defense palettes, responsive layouts |
| **Testing** | QA | **Pytest, HTTPX** | Automated integration and regression test suites |

---

## 4. System Architecture & End-to-End Data Flow

```
+-----------------------------------------------------------------------------------+
|                            Network Traffic Data Source                           |
|                    (NetFlow, IPFIX, PCAP Capture, CSV Feeds)                      |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                        1. Data Ingestion & Validation                             |
|               (Ingestion Service, Protocol Parsing, Schema Check)                 |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                          2. Preprocessing Pipeline                                |
|             (Missing Value Imputation, Timestamp Alignment, Encoding)             |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                       3. Feature Extraction & Scaling                             |
|     (Flow Duration, Packet/Byte Ratios, TCP Flag Metrics, StandardScaler)        |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                         4. ML Anomaly Detection                                   |
|                (Unsupervised Isolation Forest / Outlier Scoring)                  |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                        5. ML Threat Classification                                |
|        (Supervised Multi-Class Classifier: DoS, Probe, Brute Force, Normal)       |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                        6. Threat Severity Assessment                              |
|           (Risk Algorithm: Confidence * Impact Weight -> Severity Level)         |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                    7. Relational Persistence Layer (SQLAlchemy)                   |
|       [Traffic Records]  <->  [Threat Events]  <->  [Security Alerts]             |
|                       (PostgreSQL / SQLite Development DB)                        |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                            8. FastAPI REST Layer                                  |
|        (Endpoints: /api/health, /api/v1/traffic, /api/v1/threats, /alerts)        |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                     9. React SOC Monitoring Dashboard                             |
|    - Live System Status   - Threat Overview Counters   - Protocol Distributions   |
|    - Security Alert Feed  - Network Event Log Viewer   - Model Diagnostics        |
+-----------------------------------------------------------------------------------+
```

---

## 5. Directory Structure

```
Network_based/
├── .dockerignore                    # Root Docker exclusion rules
├── .env.example                     # Backend environment configuration template
├── .gitignore                       # Git exclusion rules
├── Dockerfile                       # Backend production container specification
├── docker-compose.yml               # Multi-container orchestration (PostgreSQL, Backend, Frontend)
├── README.md                        # Primary project documentation
├── requirements.txt                 # Backend & ML Python dependencies
├── backend/                         # Backend Application Layer
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                  # FastAPI application entrypoint & CORS config
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   └── v1/
│   │   │       ├── __init__.py
│   │   │       ├── api.py           # API V1 router aggregation
│   │   │       └── endpoints/
│   │   │           ├── __init__.py
│   │   │           ├── health.py    # GET /api/health implementation
│   │   │           ├── traffic.py   # Traffic ingestion & query routes (documented)
│   │   │           ├── threats.py   # Threat analysis routes (documented)
│   │   │           ├── alerts.py    # Alert triage routes (documented)
│   │   │           ├── metrics.py   # Dashboard telemetry routes (documented)
│   │   │           └── models.py    # Model performance endpoints (documented)
│   │   ├── core/
│   │   │   ├── __init__.py
│   │   │   ├── config.py            # Pydantic Settings configuration manager
│   │   │   └── errors.py            # Centralized exception handlers & responses
│   │   ├── db/
│   │   │   ├── __init__.py
│   │   │   └── session.py           # SQLAlchemy database session & engine factory
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   └── entities.py          # SQLAlchemy ORM entity definitions
│   │   ├── schemas/
│   │   │   ├── __init__.py
│   │   │   ├── health.py            # Health-check response schema
│   │   │   ├── traffic.py           # Traffic record schemas
│   │   │   ├── threats.py           # Threat schemas
│   │   │   └── alerts.py            # Alert schemas
│   │   └── services/
│   │       ├── __init__.py
│   │       └── health_service.py    # Health and readiness business logic
│   └── tests/
│       ├── __init__.py
│       └── test_health.py           # Pytest suite for health endpoint
├── frontend/                        # React + Vite Frontend
│   ├── .dockerignore                # Frontend Docker build exclusions
│   ├── .env.example                 # Frontend browser-safe environment template
│   ├── .gitignore                   # Frontend specific gitignore
│   ├── Dockerfile                   # Multi-stage production frontend container
│   ├── index.html                   # HTML entry page
│   ├── package.json                 # Node dependencies and scripts
│   ├── vite.config.js               # Vite build and proxy settings
│   └── src/
│       ├── main.jsx                 # React root renderer
│       ├── App.jsx                  # Main application layout & view switcher
│       ├── App.css                  # Component-specific styles
│       ├── index.css                # Global SOC dark theme, variables, utilities
│       ├── components/
│       │   ├── Sidebar.jsx          # SOC navigation sidebar
│       │   ├── Header.jsx           # Top header bar with live backend status
│       │   └── StatusBadge.jsx      # Reusable status pill component
│       └── pages/
│           ├── DashboardPlaceholder.jsx       # Real-time overview metrics
│           ├── AlertsPlaceholder.jsx          # Security incident queue
│           ├── NetworkEventsPlaceholder.jsx   # Network telemetry explorer
│           └── ModelPerformancePlaceholder.jsx # ML precision/recall diagnostics
├── database/                        # Database Schemas & Migrations
│   ├── README.md                    # Database documentation & ER notes
│   ├── schema.sql                   # Reference SQL DDL schema
│   └── seeds/
│       └── sample_traffic.json      # Sample seed data reference
├── machine-learning/                # ML Pipeline & Model Training
│   ├── README.md                    # ML architecture and training guides
│   ├── models/                      # Serialized model artifacts (.joblib/.pkl)
│   ├── notebooks/                   # Jupyter exploratory research notebooks
│   └── pipelines/                   # Reusable feature & prediction pipelines
├── datasets/                        # Datasets (Excluded from git)
│   ├── README.md                    # Dataset guidelines (NSL-KDD, CIC-IDS2017)
│   ├── raw/                         # Raw capture files
│   └── processed/                   # Cleaned and standardized features
├── documentation/                   # Detailed System Documentation
│   ├── architecture.md              # Deep-dive system architecture specification
│   ├── database_design.md           # ER diagrams and entity data dictionary
│   ├── api_specification.md         # Complete REST API blueprint
│   └── deployment_guide.md          # Setup and deployment manual
├── configuration/                   # Configuration References
│   └── README.md                    # Environment variable guide
└── tests/
    └── test_skeleton.py             # Top-level smoke test
```

---

## 6. Development Phases & Roadmap

- **Phase 1 (Completed): Architecture, Foundations & Skeleton**
  - Architectural blueprint & modular boundary definitions
  - Directory structure and repository standardization
  - Database schema and entity design (SQLAlchemy ORM + DDL)
  - REST API endpoint specifications & working `GET /api/health`
- **Phase 2 (Completed): Data Ingestion & Preprocessing Pipeline**
  - Network-flow dataset acquisition and cleaning (CIC-IDS2017)
  - Feature engineering, label normalization, and data-leakage prevention
  - Standardized scikit-learn preprocessing pipeline serialization (`preprocessor.joblib`)
- **Phase 3 (Completed): AI Anomaly Detection & Threat Classification**
  - Unsupervised Isolation Forest anomaly detector (`anomaly_detector.joblib`)
  - Supervised Random Forest multi-class threat classifier (`threat_classifier.joblib`)
  - Unified `NetworkPredictor` inference engine and dynamic severity scoring
- **Phase 4 (Completed): FastAPI AI Inference Integration**
  - `POST /api/v1/predict` endpoint with Pydantic flow validation
  - In-memory lifecycle model management (zero request-time retraining)
  - Defensive error sanitization and automated regression tests
- **Phase 5 (Completed): Database Integration & Prediction / Alert Persistence**
  - Relational persistence for prediction audit logs (`prediction_records`) and alerts (`alerts`)
  - Atomic transaction management via `PersistenceService`
  - Paginated audit queries: `GET /api/v1/predictions` and `GET /api/v1/alerts` with severity/status filters
- **Phase 6 (Completed): React Frontend Integration**
  - Professional SOC dark-mode React interface connected to live FastAPI backend
  - Centralized API service layer (`frontend/src/services/api.js`) consuming real REST endpoints
  - Interactive Flow Ingestion form with validation, NaN/Infinity guards, and viva presentation presets
  - Multi-card AI Prediction results displaying Isolation Forest divergence, Random Forest probabilities, and composite risk triage
  - Paginated Prediction Audit History with page size selectors and deterministic ordering
  - Filterable Security Incident Alerts table (severity and status filters)
  - SOC Dashboard overview computing metrics from database records
- **Phase 7 (Completed): Real-Time Security Monitoring**
  - FastAPI WebSocket endpoint (`/api/v1/ws/monitor`) with dedicated `WebSocketManager`
  - Transaction-safe event streaming: `prediction_created` and `alert_created` broadcast only after successful database commit
  - React application-level WebSocket service with controlled exponential reconnect backoff
  - Dashboard integration with live session counters, real-time bounded event feeds (max 20), and REST fallback
- **Phase 8 (Completed): Alert Management & Incident Response Dashboard**
  - Controlled alert lifecycle finite state machine (`NEW → ACKNOWLEDGED → RESOLVED`, `NEW → RESOLVED`)
  - Server-side transition validation enforcing `HTTP 409 Conflict` on invalid transitions and `HTTP 404` on missing records
  - Audit-friendly timezone-aware UTC timestamps (`created_at`, `acknowledged_at`, `resolved_at`)
  - REST endpoints: `GET /api/v1/alerts/{id}`, `PATCH /api/v1/alerts/{id}/acknowledge`, `PATCH /api/v1/alerts/{id}/resolve`
  - Real-time WebSocket lifecycle broadcasts (`alert_acknowledged`, `alert_resolved`) emitted strictly after database commit succeeds
  - Interactive Incident Investigation modal displaying detailed AI telemetry, UTC audit timestamps, and linked network flow metadata
  - Upgraded Security Alerts page with status/severity filters, inline lifecycle action buttons, and anti-duplicate request guards
  - Real-time frontend synchronization across live tables and modals upon WebSocket lifecycle events
- **Phase 9 (Completed): Authentication, RBAC & Secure Operator Access**
  - Cryptographic user authentication with salted `bcrypt` password hashing (adaptive cost factor 12)
  - Stateless JSON Web Tokens (PyJWT HS256) with configurable expiration and server-side secret management
  - Three-tier Role-Based Access Control (`ADMIN`, `ANALYST`, `VIEWER`) enforced via reusable FastAPI dependencies
  - Protected REST endpoints: read-only access for `VIEWER`, state-changing inference & alert triage restricted to `ADMIN` and `ANALYST` (HTTP 403 Forbidden enforcement)
  - Protected WebSocket telemetry (`/api/v1/ws/monitor`): unauthenticated connections rejected with close code `1008 (Policy Violation)`; token validated exclusively via application-level auth handshake frame (query-parameter tokens rejected to prevent URL/log leakage)
  - React login interface (`frontend/src/pages/Login.jsx`), centralized `AuthContext.jsx`, automatic Bearer token injection in `api.js`, and route protection
  - Role-gated frontend UI: alert action buttons hidden for Viewers, predictive submission disabled for Viewers, header displaying username, role badge, and logout action
  - Environment-driven development provisioning script (`python -m backend.scripts.create_admin`) with secure credential handling and idempotency
  - 89/89 passing automated backend tests and 0-error Vite production build
- **Phase 10 (Completed): Production Configuration & Deployment Readiness**
  - Centralized typed configuration via Pydantic Settings supporting standard `NIDS_*` environment variables (`NIDS_ENVIRONMENT`, `NIDS_DATABASE_URL`, `NIDS_JWT_SECRET`, `NIDS_JWT_ALGORITHM`, `NIDS_JWT_EXPIRE_MINUTES`, `NIDS_CORS_ORIGINS`, `NIDS_HOST`, `NIDS_PORT`, `NIDS_LOG_LEVEL`)
  - Strict production settings validation: rejects empty or insecure default placeholder JWT secrets in production, validates ports (1-65535), validates log levels, and strictly disallows wildcard (`*`) CORS origins in production
  - Comprehensive secret safety: `.gitignore` protection for `.env`, zero hardcoded credentials, and sanitized logging excluding authorization tokens and passwords
  - Structured, production-friendly logging with request audit middleware (`RequestAuditMiddleware`) tracking method, path, status, and duration
  - HTTP security headers middleware (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`) compatible with React frontend
  - PostgreSQL production database readiness with connection pooling (`psycopg2-binary`, `pool_size`, `max_overflow`, `pool_pre_ping=True`, `pool_recycle=3600`) while preserving SQLite for rapid local development
  - Containerization support: production-grade backend `Dockerfile` (Python 3.12-slim), multi-stage `frontend/Dockerfile` (Node 20 build -> Nginx Alpine), `.dockerignore` files, and `docker-compose.yml` orchestrating PostgreSQL 16, backend, and frontend with automated health checks
  - Browser-safe frontend configuration via `frontend/.env.example` (`VITE_API_BASE_URL`, `VITE_WS_BASE_URL`) with zero backend secrets exposed
  - Operational health monitoring via public `GET /api/health` reporting status, service name, version, environment, database connectivity, and ML engine status without exposing secrets or paths
  - 102/102 passing backend tests and 0-error Vite production build
  - Complete operational documentation in `documentation/deployment.md`
- **Phase 11 (Completed): API Rate Limiting & Abuse Protection**
  - Application-level API rate limiting powered by `slowapi` and in-memory bucket management with zero external dependencies (no Redis or Celery)
  - Endpoint rate quotas: login brute-force protection on `POST /api/v1/auth/login` (5/min), AI prediction inference bounding on `POST /api/v1/predict` (60/min), read query protection on `GET /predictions`, `/alerts`, `/auth/me` (120/min), and state mutation regulation on `PATCH /alerts/{id}/acknowledge`, `/resolve` (30/min)
  - Client identity strategy: uses authenticated operator claims (`user:<username>`) for authenticated callers to prevent shared-IP collisions, and peer socket IP (`ip:<client_ip>`) for unauthenticated requests
  - Anti-spoofing security: rejects untrusted `X-Forwarded-For` headers to prevent brute-force limit bypasses
  - Standardized HTTP 429 response envelopes with `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset` headers
  - Full RBAC preservation: VIEWER role remains strictly rejected with HTTP 403 on mutation endpoints
  - Configurable environment controls via `NIDS_RATE_LIMIT_*` with strict production enforcement (disabling rate limits in production mode is rejected on startup)
  - 119/119 passing automated backend tests and 0-error Vite production build
  - Complete operational documentation in `documentation/rate_limiting.md`
- **Phase 12 (Completed): Advanced Security Monitoring & Structured Audit Logging**
  - Development-oriented audit trail and security monitoring foundation answering Who, What, When, Resource, Outcome, and Safe Context
  - Standardized audit event taxonomy (`LOGIN_SUCCESS`, `LOGIN_FAILURE`, `LOGOUT`, `ACCESS_DENIED`, `PREDICTION_CREATED`, `ALERT_ACKNOWLEDGED`, `ALERT_RESOLVED`, `WEBSOCKET_AUTH_SUCCESS`, `WEBSOCKET_AUTH_FAILURE`, `RATE_LIMIT_EXCEEDED`, `SECURITY_ERROR`)
  - Dedicated SQLAlchemy `AuditLogRecord` model and database table (`audit_logs`) with composite indexes for timestamp, username, action, outcome, and resource
  - Centralized resilient `AuditService` with automatic recursive scrubbing of credentials, JWTs, Authorization headers, and secrets
  - Full handler instrumentation across authentication, RBAC authorization, predictions, alert lifecycle transitions, WebSocket handshake, and rate limiting
  - Authenticated query API (`GET /api/v1/audit-logs`) with multi-dimensional filtering, bounded pagination, and deterministic newest-first ordering
  - SOC security telemetry summary endpoint (`GET /api/v1/audit-logs/summary`) providing real-time aggregate counters (total events, failed logins, 403 denials, 429 throttles)
  - React frontend **Security Audit Logs** page with interactive filters, bounded pagination, and inspection modal
  - SOC Dashboard integration with a dedicated Security Audit & Access Telemetry card displaying live counters
  - 117/117 passing automated backend tests and 0-error Vite production build
  - Complete architectural documentation in `documentation/audit_logging.md`
- **Phase 13 (Completed): Security Analytics & Threat Intelligence Foundation**
  - Centralized security analytics data layer (`SecurityAnalyticsService`) providing aggregated statistics across predictions, alerts, and audit logs
  - REST endpoints: `GET /api/v1/analytics/overview`, `GET /api/v1/analytics/threat-distribution`, `GET /api/v1/analytics/timeline`, `GET /api/v1/analytics/top-sources`, and `GET /api/v1/analytics/investigate/{prediction_id}`
  - Extensible threat intelligence provider architecture (`ThreatIntelligenceProvider` interface) with a research reference provider (`LocalThreatIntelligenceProvider`) explicitly tagged as `LOCAL_DEMO_INTELLIGENCE` (zero external paid/commercial API dependencies)
  - Defensive threat intelligence lookup API (`GET /api/v1/threat-intelligence/ip/{ip_address}`) with strict RFC IPv4/IPv6 validation
  - Deterministic rule-based prediction explainability (`risk_reasons`) grounded directly in ML outlier scores, threat classifications, confidence metrics, and network port classifications without unverified SHAP/LIME claims
  - Forensic analyst investigation workflow aggregating predictions, model explanations, flow telemetry, linked alerts, audit logs, and threat intelligence
  - Frontend **Security Analytics** dashboard (`frontend/src/pages/SecurityAnalytics.jsx`) with KPI cards, threat category bars, severity distribution, event timeline, top attacking sources table, and analyst threat intelligence lookup console
  - Forensic prediction investigation modal available directly from **Prediction History** and **AI Prediction** pages
  - Seamless RBAC enforcement (ADMIN, ANALYST, VIEWER) and Phase 12 audit integration (`ANALYTICS_VIEWED`, `THREAT_INTELLIGENCE_LOOKUP`, `INVESTIGATION_VIEWED`)
  - 134/134 passing automated backend tests and 0-error Vite production build
  - Complete architectural documentation in `documentation/security_analytics.md`

- **Phase 14 (Completed): Real-Time SOC Operations & Incident Response Workflow**
  - Structured SOC incident management model (`IncidentRecord`, `IncidentNoteRecord`, association tables `incident_alerts` and `incident_predictions`)
  - Deterministic state machine lifecycle: `OPEN` -> `ACKNOWLEDGED` -> `INVESTIGATING` -> `CONTAINED` -> `RESOLVED` (enforces HTTP 409 Conflict on invalid transitions and requires mandatory resolution summary)
  - Sequential key generation format (`INC-YYYY-XXXXXX`) with indexed querying
  - Incident creation from alerts and predictions with severity, category, and source IP inheritance, plus duplicate active incident prevention
  - Operator assignment workflow with validation (requires active user and `ADMIN` or `ANALYST` role; blocks `VIEWER`)
  - Analyst forensic case notes with length validation and user association
  - Unified chronological incident timeline assembling status transitions, operator assignments, analyst notes, correlated alert telemetry, and audit trail events
  - Full REST API router at `/api/v1/incidents` with Pydantic validation, RBAC, and rate limiting
  - Audit logging integration (`INCIDENT_CREATED`, `INCIDENT_ASSIGNED`, `INCIDENT_STATUS_CHANGED`, `INCIDENT_NOTE_ADDED`, `INCIDENT_VIEWED`) with privacy-safe note scrubbing
  - Real-time WebSocket broadcasting (`incident_created`, `incident_status_changed`, `incident_assigned`, `incident_note_added`) over existing authenticated channel
  - Frontend **Incident Response Console** (`frontend/src/pages/Incidents.jsx`) with KPI metrics, multi-attribute filter toolbar, incidents table, creation modal, and live WebSocket streaming
  - Interactive **Incident Details Modal** (`frontend/src/components/IncidentDetails.jsx`) featuring operator action bar, notes feed, and visual state timeline
  - Security Alerts UI integration enabling one-click incident creation from any active alert row
  - Dashboard integration with a dedicated "Incident Response Summary" widget
  - 154/154 automated backend tests passing with zero regressions and clean Vite production build
  - Comprehensive architectural documentation in `documentation/incident_response.md`

- **Phase 15 (Completed): Automated Security Reporting & Evidence Export**
  - Comprehensive reporting service (`ReportingService`) synthesizing flow evaluations, threat detections, alerts, incident cases, and audit logs
  - Flexible, bounded time ranges (`last_1h`, `last_24h`, `last_7d`, `last_30d`, and validated custom datetime windows up to 90 days)
  - Multi-format executive reporting supporting **JSON** payloads, **CSV** spreadsheets, and polished vector **PDF** documents (built with ReportLab)
  - Raw dataset export endpoints streaming RFC 4180 CSV for predictions, alerts, incidents, and audit trails with bounded record limits (max 1000 items)
  - Tamper-evident incident evidence packages with SHA-256 cryptographic chain-of-custody checksums available in structured JSON and multi-file ZIP bundles
  - REST endpoints mounted at `/api/v1/reports`: `/security`, `/predictions`, `/alerts`, `/incidents`, `/audit-logs`, `/incidents/{id}/evidence`
  - Integrated RBAC authorization allowing ADMIN, ANALYST, and read-only VIEWER roles to access reporting and export features while strictly preventing unauthenticated access
  - Extended security audit logging with `REPORT_GENERATED`, `REPORT_EXPORTED`, and `INCIDENT_EVIDENCE_EXPORTED` events with privacy-safe metadata scrubbing
  - Frontend **Security Reports** page (`frontend/src/pages/Reports.jsx`) with parameter controls, live executive preview, format exports, and dataset download cards
  - Forensic evidence export buttons directly integrated into the `IncidentDetails` modal
  - 171/171 automated backend tests passing across Phases 1–15 and 0-error Vite production build
  - Comprehensive architectural documentation in `documentation/security_reporting.md`

- **Phase 16 (Completed): Advanced Threat Hunting & Investigation Workbench**
  - Multi-dimensional search engine across predictions, alerts, and incidents with strict validation (RFC IPv4/IPv6 verification, port ranges 1–65535, anomaly scores -1.0 to 1.0, confidence 0.0 to 1.0, maximum 90-day time window, maximum 200 items per slice)
  - Deterministic correlation engine synthesizing network convergence across ports, temporal bursts (<= 10m), and linked incident cases with defensive disclaimer notices
  - Deep-dive source-centric host investigation (`GET /api/v1/hunting/source/{ip}`) providing first/last seen timestamps, threat category breakdown, severity distributions, top destination endpoints, and unified chronological timeline
  - Lightweight, sanitized query history persistence (`GET /api/v1/hunting/history`) enabling analysts to quickly reload previous multi-attribute searches
  - Seamless Phase 13 investigation integration reusing the existing deep flow investigation modal
  - Frontend **Threat Hunting** workbench (`frontend/src/pages/ThreatHunting.jsx`) featuring query builder, correlation cards, tabbed results, source investigation modal, and query history reloader
  - Navigation integration in `Sidebar.jsx` and `App.jsx`
  - Strict RBAC authorization (ADMIN, ANALYST, and read-only VIEWER permitted; unauthenticated requests rejected with 401)
  - Centralized audit logging (`THREAT_HUNT_SEARCHED`, `SOURCE_INVESTIGATION_VIEWED`, `THREAT_HUNT_HISTORY_VIEWED`) with privacy-safe filter summaries
  - 196/196 automated backend regression tests passing (25 new dedicated tests) and 0-error Vite production build
  - Comprehensive architectural documentation in `documentation/threat_hunting.md`

---

## 7. Installation & Quick Start Prerequisites

### Prerequisites
- **Python 3.12+** ([python.org](https://www.python.org/))
- **Node.js 20+ / 24+ LTS** & **npm** ([nodejs.org](https://nodejs.org/))
- **Git**

### Step 1: Clone Repository & Setup Configuration
```bash
# Clone the repository
git clone <repo-url>
cd Network_based

# Initialize environment configuration
copy .env.example .env
```

### Step 2: Backend Setup
```bash
# Optional: Create and activate virtual environment
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# Linux/macOS:
# source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Run the FastAPI backend server
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```
Verify the health endpoint:
- Open your browser or use curl: `http://127.0.0.1:8000/api/health`
- Interactive Swagger API docs: `http://127.0.0.1:8000/docs`

### Step 3: Frontend Setup
In a new terminal window:
```bash
cd frontend

# Install dependencies
npm install

# Start Vite development server
npm run dev
```
Open your browser to: `http://localhost:5173`

### Step 4: Docker Compose Deployment (Alternative)
To deploy the complete containerized stack (PostgreSQL 16, FastAPI backend, and React frontend) using Docker Compose:
```bash
# 1. Initialize environment file
copy .env.example .env

# 2. Build and launch all services in detached mode
docker compose up -d --build

# 3. Check service health
docker compose ps
curl http://127.0.0.1:8000/api/health

# 4. Graceful shutdown
docker compose down
```
For deep-dive configuration details, see [documentation/deployment.md](documentation/deployment.md).

---

## 8. Security & Defensive Disclaimer

This project is developed solely as an educational and defensive security project for network intrusion detection and security monitoring. It contains **no offensive capabilities** such as exploit payloads, traffic injection, or denial-of-service tools. All data utilized must be from authorized lab environments or publicly approved research datasets (e.g., CIC-IDS2017, NSL-KDD).
