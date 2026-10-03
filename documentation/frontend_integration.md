# Phase 6: React Frontend Integration Documentation

## 1. Executive Summary

Phase 6 implements the complete web frontend integration for the **AI-Based Network Intrusion Detection System (NIDS)**. The user interface provides a cybersecurity/SOC-inspired operations dashboard that directly consumes real FastAPI REST endpoints without mock data, fake metrics, or client-side fabrication.

All frontend components strictly observe the Phase 6 boundary: connecting to the existing Phase 5 REST APIs, rendering live model inference outputs, displaying database-backed prediction audit trails, and presenting filterable security alert queues.

---

## 2. Frontend Architecture

The frontend follows a modular, feature-oriented Single Page Application (SPA) architecture built on **React 18** and **Vite**:

```
frontend/
├── .env                       # Environment configuration (VITE_API_BASE_URL)
├── index.html                 # HTML5 document entrypoint
├── package.json               # Node dependencies and scripts
├── vite.config.js             # Vite development server and API proxy configuration
└── src/
    ├── main.jsx               # React DOM root mounting
    ├── App.jsx                # Top-level state, active navigation, and initial health check
    ├── App.css                # Component styling, form controls, badges, and layout
    ├── index.css              # SOC design system tokens, typography, and dark theme
    ├── components/
    │   ├── Header.jsx         # Header with backend connection status badge and manual refresh
    │   ├── Sidebar.jsx        # Primary SOC navigation menu and system metadata
    │   └── StatusBadge.jsx    # High-contrast semantic badges for risk, severity, status
    ├── pages/
    │   ├── Dashboard.jsx      # SOC overview, live metrics, and recent feeds
    │   ├── AIPrediction.jsx   # Flow telemetry ingestion form, presets, and AI results
    │   ├── PredictionHistory.jsx # Paginated database audit log with limit selector
    │   └── SecurityAlerts.jsx # Paginated security alerts with severity & status filters
    ├── services/
    │   └── api.js             # Centralized API service with error sanitization
    ├── types/
    │   └── index.js           # JSDoc contracts and enum constants
    └── utils/
        └── formatters.js      # Date, number, percentage, score, and protocol helpers
```

---

## 3. Environment & Configuration

The frontend communicates with the FastAPI backend using a configurable base URL:

- **Environment Variable:** `VITE_API_BASE_URL` in `frontend/.env`:
  ```bash
  VITE_API_BASE_URL=http://127.0.0.1:8000
  ```
- **Vite Proxy Fallback (`vite.config.js`):**
  ```javascript
  server: {
    port: 5173,
    host: '127.0.0.1',
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  }
  ```
- **CORS Support:** Backend `ALLOWED_ORIGINS` in `backend/app/core/config.py` allows `http://127.0.0.1:5173` and `http://localhost:5173`. Arbitrary wildcards (`*`) are disallowed.

---

## 4. Centralized API Service (`src/services/api.js`)

All network requests flow through `api.js`. Component files never make direct `fetch()` calls or hardcode endpoint paths.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `api.checkHealth()` | `GET /api/health` | Queries system status and subsystem components |
| `api.predictFlow(payload)` | `POST /api/v1/predict` | Executes dual-stage AI inference and persists records |
| `api.getPredictions({ limit, offset })` | `GET /api/v1/predictions` | Retrieves paginated prediction audit history (newest first) |
| `api.getAlerts({ limit, offset, severity, status })` | `GET /api/v1/alerts` | Retrieves paginated security alerts with parameterized filters |

### Defensive Error Sanitization
The service intercepts network failures, HTTP 422, HTTP 500, and HTTP 503 errors and translates them into user-friendly `ApiError` instances. Under no circumstances are Python tracebacks, database schema queries, or filesystem paths displayed to users.

---

## 5. UI Views & Pages

### 5.1 SOC Dashboard (`src/pages/Dashboard.jsx`)
- **Real Metrics:** Computes total flows evaluated, total security alerts, and high/critical alert counts directly from retrieved API records.
- **Subsystem Diagnostics:** Displays current subsystem health status for SQLite Database, ML Inference Engine (Isolation Forest & Random Forest), and FastAPI Gateway.
- **Recent Feeds:** Displays the 5 most recent predictions and 5 most recent alerts with quick navigation links.

### 5.2 AI Threat Prediction (`src/pages/AIPrediction.jsx`)
- **Flow Telemetry Ingestion Form:** Accepts standard CIC-IDS2017 features (Destination Port, Flow Duration, Packets, Bytes, Protocol, IAT, Flags).
- **Client-Side Validation:** Rejects empty submissions, negative values, and non-numeric inputs (preventing NaN or Infinity).
- **Viva Demo Presets:** Includes one-click presets for rapid demonstration:
  - *Normal HTTPS Web Flow* (Benign web traffic)
  - *DoS SYN Flood Attack* (High-rate intrusive traffic)
  - *Port Scan Probe* (Reconnaissance traffic)
  - *Clear Form*
- **Prediction Result Breakdown:**
  - **Composite Risk Assessment:** Displays Risk Level (LOW, MEDIUM, HIGH, CRITICAL), SOC action guidance, and diagnostic summary.
  - **Isolation Forest Anomaly:** Displays outlier status, normalized outlier divergence score bar [0.0, 1.0], raw decision score, and interpretation.
  - **Random Forest Classification:** Displays predicted label, intrusion flag, estimated class probability, and horizontal probability breakdown bars across all attack families.

### 5.3 Prediction History (`src/pages/PredictionHistory.jsx`)
- **Database Telemetry:** Consumes `GET /api/v1/predictions`.
- **Pagination Controls:** Supports limit selector (10, 20, 50 per page), previous/next navigation, total record count, and page index.
- **Columns:** ID, Timestamp, Destination IP & Port, Protocol, Threat Label, Intrusion Badge, Anomaly Score, Estimated Probability, Risk Level, Recommended Action.
- **State Handling:** Dedicated loading spinner, empty database state, and error alert with retry button.

### 5.4 Security Incident Alerts (`src/pages/SecurityAlerts.jsx`)
- **Database Telemetry:** Consumes `GET /api/v1/alerts`.
- **Filtering:** Real-time dropdown filters for **Severity** (`ALL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) and **Status** (`ALL`, `NEW`, `ACKNOWLEDGED`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`).
- **Read-Only Scope:** Observes Phase 6 boundary with no mutation actions.
- **Columns:** Alert ID, Prediction ID, Timestamp, Alert Type, Severity, Threat Family, Anomaly Score, Confidence, Status, Recommended Action.

---

## 6. How to Run the System

### Step 1: Start Backend (Terminal 1)
```bash
cd "C:\Users\SANJAY SK\Desktop\Network_based"
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
- Health Check: `http://127.0.0.1:8000/api/health`
- Swagger Docs: `http://127.0.0.1:8000/docs`

### Step 2: Start Frontend (Terminal 2)
```bash
cd "C:\Users\SANJAY SK\Desktop\Network_based\frontend"
npm run dev
```
- Open browser at: `http://127.0.0.1:5173/`

### Step 3: Run Frontend Production Build Check
```bash
cd "C:\Users\SANJAY SK\Desktop\Network_based\frontend"
npm run build
```

---

## 7. Manual Verification Results

1. **Backend Health Check:** Verified via `GET /api/health` — returns status `healthy` with `ml_engine: ready`, `database: connected`, and `api: online`.
2. **Frontend Production Build:** `npm run build` compiled 1,494 modules in 6.41 seconds with 0 errors and 0 warnings.
3. **Automated Backend Regression:** All 49 existing pytest tests pass without regression (100% pass rate).
4. **End-to-End AI Prediction:** Executed real inference with flow telemetry payload:
   - Output: `anomaly_label: NORMAL` (score `0.4996`), `predicted_label: DoS` (confidence `0.61`), `risk_level: MEDIUM`.
5. **Persistence Verification:** Verified via `GET /api/v1/predictions?limit=1` — record #22 correctly persisted in database.
6. **Alert Generation Verification:** Verified via `GET /api/v1/alerts?limit=1` — alert #7 correctly created with severity `MEDIUM` linked to prediction #22.

---

## 8. Phase Boundary Confirmation

Phase 6 implements exclusively frontend integration with the existing REST APIs.
The following features belong to Phase 7 or later and were **strictly NOT implemented**:
- No automatic polling loops, periodic health polling, or continuous background requests (only a single initial health check upon application load, with manual health refresh on demand).
- No WebSockets or Server-Sent Events (SSE).
- No real-time packet capturing or PCAP streaming.
- No live network interface sniffing.
- No alert editing/acknowledgement mutation workflows.
- No user authentication or role-based access control (RBAC).
- No Docker containerization or cloud deployment scripts.
