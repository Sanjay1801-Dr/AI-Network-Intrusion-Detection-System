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
├── .env.example                     # Environment configuration template
├── .gitignore                       # Git exclusion rules
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
│   ├── index.html                   # HTML entry page
│   ├── package.json                 # Node dependencies and scripts
│   ├── vite.config.js               # Vite build and proxy settings
│   ├── .gitignore                   # Frontend specific gitignore
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

## 6. Development Phases

- **Phase 1 (Current): Architecture, Foundations & Skeleton**
  - Architectural blueprint & modular boundary definitions
  - Directory structure and repository standardization
  - Environment strategy (`.env.example`) and `.gitignore`
  - Database schema and entity design (SQLAlchemy ORM + DDL)
  - REST API endpoint specifications
  - Backend skeleton with working `GET /api/health` and CORS
  - Modern React frontend skeleton with SOC navigation and view placeholders
- **Phase 2: Data Ingestion & Preprocessing Pipeline**
  - Parsing PCAP and flow logs into standardized schemas
  - Pandas/NumPy preprocessing, missing-value imputation, feature engineering
  - Integration tests for data ingestion endpoints
- **Phase 3: Machine Learning Model Development & Inference Engine**
  - Train and evaluate Isolation Forest on benchmark datasets (NSL-KDD / CIC-IDS2017)
  - Train multi-class classifier (Random Forest / LightGBM)
  - Pipeline serialization with Joblib and inference service integration
  - Dynamic severity scoring logic
- **Phase 4: Full-Stack Integration, Live Monitoring & Threat Triage**
  - Connect React charts to live backend metrics
  - Real-time event streaming / polling
  - Alert resolution and incident management workflows
  - Comprehensive end-to-end testing and performance tuning

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

---

## 8. Security & Defensive Disclaimer

This project is developed solely as an educational and defensive security project for network intrusion detection and security monitoring. It contains **no offensive capabilities** such as exploit payloads, traffic injection, or denial-of-service tools. All data utilized must be from authorized lab environments or publicly approved research datasets (e.g., CIC-IDS2017, NSL-KDD).
