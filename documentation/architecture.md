# System Architecture & Technical Specification

## 1. Architectural Philosophy

The **AI-Based Network Intrusion Detection System (NIDS)** is structured according to **Clean Architecture** and **Layered Separation of Concerns**:

- **Decoupled Business & ML Logic:** Machine learning models and statistical transformations run in isolated processing services, keeping the API routing layer lean and declarative.
- **Dual-Engine Persistence Abstraction:** SQLAlchemy ORM encapsulates all database operations, allowing identical application logic to operate seamlessly on SQLite (for developer agility and continuous integration) and PostgreSQL (for high-volume concurrent production storage).
- **Stateless Web Services:** FastAPI backend services are designed to be stateless, allowing horizontal scaling behind reverse proxies (Nginx / Traefik).
- **SOC Single-Page Application (SPA):** The React frontend is decoupled from server-side rendering, consuming only versioned RESTful JSON APIs and WebSocket streams for real-time telemetry.

---

## 2. End-to-End Data Flow

```
                      [ External Network Flow Stream / Packet Capture ]
                                             │
                                             ▼
                               ┌───────────────────────────┐
                               │  1. Data Ingestion Layer  │
                               │  (HTTP / Batch File / CSV)│
                               └─────────────┬─────────────┘
                                             │
                                             ▼
                               ┌───────────────────────────┐
                               │ 2. Preprocessing & Clean  │
                               │  (Pandas / Imputation)    │
                               └─────────────┬─────────────┘
                                             │
                                             ▼
                               ┌───────────────────────────┐
                               │ 3. Feature Extraction     │
                               │  (Statistical Flow Metrics│
                               └─────────────┬─────────────┘
                                             │
                                             ▼
                       ┌───────────────────────────────────────────┐
                       │        4. Machine Learning Engine         │
                       │ ┌──────────────────┐ ┌──────────────────┐ │
                       │ │ Anomaly Detector │ │Threat Classifier │ │
                       │ │(Isolation Forest)│ │ (Random Forest)  │ │
                       │ └────────┬─────────┘ └────────┬─────────┘ │
                       └──────────┼────────────────────┼───────────┘
                                  └──────────┬─────────┘
                                             │
                                             ▼
                               ┌───────────────────────────┐
                               │  5. Severity Assessment   │
                               │  (Calculated Risk Matrix) │
                               └─────────────┬─────────────┘
                                             │
                                             ▼
                               ┌───────────────────────────┐
                               │ 6. Storage & Event Log    │
                               │   (SQLAlchemy / DB)       │
                               └─────────────┬─────────────┘
                                             │
                                             ▼
                               ┌───────────────────────────┐
                               │ 7. FastAPI Gateway Layer  │
                               │   (/api/v1 REST Endpoints)│
                               └─────────────┬─────────────┘
                                             │
                                             ▼
                               ┌───────────────────────────┐
                               │ 8. React SOC Dashboard    │
                               │   (Visual Alerts, Charts) │
                               └───────────────────────────┘
```

### Detailed Stage Breakdown:

1. **Network Traffic Ingestion:**
   Network records enter via REST endpoint (`/api/v1/traffic/ingest`) or simulated batch queue. Raw flow metrics include: source IP, destination IP, source port, destination port, protocol (TCP/UDP/ICMP), packet count, byte volume, TCP flags (SYN, ACK, FIN, RST, PSH, URG), and duration.
2. **Data Preprocessing:**
   Ensures schema integrity. Null fields are imputed, IP addresses are validated, invalid timestamps are normalized, and protocol names are mapped to categorical integers.
3. **Feature Extraction:**
   Calculates flow behavioral indicators:
   - Packet rate (`packets / duration`)
   - Byte rate (`bytes / duration`)
   - Average packet size (`bytes / packets`)
   - Ratio of SYN flags to total packets (common indicator of SYN flooding/port sweeps)
   - Connection frequency per destination host.
4. **Machine Learning Anomaly Detection:**
   Unsupervised models (Isolation Forest) compute an anomaly score between `-1.0` and `1.0`. Scores below the threshold indicate an unusual deviation from established baselines (potential zero-day or covert channel).
5. **Supervised Threat Classification:**
   If flagged as anomalous or evaluated in standard inspection, a trained classifier (Random Forest / Gradient Boosted Trees) assigns probability across threat classes:
   - `Normal`
   - `DoS / DDoS` (SYN Flood, UDP Flood, Slowloris)
   - `Port Scan / Probe` (Nmap sweeps, TCP SYN discovery)
   - `Brute Force` (SSH, FTP, HTTP authentication attempts)
   - `Infiltration / Malicious Flow`
6. **Threat Severity Calculation:**
   Determines a standardized severity rating (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`):
   $$\text{Severity Score} = (\text{Confidence} \times 0.4) + (\text{Anomaly Outlier Degree} \times 0.3) + (\text{Asset Criticality} \times 0.3)$$
7. **Database Persistence:**
   - Network flow stored in `traffic_records`.
   - Predictions and detections recorded in `ml_predictions` and `threat_events`.
   - High-severity incidents auto-trigger records in `security_alerts`.
8. **FastAPI Delivery:**
   Serializes records using Pydantic v2 schemas. Employs async database queries with pagination and filtering.
9. **React Dashboard Presentation:**
   Security analysts view real-time incident counters, visual breakdown charts, filterable incident tables, and system health badges.

---

## 3. Major Module Responsibilities

| Module | Core Responsibility |
| :--- | :--- |
| **`backend.app.api`** | HTTP route definitions, URL path routing, request validation via Pydantic, status code handling, dependency injection. |
| **`backend.app.core`** | Configuration loading (`pydantic-settings`), environment variables, global security settings, custom exception classes, and logging setup. |
| **`backend.app.db`** | Database session lifecycle management, connection pooling, and migrations. |
| **`backend.app.models`** | SQLAlchemy declarative models defining table schemas, columns, constraints, foreign keys, and indexes. |
| **`backend.app.schemas`** | Pydantic request and response schemas validating input payloads and controlling serialization formats. |
| **`backend.app.services`** | Pure business logic, including ingestion validation, severity score algorithms, and alert generation. |
| **`machine-learning`** | Model training scripts, feature engineering pipelines, hyperparameter tuning, model artifact serialization, and inference wrappers. |
| **`frontend.src.components`** | Reusable visual components (Navigation Sidebar, App Header, Metric Cards, Status Badges, Severity Chips). |
| **`frontend.src.pages`** | Primary view controllers (Dashboard Overview, Alerts Management, Network Flow Inspector, ML Model Diagnostics). |
