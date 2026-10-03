# REST API Specification (Planned & Phase 1 Implemented)

## 1. Overview & Base Conventions

- **Base URL:** `http://127.0.0.1:8000`
- **API Prefix:** `/api/v1` (with `/api/health` at root level)
- **Data Format:** `application/json`
- **Error Format:** Standardized JSON error response:
  ```json
  {
    "status": "error",
    "error_code": "RESOURCE_NOT_FOUND",
    "message": "The requested threat record was not found.",
    "details": null,
    "timestamp": "2026-10-03T12:00:00Z"
  }
  ```

---

## 2. API Endpoint Matrix

| Method | Endpoint | Status | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/health` | **Implemented (Phase 1/4)** | System health, service status, uptime & ML readiness |
| `POST`| `/api/v1/predict` | **Implemented (Phase 4)** | Predict flow anomaly, classify threat family & compute risk triage |
| `POST` | `/api/v1/traffic/ingest` | Documented (Phase 2) | Ingest single or batch network traffic flow records |
| `GET` | `/api/v1/traffic` | Documented (Phase 2) | Query traffic records with filtering & pagination |
| `GET` | `/api/v1/traffic/{id}` | Documented (Phase 2) | Retrieve a single traffic record by ID |
| `GET` | `/api/v1/threats` | Documented (Phase 3) | List detected threats with severity filters |
| `GET` | `/api/v1/threats/{id}` | Documented (Phase 3) | Get detailed threat inspection and feature analysis |
| `POST` | `/api/v1/threats/{id}/mitigate`| Documented (Phase 3) | Record mitigation status for an identified threat |
| `GET` | `/api/v1/alerts` | Documented (Phase 3) | List security alerts for SOC triage |
| `PATCH`| `/api/v1/alerts/{id}/status` | Documented (Phase 3) | Update alert status (`ACKNOWLEDGED`, `RESOLVED`) |
| `GET` | `/api/v1/alerts/statistics` | Documented (Phase 3) | Aggregated alert metrics by severity & category |
| `GET` | `/api/v1/metrics/overview` | Documented (Phase 4) | High-level SOC telemetry (events/sec, threat counts) |
| `GET` | `/api/v1/models/status` | Documented (Phase 4) | Active ML models, version metadata, and drift metrics|
| `POST` | `/api/v1/models/evaluate` | Documented (Phase 4) | Run diagnostic evaluation on recent flow batches |

---

## 3. Endpoint Specifications

### 3.1 Health Check (Implemented in Phase 1)
- **Endpoint:** `GET /api/health`
- **Auth:** None
- **Response (200 OK):**
  ```json
  {
    "status": "healthy",
    "service": "AI Network Intrusion Detection System",
    "version": "1.0.0-phase1",
    "environment": "development",
    "timestamp": "2026-10-03T12:00:00.000Z",
    "components": {
      "database": "connected",
      "ml_engine": "ready",
      "api": "online"
    }
  }
  ```

---

### 3.2 AI Threat Prediction (Implemented in Phase 4)
- **Endpoint:** `POST /api/v1/predict`
- **Auth:** None (Phase 4)
- **Description:** Submits network flow telemetry for real-time dual-stage inference: Isolation Forest outlier detection, Random Forest multiclass classification, and SOC risk rating.
- **Request Body (JSON):**
  ```json
  {
    "Destination Port": 443,
    "Flow Duration": 245012,
    "Total Fwd Packets": 14,
    "Total Backward Packets": 18,
    "Total Length of Fwd Packets": 1240,
    "Total Length of Bwd Packets": 18450,
    "Flow Bytes/s": 80363.41,
    "Flow Packets/s": 130.60,
    "Protocol": 6
  }
  ```
- **Response (200 OK):**
  ```json
  {
    "anomaly": {
      "is_anomaly": false,
      "anomaly_label": "NORMAL",
      "anomaly_score": 0.284,
      "raw_decision_score": 0.108,
      "interpretation": "Outlier divergence score: 0.284 (0.0=nominal, 1.0=severe outlier)."
    },
    "classification": {
      "predicted_label": "BENIGN",
      "is_intrusion": false,
      "confidence": 0.40,
      "confidence_type": "estimated_class_probability",
      "class_probabilities": {
        "BENIGN": 0.40,
        "Bot": 0.25,
        "DoS": 0.08,
        "Infiltration": 0.12,
        "Port Scan": 0.01,
        "Web Attack": 0.14
      }
    },
    "risk_assessment": {
      "risk_level": "LOW",
      "recommended_action": "Standard Flow Logging",
      "summary": "Flow evaluated: Anomaly=NORMAL (score 0.28), Classification='BENIGN' (est. prob 40.0%). Assigned Risk Level: LOW."
    }
  }
  ```
- **Error Responses:**
  - `422 Unprocessable Content`: Empty payload, NaN/Infinity, non-numeric values.
  - `503 Service Unavailable`: Model artifacts missing or failed to initialize.
  - `500 Internal Server Error`: Unexpected internal computation failure (stack traces suppressed).

---

### 3.3 Network Traffic Ingestion (Phase 2)
- **Endpoint:** `POST /api/v1/traffic/ingest`
- **Request Body (Batch):**
  ```json
  {
    "batch_id": "bfa89a31-01f2-4bc6-bf63-8a39c8789312",
    "records": [
      {
        "captured_at": "2026-10-03T12:05:01Z",
        "source_ip": "192.168.1.105",
        "destination_ip": "10.0.0.1",
        "source_port": 54212,
        "destination_port": 80,
        "protocol": "TCP",
        "duration_seconds": 1.25,
        "total_packets": 24,
        "total_bytes": 1820,
        "flags": {
          "syn": 1,
          "ack": 1,
          "rst": 0,
          "fin": 1
        }
      }
    ]
  }
  ```
- **Response (202 Accepted):**
  ```json
  {
    "status": "success",
    "processed_count": 1,
    "anomalies_detected": 0,
    "batch_id": "bfa89a31-01f2-4bc6-bf63-8a39c8789312"
  }
  ```

---

### 3.3 Security Alerts Query (Phase 3)
- **Endpoint:** `GET /api/v1/alerts`
- **Query Parameters:**
  - `severity`: `LOW` | `MEDIUM` | `HIGH` | `CRITICAL`
  - `status`: `NEW` | `ACKNOWLEDGED` | `RESOLVED` | `FALSE_POSITIVE`
  - `limit`: Integer (default: 50, max: 200)
  - `offset`: Integer (default: 0)
- **Response (200 OK):**
  ```json
  {
    "total": 142,
    "page": 1,
    "limit": 50,
    "data": [
      {
        "id": "7fa84e90-c119-482a-bc91-2bb4501a1c32",
        "title": "High-Volume SYN Flood Inbound",
        "description": "Suspicious high-frequency SYN packets targeted at web cluster 10.0.0.1:443",
        "severity": "CRITICAL",
        "status": "NEW",
        "threat_type": "DoS_SYN_Flood",
        "confidence": 0.94,
        "source_ip": "203.0.113.88",
        "created_at": "2026-10-03T12:04:12Z"
      }
    ]
  }
  ```

---

### 3.4 ML Model Status & Metrics (Phase 4)
- **Endpoint:** `GET /api/v1/models/status`
- **Response (200 OK):**
  ```json
  {
    "models": [
      {
        "name": "isolation_forest_ids",
        "version": "1.0.0",
        "algorithm": "Isolation Forest (Unsupervised)",
        "status": "LOADED",
        "last_trained": "2026-10-01T00:00:00Z",
        "features_count": 18,
        "average_inference_time_ms": 1.4
      },
      {
        "name": "threat_classifier_rf",
        "version": "1.0.0",
        "algorithm": "Random Forest Classifier",
        "status": "LOADED",
        "accuracy": 0.978,
        "f1_score": 0.972,
        "classes": ["Normal", "DoS", "PortScan", "BruteForce", "Infiltration"]
      }
    ]
  }
  ```
