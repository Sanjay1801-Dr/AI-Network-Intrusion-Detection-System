# Machine Learning Subsystem — Anomaly Detection & Threat Classification

## 1. Subsystem Architecture

The Machine Learning subsystem operates as a dual-engine defensive intelligence architecture:

```text
                               Raw Network Flow Telemetry
                                           │
                                           ▼
                      ┌─────────────────────────────────────────┐
                      │    Phase 2 Preprocessing & Features     │
                      │  (Cleaning, Imputation, Ratio Scaling)  │
                      └────────────────────┬────────────────────┘
                                           │
                                           ▼
                                42-D Model Feature Vector
                                           │
                    ┌──────────────────────┴──────────────────────┐
                    ▼                                             ▼
     ┌─────────────────────────────┐               ┌─────────────────────────────┐
     │  Unsupervised Anomaly Model │               │ Supervised Classifier Model │
     │     (Isolation Forest)      │               │       (Random Forest)       │
     └──────────────┬──────────────┘               └──────────────┬──────────────┘
                    │                                             │
                    ▼                                             ▼
          Anomaly Deviation Score                       Predicted Threat Class
              [0.0 to 1.0]                               & Posterior Confidence
                    │                                             │
                    └──────────────────────┬──────────────────────┘
                                           │
                                           ▼
                      ┌─────────────────────────────────────────┐
                      │       Combined Decision Logic Layer     │
                      │        (Risk Level: LOW to CRITICAL)    │
                      └─────────────────────────────────────────┘
```

- **Stage 1 (Unsupervised Anomaly Detection):** Identifies outlier network flows and structural behavioral deviations without requiring attack labels.
- **Stage 2 (Supervised Threat Classification):** Classifies network flows into specific recognized attack families (DoS, Port Scan, Brute Force, Web Attack, Bot, Infiltration, etc.).
- **Stage 3 (Unified Risk Decision):** Synthesizes outlier metrics and supervised probabilities to produce an actionable SOC risk triage level (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).

---

## 2. Directory Layout

```text
machine_learning/
├── __init__.py
├── models/
│   ├── .gitkeep
│   ├── preprocessor.joblib            # Frozen Scikit-learn ColumnTransformer
│   ├── anomaly_detector.joblib        # Fitted Isolation Forest model
│   ├── threat_classifier.joblib       # Fitted Random Forest multi-class model
│   └── model_metadata.json            # Model specifications, hyperparameters & splits
├── pipelines/
│   ├── __init__.py                    # Lazy attribute exports
│   ├── dataset_loader.py              # Resilient CSV loader with sample fallback
│   ├── dataset_inspector.py           # Deep dataset hygiene inspection
│   ├── feature_engineering.py         # Dynamic packet/byte rate & ratio derivation
│   └── preprocessing.py               # Cleaning, encoding & scaling pipeline
├── training/
│   ├── __init__.py
│   ├── train_anomaly_detector.py      # Isolation Forest trainer
│   ├── train_threat_classifier.py     # Random Forest trainer with class-weight balance
│   └── train_models.py                # Master training & evaluation orchestrator
├── evaluation/
│   ├── __init__.py
│   ├── evaluate_anomaly.py            # Anomaly diagnostic distributions & detection rate
│   ├── evaluate_classifier.py         # Multi-class accuracy, F1, and confusion matrix
│   ├── reports.py                     # Report serialization utilities
│   ├── classification_report.json     # Per-class precision, recall, and support
│   ├── confusion_matrix.csv           # Multi-class confusion matrix
│   ├── feature_importance.csv         # Ranked Gini feature importances
│   └── model_metrics.json             # Consolidated evaluation catalog
└── inference/
    ├── __init__.py
    └── predictor.py                   # Runtime NetworkPredictor inference engine
```

---

## 3. Anomaly Detection Engine (Isolation Forest)

### Mathematical Basis
Isolation Forest exploits two quantitative properties of anomalies: they are *few in number* and possess *attribute-value differences* compared to normal inliers. By recursively partitioning feature space using random orthogonal hyperplanes, anomalies are isolated near the root of the trees (shorter average path length $h(x)$).

### Scoring Convention & Directionality
1. **Raw Decision Function:**
   $$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$
   Scikit-learn's `decision_function(X)` produces a signed score offset by the contamination threshold: negative values denote outliers, while positive values denote inliers.
2. **Normalized Anomaly Score:**
   $$\text{anomaly\_score} = \text{clip}\left(0.50 - (\text{raw\_score} \times 2.0), 0.0, 1.0\right)$$
   - `0.0`: Completely nominal / central inlier.
   - `0.5`: Contamination decision boundary.
   - `1.0`: Extreme behavioral outlier.
   - **Crucial Clarification:** This is a normalized *outlier deviation score*, **not** a Bayesian posterior probability.

### Hyperparameters
- `n_estimators`: 150 trees
- `contamination`: 0.05 (expected proportion of outliers in baseline)
- `max_samples`: `'auto'` ($\min(256, n)$)
- `random_state`: 42

---

## 4. Threat Classification Engine (Random Forest)

### Architecture
An ensemble of decorrelated classification trees using bootstrap aggregating (bagging) with random feature subspace sampling at each split ($m = \sqrt{p}$).

### Dynamic Class Detection
The classifier dynamically detects classes present in the training partition, mapping raw strings into canonical SOC threat families:
- `BENIGN`
- `DoS`
- `Port Scan`
- `Brute Force`
- `Web Attack`
- `Bot`
- `Infiltration`

### Class Imbalance Mitigation
Network datasets feature extreme class imbalances (often >80% BENIGN). To prevent the classifier from collapsing to the majority class, we enforce:
$$\text{class\_weight} = \text{'balanced'}$$
which computes weights inversely proportional to class frequencies:
$$w_j = \frac{n}{k \cdot n_j}$$

### Hyperparameters
- `n_estimators`: 100 trees
- `max_depth`: 16 (prevents pathological leaf memorization)
- `min_samples_split`: 2
- `min_samples_leaf`: 1
- `random_state`: 42

---

## 5. Data Leakage Prevention Blueprint

Rigorous anti-leakage isolation is strictly enforced across the pipeline:

1. **Target Disconnection:** Target labels (`label`, `class`, `is_intrusion`) are detached prior to feature transformations and never enter the feature matrix.
2. **Strict Train/Test Partitioning:** The preprocessor (`NetworkDataPreprocessor`) is fitted **exclusively on the training split**. Imputers (median) and scalers (IQR bounds) learn moments only from training records.
3. **Identifier Neutrality:** IP addresses, timestamps, and row IDs are pruned to prevent models from memorizing specific hosts or subnets.
4. **Reproducible Frozen Serialization:** The exact preprocessor state is saved to `preprocessor.joblib`. During inference, `transform()` operates in read-only mode.

---

## 6. Inference Workflow (`NetworkPredictor`)

The `NetworkPredictor` class provides a clean programmatic interface for single flows or batch telemetry:

```python
from machine_learning.inference.predictor import NetworkPredictor

# 1. Load frozen preprocessor and trained models
predictor = NetworkPredictor().load_artifacts()

# 2. Input flow record (handles raw, partial, or full feature dictionaries)
sample_flow = {
    "destination_port": 80,
    "flow_duration": 4200,
    "total_fwd_packets": 120,
    "total_backward_packets": 0,
    "total_length_of_fwd_packets": 7200,
    "total_length_of_bwd_packets": 0,
    "syn_flag_count": 120,
    "protocol": 6,
}

# 3. Predict combined security assessment
result = predictor.predict(sample_flow)
print(result)
```

### Sample Output:
```json
{
  "anomaly": {
    "is_anomaly": false,
    "anomaly_label": "NORMAL",
    "anomaly_score": 0.3656,
    "raw_decision_score": 0.0672,
    "interpretation": "Outlier divergence score: 0.366 (0.0=nominal, 1.0=severe outlier)."
  },
  "classification": {
    "predicted_label": "DoS",
    "is_intrusion": true,
    "confidence": 0.46,
    "confidence_type": "estimated_class_probability",
    "class_probabilities": {
      "BENIGN": 0.03,
      "Bot": 0.24,
      "DoS": 0.46,
      "Infiltration": 0.07,
      "Port Scan": 0.06,
      "Web Attack": 0.14
    }
  },
  "risk_assessment": {
    "risk_level": "MEDIUM",
    "recommended_action": "Flow Telemetry Inspection & Behavioral Audit",
    "summary": "Flow evaluated: Anomaly=NORMAL (score 0.37), Classification='DoS' (est. prob 46.0%). Assigned Risk Level: MEDIUM."
  }
}
```

---

## 7. Development Sample vs. Benchmark Datasets

> **CRITICAL SCIENTIFIC NOTICE:**
> When trained on `datasets/samples/sample_network_traffic.csv`, the resulting metrics are **for pipeline validation only**.
> Because the development fixture contains only 28 flows, evaluation figures (e.g. 66.7% accuracy) must **never** be cited as production or security performance.
> To train a production model, download the full **CIC-IDS2017** or **UNSW-NB15** CSV files and place them into `datasets/raw/`. The training orchestrator will automatically detect and train on the real benchmark dataset.

---

## 8. CLI Commands

### Train Anomaly Detector and Threat Classifier
```powershell
python -m machine_learning.training.train_models
```

### Run Phase 3 & 4 Test Suite
```powershell
pytest backend/tests/test_prediction.py tests/test_ml_models.py -v
```

### Run Entire Project Test Suite (All 35 Tests)
```powershell
pytest -v
```

---

## 9. FastAPI AI Inference Integration (Phase 4)

### Architecture
Phase 4 exposes the trained Phase 3 `NetworkPredictor` via a defensive, production-style REST API endpoint on FastAPI:
```text
Client
  │
  ▼
FastAPI POST /api/v1/predict
  │
  ▼ (Pydantic Request Validation: reject NaN/Inf, empty body, code injection)
PredictionService (Singleton Model Manager)
  │
  ▼ (Pre-loaded, frozen estimators; NO retraining per request)
NetworkPredictor
  ├─► Isolation Forest Anomaly Detection
  └─► Random Forest Threat Classification
  │
  ▼
Composite Risk Assessment (LOW | MEDIUM | HIGH | CRITICAL)
  │
  ▼
Structured JSON Response
```

> **IMPORTANT ARCHITECTURAL GUARANTEE:**
> The API exposes the Phase 3 AI inference engine. **It does NOT train models during prediction requests.** Models are deserialized once into memory during application lifespan startup and reused across requests.

### Endpoint Details
- **Route:** `POST /api/v1/predict`
- **Headers:** `Content-Type: application/json`
- **Status Codes:**
  - `200 OK`: Successful dual-engine prediction and risk triage.
  - `422 Unprocessable Content`: Validation error (NaN, Infinity, empty payload, non-numeric values).
  - `503 Service Unavailable`: ML models missing or degraded (controlled JSON response, no stack traces).
  - `500 Internal Server Error`: Unexpected internal inference failure (stack traces suppressed).

### Example Python Request
```python
import requests

url = "http://127.0.0.1:8000/api/v1/predict"
payload = {
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

response = requests.post(url, json=payload)
print(response.status_code, response.json())
```

### Example Curl Request
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/predict" \
     -H "Content-Type: application/json" \
     -d '{"Destination Port": 80, "Flow Duration": 184500, "Total Fwd Packets": 8, "Total Backward Packets": 10}'
```

### CORS Configuration
Configured in `backend/app/core/config.py` with explicit allowed origins:
- `http://localhost:5173` (Vite local dev)
- `http://127.0.0.1:5173` (Vite loopback)
Wildcard CORS with credentials is intentionally disabled.

