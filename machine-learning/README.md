# Machine Learning Subsystem & Feature Pipelines

## 1. Subsystem Architecture

The Machine Learning subsystem operates in two stages:
1. **Phase 2 (Completed):** Data Ingestion, Inspection, Cleaning, Feature Engineering, Label Normalization, and Scikit-Learn Pipeline Serialization.
2. **Phase 3 (Upcoming):** Unsupervised Anomaly Detection (Isolation Forest) and Supervised Multi-Class Threat Classification (Random Forest / Gradient Boosting).

---

## 2. Package Structure

To ensure clean Python imports while preserving project organization, the ML modules are accessible via the `machine_learning` package:

```text
machine_learning/
├── __init__.py                        # ML root package
├── models/                            # Serialized model artifacts (.joblib)
│   ├── .gitkeep
│   └── preprocessor.joblib            # Frozen Scikit-learn ColumnTransformer
└── pipelines/
    ├── __init__.py                    # Pipelines exports
    ├── dataset_loader.py              # Resilient CSV reader with fallback logic
    ├── dataset_inspector.py           # Deep diagnostic reporting utility
    ├── feature_engineering.py         # Network flow behavioral indicator extraction
    └── preprocessing.py               # Cleaning, encoding, scaling & pipeline runner
```

---

## 3. Feature Engineering Specifications

The `NetworkFeatureEngineer` transformer dynamically inspects column availability and computes cybersecurity behavioral indicators:

| Feature Name | Prerequisite Columns | Cybersecurity Signal |
| :--- | :--- | :--- |
| `total_packets` | `total_fwd_packets`, `total_bwd_packets` | Aggregated flow volume indicator |
| `total_bytes` | `total_fwd_bytes`, `total_bwd_bytes` | Aggregated bandwidth consumption |
| `calc_flow_packets_per_s` | `total_packets`, `flow_duration` | Packet rate (elevated in DoS/flood attacks) |
| `calc_flow_bytes_per_s` | `total_bytes`, `flow_duration` | Byte throughput (elevated in exfiltration) |
| `fwd_bwd_packet_ratio` | `total_fwd_packets`, `total_bwd_packets` | Directional asymmetry (elevated in scans/probes) |
| `fwd_bwd_byte_ratio` | `total_fwd_bytes`, `total_bwd_bytes` | Payload asymmetry between client and server |
| `syn_ratio` | `syn_flag_count`, `total_packets` | Ratio of SYN attempts (key signature of SYN flood & port sweeps) |
| `rst_ratio` | `rst_flag_count`, `total_packets` | Ratio of connection resets (connection rejections during scans) |
| `port_category` | `destination_port` | IANA tier: `well_known` (0-1023), `registered` (1024-49151), `dynamic` (49152-65535) |

---

## 4. Data Leakage Prevention Blueprint

For final-year evaluation and production reliability, the following safeguards are implemented:

- **Target Disconnection:** Target labels are completely stripped before any transformer or scaler is fitted.
- **Strict Separation of Train and Test State:** Imputers and scalers compute statistical moments (median, IQR) **strictly** on training data. Test sets and incoming real-time flows are transformed without updating internal parameters.
- **Joblib Persistence:** The exact fitted `NetworkDataPreprocessor` is saved to disk:
  ```python
  from machine_learning.pipelines.preprocessing import NetworkDataPreprocessor
  preprocessor = NetworkDataPreprocessor.load_pipeline("machine_learning/models/preprocessor.joblib")
  model_input = preprocessor.transform(incoming_raw_df)
  ```
- **Zero Future Information:** All calculations rely solely on the current flow's intrinsic attributes.

---

## 5. Execution Instructions

### Run Dataset Inspection
```powershell
python -m machine_learning.pipelines.dataset_inspector
```

### Run End-to-End Preprocessing
```powershell
python -m machine_learning.pipelines.preprocessing
```

### Run Tests
```powershell
pytest tests/test_preprocessing_pipeline.py -v
```
