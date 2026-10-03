# Network Intrusion Detection Datasets

## 1. Supported Benchmark Datasets

The preprocessing subsystem is engineered to support both primary and secondary cybersecurity benchmark datasets, as well as live capture telemetry:

### 1.1 Primary Benchmark: CIC-IDS2017
- **Institution:** Canadian Institute for Cybersecurity, University of New Brunswick (UNB)
- **Official Source:** [https://www.unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html)
- **Description:** Generated via CICFlowMeter capturing bidirectional network flow features. Contains benign activity and 7 threat families:
  - DoS (Hulk, GoldenEye, slowloris, Slowhttptest)
  - DDoS (LOIC)
  - Port Scan (Nmap stealth and full TCP sweeps)
  - Brute Force (SSH-Patator, FTP-Patator)
  - Web Attacks (Cross-Site Scripting, SQL Injection, Brute Force)
  - Botnets (ARES)
  - Infiltration (Dropbox downloads, Metasploit payloads)

### 1.2 Secondary Benchmark: UNSW-NB15
- **Institution:** Cyber Range Lab of UNSW Canberra Cyber
- **Official Source:** [https://research.unsw.edu.au/projects/unsw-nb15-dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
- **Description:** Modern network traffic dataset with realistic benign traffic and 9 modern attack families (Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms).

---

## 2. Dataset Directory Structure & File Placement

```text
datasets/
├── README.md                              # This documentation file
├── raw/                                   # PLACE YOUR DOWNLOADED BENCHMARK CSVs HERE
│   └── .gitkeep
├── processed/                             # Output folder for cleaned & scaled datasets
│   ├── .gitkeep
│   └── processed_traffic.csv              # Model-ready feature matrix
├── metadata/                              # Dataset governance catalogs
│   └── dataset_info.json                  # Preprocessing audit log & distributions
└── samples/                               # Small development & test fixtures
    └── sample_network_traffic.csv         # Labeled developmental fixture
```

### Where to Place Downloaded Raw Files:
1. Download the raw CSV files for **CIC-IDS2017** or **UNSW-NB15** from official academic sources.
2. Place the CSV files inside:
   ```text
   datasets/raw/
   ```
   *(e.g., `datasets/raw/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`)*
3. The `datasets/raw/*.csv` files are automatically **git-ignored** to prevent pushing large binary/CSV files to source control.
4. When `datasets/raw/` is empty, the pipeline **automatically falls back to `datasets/samples/sample_network_traffic.csv`**, ensuring automated tests and continuous integration pass without requiring multi-gigabyte downloads.

---

## 3. Preprocessing & Data Cleaning Pipeline

The preprocessing pipeline (`machine_learning.pipelines.preprocessing`) performs:

1. **Header Hygiene:** Strips accidental leading/trailing whitespace (e.g. `" Destination Port"` -> `"destination_port"`), removes special characters, and converts column names to uniform snake_case.
2. **Deduplication:** Identifies and drops exact duplicate flow records to prevent inflated evaluation metrics.
3. **Infinite Value Treatment:** Converts `"Infinity"`, `"-Infinity"`, and IEEE floating-point `Inf` to `NaN`, followed by median imputation.
4. **Identifier Pruning:** Removes non-generalizable columns (e.g. `flow_id`, raw `timestamp`, `source_ip` / `destination_ip` when preventing overfitting to specific subnets). All dropped columns and rationale are recorded in metadata.
5. **Extreme Quantile Clipping:** Clips extreme 99.9th percentile outliers to safeguard scaling transformations against massive volume spikes.
6. **Robust Scaling:** Uses `RobustScaler` (median and IQR) for numerical features to handle high-variance packet/byte spikes.
7. **Categorical Encoding:** Employs `OneHotEncoder(handle_unknown='ignore')` for protocol and port category attributes.

---

## 4. Label Handling & Multi-Class Standardization

Raw datasets often use divergent naming conventions. The preprocessor standardizes attack classes into uniform SOC families while preserving original labels:

| Original Raw Label Variant | Standardized Multi-Class Label | Binary Label (`is_intrusion`) |
| :--- | :--- | :--- |
| `BENIGN`, `normal`, `Normal` | `BENIGN` | `0` (Normal) |
| `DoS Hulk`, `DoS GoldenEye`, `DoS slowloris` | `DoS` | `1` (Intrusion) |
| `DDoS`, `DDoS LOIC` | `DDoS` | `1` (Intrusion) |
| `PortScan`, `Port Scan` | `Port Scan` | `1` (Intrusion) |
| `SSH-Patator`, `FTP-Patator` | `Brute Force` | `1` (Intrusion) |
| `Web Attack – XSS`, `Web Attack – Sql Injection` | `Web Attack` | `1` (Intrusion) |
| `Bot`, `Botnet` | `Bot` | `1` (Intrusion) |
| `Infiltration` | `Infiltration` | `1` (Intrusion) |
| *Other unrecognized attacks* | `Other Attack` | `1` (Intrusion) |

---

## 5. Data Leakage Prevention Strategy

To ensure scientific validity for your final-year project evaluation, the pipeline enforces strict anti-leakage barriers:

1. **Target Separation:** The label column is detached before feature engineering or scaling. Target names never enter the feature matrix.
2. **Frozen Estimator State:** Imputers, encoders, and scalers are fitted **only** on the training dataset. The test split and real-time inference telemetry use `transform()` only without updating parameters.
3. **Identifier Neutrality:** Static identifiers like host IP addresses and absolute timestamps are excluded from features to prevent classifiers from memorizing specific network nodes rather than learning flow dynamics.
4. **Reproducible Serialization:** The fitted preprocessor is saved using `joblib` (`machine_learning/models/preprocessor.joblib`), ensuring that Phase 3 ML models and Phase 4 API inference use identical numerical transformations.

---

## 6. How to Run Preprocessing & Tests

### Inspect Dataset
```powershell
python -m machine_learning.pipelines.dataset_inspector
```

### Run Full Preprocessing Pipeline
```powershell
python -m machine_learning.pipelines.preprocessing
```

### Run Phase 2 Tests
```powershell
pytest tests/test_preprocessing_pipeline.py -v
```

### Run Complete Project Test Suite (Phase 1 + Phase 2)
```powershell
pytest -v
```
