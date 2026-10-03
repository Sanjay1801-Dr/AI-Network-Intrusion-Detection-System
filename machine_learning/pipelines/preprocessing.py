"""Network data preprocessing and transformation pipeline."""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple, Union
import joblib
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, RobustScaler, StandardScaler

from machine_learning.pipelines.dataset_loader import DatasetLoader
from machine_learning.pipelines.dataset_inspector import DatasetInspector
from machine_learning.pipelines.feature_engineering import NetworkFeatureEngineer

logger = logging.getLogger("nids.preprocessing")


class NetworkDataPreprocessor(BaseEstimator, TransformerMixin):
    """End-to-end preprocessing, cleaning, encoding, and scaling pipeline for network flow data.

    Follows strict data-leakage prevention principles:
    - Imputers, encoders, and scalers are fitted exclusively on training data.
    - Transform applies identical learned transformations during test and real-time inference.
    - Target labels are completely excluded from feature matrices.
    """

    LABEL_NORMALIZATION_MAP: Dict[str, str] = {
        "benign": "BENIGN",
        "normal": "BENIGN",
        "dos hulk": "DoS",
        "dos goldeneye": "DoS",
        "dos slowloris": "DoS",
        "dos slowhttptest": "DoS",
        "ddos": "DDoS",
        "portscan": "Port Scan",
        "port scan": "Port Scan",
        "ftp-patator": "Brute Force",
        "ssh-patator": "Brute Force",
        "web attack – xss": "Web Attack",
        "web attack – sql injection": "Web Attack",
        "web attack – brute force": "Web Attack",
        "web attack - xss": "Web Attack",
        "web attack - sql injection": "Web Attack",
        "web attack - brute force": "Web Attack",
        "bot": "Bot",
        "infiltration": "Infiltration",
        "heartbleed": "DoS",
    }

    IDENTIFIER_COL_PATTERNS: List[str] = [
        "flow_id",
        "flow id",
        "source_ip",
        "src_ip",
        "source ip",
        "destination_ip",
        "dst_ip",
        "dest ip",
        "timestamp",
        "session_id",
        "record_id",
    ]

    def __init__(
        self,
        scaler_type: str = "robust",
        remove_identifiers: bool = True,
        remove_constant_columns: bool = True,
        clip_extreme_quantiles: bool = True,
    ) -> None:
        self.scaler_type = scaler_type
        self.remove_identifiers = remove_identifiers
        self.remove_constant_columns = remove_constant_columns
        self.clip_extreme_quantiles = clip_extreme_quantiles

        # State attributes established during fit
        self.feature_engineer = NetworkFeatureEngineer()
        self.column_transformer: Optional[ColumnTransformer] = None
        self.fitted_numeric_cols_: List[str] = []
        self.fitted_categorical_cols_: List[str] = []
        self.removed_columns_: Dict[str, str] = {}
        self.quantile_bounds_: Dict[str, Tuple[float, float]] = {}
        self.is_fitted_: bool = False

    @staticmethod
    def normalize_column_name(col: str) -> str:
        """Strip whitespace and convert arbitrary column strings to uniform snake_case."""
        clean = col.strip().lower()
        clean = clean.replace("/", "_per_").replace("-", "_").replace(" ", "_")
        clean = re.sub(r"[^a-zA-Z0-9_]", "", clean)
        clean = re.sub(r"_+", "_", clean)
        return clean.strip("_")

    def clean_raw_dataframe(
        self,
        df: pd.DataFrame,
        is_training: bool = False,
    ) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """Perform initial data hygiene: column normalization, deduplication, and infinite value replacement.

        Args:
            df: Raw input DataFrame.
            is_training: Flag indicating whether duplicate removal and pruning should update fit state.

        Returns:
            Tuple of (Cleaned DataFrame, Hygiene log dictionary).
        """
        cleaned_df = df.copy()
        hygiene_log: Dict[str, Any] = {
            "initial_rows": len(cleaned_df),
            "initial_columns": len(cleaned_df.columns),
            "duplicates_removed": 0,
            "infinite_replacements": 0,
            "columns_dropped": {},
        }

        # 1. Normalize column names
        cleaned_df.columns = [self.normalize_column_name(c) for c in cleaned_df.columns]

        # 2. Remove exact duplicates (only during dataset cleaning/training)
        if is_training:
            orig_len = len(cleaned_df)
            cleaned_df = cleaned_df.drop_duplicates()
            dups = orig_len - len(cleaned_df)
            hygiene_log["duplicates_removed"] = dups
            if dups > 0:
                logger.info("Removed %d duplicate flow records", dups)

        # 3. Replace infinite values with NaN across all numeric and string columns
        inf_count = 0
        for col in cleaned_df.columns:
            if pd.api.types.is_numeric_dtype(cleaned_df[col]):
                mask = np.isinf(cleaned_df[col])
                cnt = int(mask.sum())
                if cnt > 0:
                    cleaned_df.loc[mask, col] = np.nan
                    inf_count += cnt
            elif pd.api.types.is_object_dtype(cleaned_df[col]) or pd.api.types.is_string_dtype(cleaned_df[col]):
                # Check for string "Infinity" or "-Infinity"
                mask = cleaned_df[col].isin(["Infinity", "-Infinity", "Inf", "-Inf"])
                cnt = int(mask.sum())
                if cnt > 0:
                    cleaned_df.loc[mask, col] = np.nan
                    inf_count += cnt
                    # Attempt numeric cast
                    try:
                        cleaned_df[col] = pd.to_numeric(cleaned_df[col])
                    except (ValueError, TypeError):
                        pass

        hygiene_log["infinite_replacements"] = inf_count

        return cleaned_df, hygiene_log

    def extract_and_normalize_labels(
        self,
        df: pd.DataFrame,
    ) -> Tuple[pd.DataFrame, Optional[pd.Series], Optional[pd.Series], Optional[pd.Series]]:
        """Identify target column, preserve original, and generate normalized multi-class and binary labels.

        Args:
            df: Cleaned DataFrame.

        Returns:
            Tuple of (DataFrame without label column, original_labels, normalized_labels, is_intrusion binary series).
        """
        label_col = None
        candidates = ["label", "class", "attack_cat", "threat_type"]
        for c in candidates:
            if c in df.columns:
                label_col = c
                break

        if not label_col:
            logger.warning("No label column detected. Treating all flows as unlabeled.")
            return df, None, None, None

        orig_labels = df[label_col].astype(str).str.strip()
        features_df = df.drop(columns=[label_col])

        # Normalize to standardized categories
        def _map_label(val: str) -> str:
            lower = val.lower().strip()
            if lower in self.LABEL_NORMALIZATION_MAP:
                return self.LABEL_NORMALIZATION_MAP[lower]
            for pattern, target in self.LABEL_NORMALIZATION_MAP.items():
                if pattern in lower:
                    return target
            return "Other Attack" if lower not in ("benign", "normal") else "BENIGN"

        norm_labels = orig_labels.apply(_map_label)
        is_intrusion = (norm_labels != "BENIGN").astype(int)

        return features_df, orig_labels, norm_labels, is_intrusion

    def fit(self, X: pd.DataFrame, y: Optional[pd.Series] = None) -> "NetworkDataPreprocessor":
        """Fit preprocessor: detects column types, establishes bounds, and fits encoders & scalers.

        Args:
            X: Input training DataFrame (raw or cleaned features without target label).
            y: Optional target (unused in unsupervised transforms).

        Returns:
            Fitted preprocessor instance.
        """
        # 1. Clean
        df, _ = self.clean_raw_dataframe(X, is_training=True)

        # 2. Feature Engineering
        df = self.feature_engineer.transform(df)

        # 3. Detect and drop identifier-like columns
        drop_cols: Dict[str, str] = {}
        for col in df.columns:
            col_lower = str(col).lower()
            if self.remove_identifiers and any(pat in col_lower for pat in self.IDENTIFIER_COL_PATTERNS):
                drop_cols[col] = "Identifier column dropped to prevent model overfitting to specific host/time attributes."
            elif self.remove_constant_columns and df[col].nunique(dropna=False) <= 1:
                drop_cols[col] = "Constant column (zero variance, provides no discriminative signal)."

        self.removed_columns_ = drop_cols
        remaining_df = df.drop(columns=list(drop_cols.keys()), errors="ignore")

        # 4. Partition numerical vs categorical columns
        num_cols: List[str] = []
        cat_cols: List[str] = []

        for col in remaining_df.columns:
            if pd.api.types.is_numeric_dtype(remaining_df[col]):
                num_cols.append(col)
                # Compute 99.9th percentile bounds for outlier clipping
                if self.clip_extreme_quantiles:
                    q_low = float(remaining_df[col].quantile(0.0001))
                    q_high = float(remaining_df[col].quantile(0.9999))
                    if q_high > q_low:
                        self.quantile_bounds_[col] = (q_low, q_high)
            else:
                cat_cols.append(col)

        self.fitted_numeric_cols_ = num_cols
        self.fitted_categorical_cols_ = cat_cols

        # 5. Build Scikit-learn ColumnTransformer
        num_scaler = RobustScaler() if self.scaler_type == "robust" else StandardScaler()
        num_pipeline = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", num_scaler),
        ])

        cat_pipeline = Pipeline([
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("encoder", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
        ])

        transformers = []
        if num_cols:
            transformers.append(("num", num_pipeline, num_cols))
        if cat_cols:
            transformers.append(("cat", cat_pipeline, cat_cols))

        self.column_transformer = ColumnTransformer(
            transformers=transformers,
            remainder="drop",
        )

        # Fit ColumnTransformer on remaining features
        self.column_transformer.fit(remaining_df)
        self.is_fitted_ = True
        logger.info(
            "Fitted preprocessor successfully with %d numerical and %d categorical features (Dropped %d columns)",
            len(num_cols),
            len(cat_cols),
            len(drop_cols),
        )

        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        """Transform raw input DataFrame into scaled, encoded numerical feature matrix.

        Args:
            X: Input DataFrame.

        Returns:
            NumPy 2D array of model-ready features.
        """
        if not self.is_fitted_ or self.column_transformer is None:
            raise RuntimeError("NetworkDataPreprocessor must be fitted before calling transform().")

        # 1. Clean
        df, _ = self.clean_raw_dataframe(X, is_training=False)

        # 2. Feature Engineering
        df = self.feature_engineer.transform(df)

        # 3. Drop removed columns
        df = df.drop(columns=list(self.removed_columns_.keys()), errors="ignore")

        # 4. Clip extreme quantiles
        if self.clip_extreme_quantiles:
            for col, (q_low, q_high) in self.quantile_bounds_.items():
                if col in df.columns:
                    df[col] = df[col].clip(lower=q_low, upper=q_high)

        # 5. Ensure all columns expected by fitted ColumnTransformer exist
        for col in self.fitted_numeric_cols_:
            if col not in df.columns:
                df[col] = np.nan
        for col in self.fitted_categorical_cols_:
            if col not in df.columns:
                df[col] = np.nan

        # 6. Apply fitted ColumnTransformer
        return self.column_transformer.transform(df)

    def fit_transform(self, X: pd.DataFrame, y: Optional[pd.Series] = None) -> np.ndarray:
        """Fit and transform in a single call."""
        return self.fit(X, y).transform(X)

    def get_feature_names_out(self) -> List[str]:
        """Retrieve output feature column names from fitted transformer."""
        if not self.is_fitted_ or self.column_transformer is None:
            return []
        try:
            return list(self.column_transformer.get_feature_names_out())
        except Exception:
            # Fallback if scikit-learn version does not support on all transformers
            names = []
            for name in self.fitted_numeric_cols_:
                names.append(f"num__{name}")
            for name in self.fitted_categorical_cols_:
                names.append(f"cat__{name}")
            return names

    def save_pipeline(self, target_path: Union[str, Path]) -> None:
        """Serialize fitted preprocessor to disk using joblib."""
        if not self.is_fitted_:
            raise RuntimeError("Cannot serialize an unfitted preprocessor.")
        path = Path(target_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        logger.info("Saved fitted preprocessor artifact to: %s", path)

    @classmethod
    def load_pipeline(cls, model_path: Union[str, Path]) -> "NetworkDataPreprocessor":
        """Deserialize preprocessor pipeline from disk using joblib."""
        path = Path(model_path)
        if not path.exists():
            raise FileNotFoundError(f"Model artifact not found at: {path}")
        preprocessor = joblib.load(path)
        if not isinstance(preprocessor, cls):
            raise TypeError(f"Loaded object is of type {type(preprocessor)}, expected {cls.__name__}")
        logger.info("Loaded preprocessor artifact from: %s", path)
        return preprocessor


def run_pipeline(
    input_file: Optional[str] = None,
    output_csv: str = "datasets/processed/processed_traffic.csv",
    output_metadata: str = "datasets/metadata/dataset_info.json",
    model_save_path: str = "machine_learning/models/preprocessor.joblib",
) -> Dict[str, Any]:
    """Execute complete Phase 2 dataset ingestion, inspection, cleaning, and preprocessing workflow."""
    print("=" * 80)
    print(" AI NETWORK INTRUSION DETECTION SYSTEM — PHASE 2 PREPROCESSING PIPELINE ".center(80))
    print("=" * 80)

    # 1. Locate and Load Dataset
    loader = DatasetLoader()
    raw_df, load_meta = loader.load_dataset(file_path=input_file)
    print(f"\n[1/7] Loaded Dataset: {load_meta['file_name']}")
    print(f"      Source: {load_meta['file_path']}")
    print(f"      Size:   {load_meta['file_size_bytes']:,} bytes | Sample Mode: {load_meta['is_sample_dataset']}")

    # 2. Inspect Raw Dataset
    print("\n[2/7] Running Diagnostic Dataset Inspection...")
    insp_report = DatasetInspector.inspect(raw_df)
    DatasetInspector.print_terminal_report(insp_report, title=f"RAW DATASET INSPECTION: {load_meta['file_name']}")

    # 3. Clean and Normalize Data
    print("\n[3/7] Cleaning Raw Data & Normalizing Headers...")
    preprocessor = NetworkDataPreprocessor(scaler_type="robust")
    cleaned_df, hygiene_log = preprocessor.clean_raw_dataframe(raw_df, is_training=True)

    # 4. Extract Labels (Preventing Leakage)
    print("\n[4/7] Normalizing Attack Categories & Extracting Labels...")
    features_df, orig_labels, norm_labels, is_intrusion = preprocessor.extract_and_normalize_labels(cleaned_df)

    if norm_labels is not None:
        print("      Detected Label Breakdown:")
        for label, count in norm_labels.value_counts().items():
            print(f"        * {label:<20} : {count:>5} flows")

    # 5. Fit Preprocessing Pipeline & Feature Engineering
    print("\n[5/7] Engineering Behavioral Features & Fitting Scalers/Encoders...")
    X_processed = preprocessor.fit_transform(features_df)
    feature_names = preprocessor.get_feature_names_out()
    print(f"      Transformed feature matrix shape: {X_processed.shape}")
    print(f"      Total model-ready features:       {len(feature_names)}")

    # 6. Save Processed Dataset (CSV)
    print("\n[6/7] Exporting Processed Dataset...")
    processed_path = Path(output_csv)
    processed_path.parent.mkdir(parents=True, exist_ok=True)

    # Build exported DataFrame containing features + labels for ML training in Phase 3
    export_df = pd.DataFrame(X_processed, columns=feature_names)
    if norm_labels is not None:
        export_df["original_label"] = orig_labels.values
        export_df["normalized_label"] = norm_labels.values
        export_df["is_intrusion"] = is_intrusion.values

    export_df.to_csv(processed_path, index=False)
    print(f"      Saved processed dataset to: {processed_path.resolve()} ({len(export_df)} rows)")

    # Also save to machine-learning/models directory for compatibility
    preprocessor.save_pipeline(model_save_path)
    # Also save to machine-learning/models/ for Phase 1 folder structure compatibility
    alt_model_path = Path("machine-learning/models/preprocessor.joblib")
    preprocessor.save_pipeline(alt_model_path)

    # 7. Generate & Save Comprehensive Preprocessing Metadata
    print("\n[7/7] Generating Pipeline Metadata & Data Governance Summary...")
    meta_path = Path(output_metadata)
    meta_path.parent.mkdir(parents=True, exist_ok=True)

    metadata: Dict[str, Any] = {
        "dataset_name": load_meta["file_name"],
        "source": load_meta["file_path"],
        "is_sample_dataset": load_meta["is_sample_dataset"],
        "preprocessing_timestamp": datetime.now(timezone.utc).isoformat(),
        "preprocessing_version": "1.0.0-phase2",
        "original_row_count": load_meta["raw_row_count"],
        "processed_row_count": len(export_df),
        "original_column_count": load_meta["raw_column_count"],
        "processed_feature_count": len(feature_names),
        "duplicates_removed": hygiene_log["duplicates_removed"],
        "infinite_values_imputed": hygiene_log["infinite_replacements"],
        "removed_columns": preprocessor.removed_columns_,
        "engineered_features": preprocessor.feature_engineer.engineered_feature_names_,
        "fitted_numerical_features": preprocessor.fitted_numeric_cols_,
        "fitted_categorical_features": preprocessor.fitted_categorical_cols_,
        "label_distribution": insp_report.get("label_distribution", {}),
        "leakage_prevention": {
            "target_excluded_from_features": True,
            "fitted_on_features_only": True,
            "encoders_and_scalers_frozen": True,
            "serializable_via_joblib": True,
        },
    }

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"      Saved metadata catalog to:  {meta_path.resolve()}")

    print("\n" + "=" * 80)
    print(" PHASE 2 PREPROCESSING COMPLETED SUCCESSFULLY ".center(80))
    print("=" * 80 + "\n")

    return metadata


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    run_pipeline()
