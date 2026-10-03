"""Comprehensive test suite for Phase 2 dataset loading, inspection, and preprocessing pipeline."""

import os
import tempfile
from pathlib import Path
import numpy as np
import pandas as pd
import pytest

from machine_learning.pipelines.dataset_loader import DatasetLoader
from machine_learning.pipelines.dataset_inspector import DatasetInspector
from machine_learning.pipelines.feature_engineering import NetworkFeatureEngineer
from machine_learning.pipelines.preprocessing import NetworkDataPreprocessor


@pytest.fixture
def sample_csv_path():
    """Path to the development sample dataset."""
    path = Path("datasets/samples/sample_network_traffic.csv")
    assert path.exists(), "Sample dataset must exist for tests."
    return path


def test_dataset_loader_sample_fallback(sample_csv_path):
    """Test that DatasetLoader automatically falls back to development sample when no raw dataset exists."""
    with tempfile.TemporaryDirectory() as empty_dir:
        loader = DatasetLoader(raw_dir=empty_dir)
        df, meta = loader.load_dataset()

        assert not df.empty
        assert meta["is_sample_dataset"] is True
        assert "file_name" in meta
        assert meta["raw_row_count"] > 0
        assert meta["raw_column_count"] > 10


def test_column_normalization():
    """Verify that column names with irregular spacing and case are cleaned to uniform snake_case."""
    dirty_columns = [
        " Destination Port",
        " Flow Duration",
        "Total Fwd Packets",
        "Flow Bytes/s",
        "Fwd Packet Length Max",
        " Label ",
    ]
    expected = [
        "destination_port",
        "flow_duration",
        "total_fwd_packets",
        "flow_bytes_per_s",
        "fwd_packet_length_max",
        "label",
    ]
    for raw, exp in zip(dirty_columns, expected):
        assert NetworkDataPreprocessor.normalize_column_name(raw) == exp


def test_clean_raw_dataframe_duplicates_and_infinite():
    """Verify deduplication and infinite value detection during cleaning."""
    test_df = pd.DataFrame({
        " Destination Port": [80, 80, 443],
        " Flow Duration": [1000, 1000, 2000],
        "Flow Bytes/s": [500.0, 500.0, "Infinity"],
    })

    preprocessor = NetworkDataPreprocessor()
    cleaned_df, hygiene_log = preprocessor.clean_raw_dataframe(test_df, is_training=True)

    # 1 duplicate row should be removed
    assert len(cleaned_df) == 2
    assert hygiene_log["duplicates_removed"] == 1
    # Infinite string should have been converted to NaN
    assert hygiene_log["infinite_replacements"] >= 1
    assert "destination_port" in cleaned_df.columns
    assert "flow_bytes_per_s" in cleaned_df.columns


def test_label_normalization():
    """Verify that varied attack family strings normalize to standard SOC categories."""
    preprocessor = NetworkDataPreprocessor()
    test_df = pd.DataFrame({
        "flow_duration": [100, 200, 300, 400, 500],
        "label": [
            "BENIGN",
            "DoS Hulk",
            "PortScan",
            "SSH-Patator",
            "Web Attack – XSS",
        ],
    })

    features_df, orig_labels, norm_labels, is_intrusion = preprocessor.extract_and_normalize_labels(test_df)

    assert "label" not in features_df.columns
    assert list(norm_labels) == [
        "BENIGN",
        "DoS",
        "Port Scan",
        "Brute Force",
        "Web Attack",
    ]
    assert list(is_intrusion) == [0, 1, 1, 1, 1]


def test_feature_engineering_dynamic():
    """Verify that NetworkFeatureEngineer adds rate and ratio metrics when columns exist."""
    engineer = NetworkFeatureEngineer()
    test_df = pd.DataFrame({
        "destination_port": [80, 53],
        "flow_duration": [1000000, 500000],  # microseconds
        "total_fwd_packets": [10, 2],
        "total_backward_packets": [10, 2],
        "total_length_of_fwd_packets": [1000, 80],
        "total_length_of_bwd_packets": [5000, 160],
        "syn_flag_count": [1, 0],
    })

    engineered_df = engineer.transform(test_df)

    assert "total_packets" in engineered_df.columns
    assert "total_bytes" in engineered_df.columns
    assert "calc_flow_packets_per_s" in engineered_df.columns
    assert "calc_flow_bytes_per_s" in engineered_df.columns
    assert "fwd_bwd_packet_ratio" in engineered_df.columns
    assert "fwd_bwd_byte_ratio" in engineered_df.columns
    assert "syn_ratio" in engineered_df.columns
    assert "port_category" in engineered_df.columns
    assert engineered_df["port_category"].iloc[0] == "well_known"


def test_feature_engineering_missing_prerequisites():
    """Verify that feature engineering gracefully skips calculations when source columns are missing."""
    engineer = NetworkFeatureEngineer()
    sparse_df = pd.DataFrame({
        "unrelated_metric_a": [1.0, 2.0],
        "unrelated_metric_b": [3.0, 4.0],
    })

    # Should not raise any KeyError or exception
    output_df = engineer.transform(sparse_df)
    assert len(output_df) == 2
    assert "unrelated_metric_a" in output_df.columns


def test_preprocessing_fit_transform(sample_csv_path):
    """Test full fitting and transformation pipeline on development sample dataset."""
    loader = DatasetLoader()
    raw_df, _ = loader.load_dataset(sample_csv_path)

    preprocessor = NetworkDataPreprocessor(scaler_type="robust")
    cleaned_df, _ = preprocessor.clean_raw_dataframe(raw_df, is_training=True)
    features_df, orig_labels, norm_labels, is_intrusion = preprocessor.extract_and_normalize_labels(cleaned_df)

    X_processed = preprocessor.fit_transform(features_df)

    # Validate output matrix
    assert isinstance(X_processed, np.ndarray)
    assert X_processed.ndim == 2
    assert X_processed.shape[0] == len(features_df)
    assert X_processed.shape[1] > 0
    # No NaNs or Infs remaining in transformed matrix
    assert not np.isnan(X_processed).any(), "Processed feature matrix must not contain NaN"
    assert not np.isinf(X_processed).any(), "Processed feature matrix must not contain Infinite values"


def test_joblib_serialization_deserialization(sample_csv_path):
    """Verify preprocessor pipeline serialization and deserialization reproducibility."""
    loader = DatasetLoader()
    raw_df, _ = loader.load_dataset(sample_csv_path)

    preprocessor = NetworkDataPreprocessor()
    cleaned_df, _ = preprocessor.clean_raw_dataframe(raw_df, is_training=True)
    features_df, _, _, _ = preprocessor.extract_and_normalize_labels(cleaned_df)

    X_original = preprocessor.fit_transform(features_df)

    with tempfile.TemporaryDirectory() as tmp_dir:
        save_path = Path(tmp_dir) / "preprocessor.joblib"
        preprocessor.save_pipeline(save_path)
        assert save_path.exists()

        # Load back
        reloaded = NetworkDataPreprocessor.load_pipeline(save_path)
        assert reloaded.is_fitted_ is True

        # Transform unseen sample slice
        sample_slice = features_df.head(5)
        out1 = preprocessor.transform(sample_slice)
        out2 = reloaded.transform(sample_slice)

        np.testing.assert_allclose(out1, out2, rtol=1e-5, atol=1e-5)


def test_data_leakage_prevention(sample_csv_path):
    """Ensure labels are strictly separated and excluded from feature matrices."""
    loader = DatasetLoader()
    raw_df, _ = loader.load_dataset(sample_csv_path)

    preprocessor = NetworkDataPreprocessor()
    cleaned_df, _ = preprocessor.clean_raw_dataframe(raw_df, is_training=True)
    features_df, orig_labels, norm_labels, is_intrusion = preprocessor.extract_and_normalize_labels(cleaned_df)

    # 1. Target column must not exist in features DataFrame
    assert "label" not in features_df.columns
    assert "class" not in features_df.columns

    # 2. Fit preprocessor
    preprocessor.fit(features_df)
    feature_names = preprocessor.get_feature_names_out()

    for col in ["label", "original_label", "normalized_label", "is_intrusion"]:
        assert not any(col in fn for fn in feature_names), f"Target label '{col}' leaked into feature names!"


def test_dataset_inspector_report(sample_csv_path):
    """Test that DatasetInspector correctly identifies distributions, duplicates, and anomalies."""
    loader = DatasetLoader()
    raw_df, _ = loader.load_dataset(sample_csv_path)

    report = DatasetInspector.inspect(raw_df)

    assert "row_count" in report
    assert "column_count" in report
    assert "dtypes" in report
    assert "missing_values" in report
    assert "infinite_values" in report
    assert "label_distribution" in report
    assert "constant_columns" in report
    assert report["duplicate_count"] >= 1
    assert "BENIGN" in report["label_distribution"]
