"""Comprehensive test suite for Phase 3 ML anomaly detection, threat classification, and inference."""

import os
from pathlib import Path
import tempfile
import numpy as np
import pandas as pd
import pytest

from machine_learning.pipelines.dataset_loader import DatasetLoader
from machine_learning.pipelines.preprocessing import NetworkDataPreprocessor
from machine_learning.training.train_anomaly_detector import AnomalyDetectorTrainer
from machine_learning.training.train_threat_classifier import ThreatClassifierTrainer
from machine_learning.evaluation.evaluate_classifier import ClassifierEvaluator
from machine_learning.evaluation.evaluate_anomaly import AnomalyEvaluator
from machine_learning.inference.predictor import NetworkPredictor


@pytest.fixture(scope="module")
def prepared_data():
    """Load, clean, and preprocess the development sample for model testing."""
    loader = DatasetLoader()
    raw_df, meta = loader.load_dataset()

    preprocessor = NetworkDataPreprocessor(scaler_type="robust")
    cleaned_df, _ = preprocessor.clean_raw_dataframe(raw_df, is_training=True)
    features_df, orig_labels, norm_labels, is_intrusion = preprocessor.extract_and_normalize_labels(cleaned_df)

    X = preprocessor.fit_transform(features_df)
    feature_names = preprocessor.get_feature_names_out()

    return {
        "raw_df": raw_df,
        "features_df": features_df,
        "norm_labels": norm_labels,
        "is_intrusion": is_intrusion,
        "X": X,
        "feature_names": feature_names,
        "preprocessor": preprocessor,
    }


def test_anomaly_model_training(prepared_data):
    """Test unsupervised Isolation Forest fitting and score generation."""
    X = prepared_data["X"]
    trainer = AnomalyDetectorTrainer(contamination=0.05, n_estimators=50, random_state=42)
    model = trainer.fit(X)

    assert model is not None
    assert trainer.is_fitted_ is True

    preds, raw_scores, norm_scores = trainer.predict_with_scores(X)

    assert len(preds) == len(X)
    assert set(preds).issubset({0, 1})
    assert len(norm_scores) == len(X)
    assert np.all(norm_scores >= 0.0) and np.all(norm_scores <= 1.0)


def test_classifier_training_and_classes(prepared_data):
    """Test supervised Random Forest fitting and dynamic class detection."""
    X = prepared_data["X"]
    y = prepared_data["norm_labels"]

    trainer = ThreatClassifierTrainer(n_estimators=50, max_depth=8, random_state=42)
    model = trainer.fit(X, y)

    assert model is not None
    assert trainer.is_fitted_ is True
    assert len(trainer.classes_) > 1
    assert "BENIGN" in trainer.classes_

    preds = trainer.predict(X)
    assert len(preds) == len(X)
    assert set(preds).issubset(set(trainer.classes_))

    probas = trainer.predict_proba(X)
    assert probas.shape == (len(X), len(trainer.classes_))
    # Probabilities per row sum to 1.0
    np.testing.assert_allclose(np.sum(probas, axis=1), 1.0, atol=1e-5)


def test_feature_importance_extraction(prepared_data):
    """Verify feature importances are extracted, non-negative, and sorted descending."""
    X = prepared_data["X"]
    y = prepared_data["norm_labels"]
    feature_names = prepared_data["feature_names"]

    trainer = ThreatClassifierTrainer(n_estimators=30, random_state=42)
    trainer.fit(X, y)

    importance_df = trainer.extract_feature_importance(feature_names)

    assert isinstance(importance_df, pd.DataFrame)
    assert "feature" in importance_df.columns
    assert "importance" in importance_df.columns
    assert len(importance_df) == len(feature_names)
    assert np.all(importance_df["importance"] >= 0.0)

    # Check sorting
    vals = importance_df["importance"].values
    assert np.all(vals[:-1] >= vals[1:]), "Feature importances must be sorted descending"


def test_model_serialization_and_loading(prepared_data):
    """Verify joblib model serialization and byte-identical deserialization."""
    X = prepared_data["X"]
    y = prepared_data["norm_labels"]

    anom_trainer = AnomalyDetectorTrainer(n_estimators=30, random_state=42)
    anom_trainer.fit(X)

    class_trainer = ThreatClassifierTrainer(n_estimators=30, random_state=42)
    class_trainer.fit(X, y)

    with tempfile.TemporaryDirectory() as tmp_dir:
        anom_path = Path(tmp_dir) / "anomaly_detector.joblib"
        class_path = Path(tmp_dir) / "threat_classifier.joblib"

        anom_trainer.save(anom_path)
        class_trainer.save(class_path)

        assert anom_path.exists()
        assert class_path.exists()

        reloaded_anom = AnomalyDetectorTrainer.load(anom_path)
        reloaded_class = ThreatClassifierTrainer.load(class_path)

        assert reloaded_anom.is_fitted_ is True
        assert reloaded_class.is_fitted_ is True

        # Assert identical predictions
        _, _, scores_orig = anom_trainer.predict_with_scores(X[:5])
        _, _, scores_reloaded = reloaded_anom.predict_with_scores(X[:5])
        np.testing.assert_allclose(scores_orig, scores_reloaded)

        preds_orig = class_trainer.predict(X[:5])
        preds_reloaded = reloaded_class.predict(X[:5])
        np.testing.assert_array_equal(preds_orig, preds_reloaded)


def test_classifier_evaluation_metrics():
    """Verify calculation of multi-class accuracy, precision, recall, and confusion matrix."""
    y_true = ["BENIGN", "BENIGN", "DoS", "Port Scan", "Brute Force"]
    y_pred = ["BENIGN", "DoS", "DoS", "Port Scan", "Brute Force"]
    classes = ["BENIGN", "Brute Force", "DoS", "Port Scan"]

    eval_results = ClassifierEvaluator.evaluate(y_true, y_pred, class_labels=classes)

    assert eval_results["accuracy"] == 0.80
    assert "precision_macro" in eval_results
    assert "recall_macro" in eval_results
    assert "f1_macro" in eval_results
    assert "confusion_matrix_df" in eval_results

    cm_df = eval_results["confusion_matrix_df"]
    assert cm_df.loc["BENIGN", "BENIGN"] == 1
    assert cm_df.loc["BENIGN", "DoS"] == 1


def test_anomaly_evaluation_metrics():
    """Verify calculation of anomaly detection diagnostic distributions."""
    anom_preds = np.array([0, 0, 1, 1, 0])
    anom_scores = np.array([0.1, 0.2, 0.8, 0.9, 0.3])
    ground_truth = np.array([0, 0, 1, 1, 0])

    eval_results = AnomalyEvaluator.evaluate(
        anomaly_predictions=anom_preds,
        anomaly_scores=anom_scores,
        ground_truth_intrusion=ground_truth,
    )

    assert eval_results["total_samples"] == 5
    assert eval_results["flagged_anomalies"] == 2
    assert eval_results["anomaly_rate"] == 0.4
    assert "supervised_validation" in eval_results
    val = eval_results["supervised_validation"]
    assert val["anomaly_precision"] == 1.0
    assert val["anomaly_recall_detection_rate"] == 1.0


def test_inference_predictor_end_to_end():
    """Test NetworkPredictor end-to-end inference on single record and batch."""
    predictor = NetworkPredictor().load_artifacts()

    # 1. Single flow dict
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

    result = predictor.predict(sample_flow)

    assert isinstance(result, dict)
    assert "anomaly" in result
    assert "classification" in result
    assert "risk_assessment" in result

    assert "is_anomaly" in result["anomaly"]
    assert "anomaly_score" in result["anomaly"]
    assert 0.0 <= result["anomaly"]["anomaly_score"] <= 1.0

    assert "predicted_label" in result["classification"]
    assert "confidence" in result["classification"]
    assert "class_probabilities" in result["classification"]

    assert result["risk_assessment"]["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert "recommended_action" in result["risk_assessment"]


def test_inference_batch_and_dataframe():
    """Test NetworkPredictor handles batches and pandas DataFrames."""
    predictor = NetworkPredictor().load_artifacts()

    batch = [
        {"destination_port": 443, "flow_duration": 180000, "total_fwd_packets": 10},
        {"destination_port": 22, "flow_duration": 1500, "total_fwd_packets": 1},
    ]

    # List of dicts
    batch_res = predictor.predict(batch)
    assert isinstance(batch_res, list)
    assert len(batch_res) == 2

    # DataFrame
    df = pd.DataFrame(batch)
    df_res = predictor.predict(df)
    assert isinstance(df_res, list)
    assert len(df_res) == 2


def test_inference_handles_empty_or_invalid_input():
    """Verify error handling on invalid or empty inputs."""
    predictor = NetworkPredictor().load_artifacts()

    with pytest.raises(ValueError):
        predictor.predict({})

    with pytest.raises(ValueError):
        predictor.predict([])

    with pytest.raises(TypeError):
        predictor.predict("not-a-valid-input-type")
