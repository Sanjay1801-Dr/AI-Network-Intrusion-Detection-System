"""Master training pipeline orchestrator for AI-Based Network Intrusion Detection System."""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from machine_learning.pipelines.dataset_loader import DatasetLoader
from machine_learning.pipelines.dataset_inspector import DatasetInspector
from machine_learning.pipelines.preprocessing import NetworkDataPreprocessor
from machine_learning.training.train_anomaly_detector import AnomalyDetectorTrainer
from machine_learning.training.train_threat_classifier import ThreatClassifierTrainer
from machine_learning.evaluation.evaluate_classifier import ClassifierEvaluator
from machine_learning.evaluation.evaluate_anomaly import AnomalyEvaluator
from machine_learning.evaluation.reports import EvaluationReporter

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("nids.training")


def train_pipeline(
    input_file: Optional[str] = None,
    test_size: float = 0.30,
    random_state: int = 42,
    contamination: float = 0.05,
    models_dir: str = "machine_learning/models",
    eval_dir: str = "machine_learning/evaluation",
) -> Dict[str, Any]:
    """Execute complete Phase 3 machine learning training, evaluation, and serialization workflow."""
    border = "=" * 80
    print("\n" + border)
    print(" AI NETWORK INTRUSION DETECTION SYSTEM -- PHASE 3 MODEL TRAINING ".center(78))
    print(border)

    # 1. Dataset Discovery & Ingestion
    loader = DatasetLoader()
    raw_df, load_meta = loader.load_dataset(file_path=input_file)
    is_sample = bool(load_meta["is_sample_dataset"])

    if is_sample:
        print("\n" + "!" * 80)
        print("  WARNING: DEVELOPMENT SAMPLE IN USE.")
        print("  Model metrics are for pipeline validation only and must not be interpreted")
        print("  as real-world security detection performance.")
        print("  Place full benchmark CSV files into 'datasets/raw/' for production training.")
        print("!" * 80)

    print(f"\n[1/8] Loaded Training Data: {load_meta['file_name']}")
    print(f"      File Path:    {load_meta['file_path']}")
    print(f"      Total Flows:  {load_meta['raw_row_count']:,} | Total Columns: {load_meta['raw_column_count']}")
    print(f"      Sample Mode:  {is_sample}")

    # 2. Diagnostic Inspection
    print("\n[2/8] Running Initial Data Inspection...")
    insp_report = DatasetInspector.inspect(raw_df)
    DatasetInspector.print_terminal_report(insp_report, title=f"DATASET DIAGNOSTICS: {load_meta['file_name']}")

    # 3. Clean and Extract Labels
    print("\n[3/8] Cleaning Data & Normalizing Attack Labels...")
    preprocessor = NetworkDataPreprocessor(scaler_type="robust")
    cleaned_df, hygiene_log = preprocessor.clean_raw_dataframe(raw_df, is_training=True)
    features_df, orig_labels, norm_labels, is_intrusion = preprocessor.extract_and_normalize_labels(cleaned_df)

    if norm_labels is None:
        raise ValueError("Cannot train supervised classifier without a target label column.")

    print(f"      Cleaned Flow Records: {len(features_df)} (Removed {hygiene_log['duplicates_removed']} duplicates)")
    print("      Class Distribution:")
    class_counts = norm_labels.value_counts()
    for cls_name, cnt in class_counts.items():
        pct = (cnt / len(norm_labels)) * 100
        print(f"        * {cls_name:<24} : {cnt:>5} flows ({pct:>5.1f}%)")

    # 4. Train / Test Split (Strict Anti-Leakage Isolation)
    print("\n[4/8] Splitting Data into Training and Evaluation Sets...")
    # Stratification check: Requires at least 2 samples per class
    min_class_count = int(class_counts.min())
    use_stratify = min_class_count >= 2

    if use_stratify:
        logger.info("Using stratified train-test split (min class count = %d)", min_class_count)
        X_train_raw, X_test_raw, y_train, y_test, is_intro_train, is_intro_test = train_test_split(
            features_df,
            norm_labels,
            is_intrusion,
            test_size=test_size,
            random_state=random_state,
            stratify=norm_labels,
        )
    else:
        logger.info(
            "Class count < 2 detected for some classes in development sample; using fixed random split."
        )
        X_train_raw, X_test_raw, y_train, y_test, is_intro_train, is_intro_test = train_test_split(
            features_df,
            norm_labels,
            is_intrusion,
            test_size=test_size,
            random_state=random_state,
        )

    print(f"      Training partition:   {len(X_train_raw)} flows ({100 - (test_size * 100):.0f}%)")
    print(f"      Evaluation partition: {len(X_test_raw)} flows ({test_size * 100:.0f}%)")

    # 5. Fit Preprocessor ON TRAINING SPLIT ONLY
    print("\n[5/8] Fitting Anti-Leakage Preprocessor Exclusively on Training Split...")
    X_train = preprocessor.fit_transform(X_train_raw)
    X_test = preprocessor.transform(X_test_raw)
    feature_names = preprocessor.get_feature_names_out()

    print(f"      Training Matrix Shape:   {X_train.shape}")
    print(f"      Evaluation Matrix Shape: {X_test.shape}")
    print(f"      Transformed Features:    {len(feature_names)}")

    # 6. Train Anomaly Detection (Isolation Forest)
    print("\n[6/8] Training Unsupervised Anomaly Detector (Isolation Forest)...")
    anomaly_trainer = AnomalyDetectorTrainer(
        contamination=contamination,
        n_estimators=150,
        random_state=random_state,
    )
    anomaly_trainer.fit(X_train)
    test_anom_preds, test_anom_raw, test_anom_scores = anomaly_trainer.predict_with_scores(X_test)

    # 7. Train Threat Classifier (Random Forest)
    print("\n[7/8] Training Supervised Threat Classifier (Random Forest)...")
    classifier_trainer = ThreatClassifierTrainer(
        n_estimators=100,
        max_depth=16,
        class_weight="balanced",
        random_state=random_state,
    )
    classifier_trainer.fit(X_train, y_train)
    test_class_preds = classifier_trainer.predict(X_test)
    feature_importance_df = classifier_trainer.extract_feature_importance(feature_names)

    # 8. Evaluation & Serialization
    print("\n[8/8] Evaluating Models & Serializing Artifacts...")
    classifier_eval = ClassifierEvaluator.evaluate(
        y_true=y_test,
        y_pred=test_class_preds,
        class_labels=classifier_trainer.classes_,
    )

    anomaly_eval = AnomalyEvaluator.evaluate(
        anomaly_predictions=test_anom_preds,
        anomaly_scores=test_anom_scores,
        ground_truth_intrusion=is_intro_test,
    )

    # Save artifacts
    models_path = Path(models_dir)
    models_path.mkdir(parents=True, exist_ok=True)
    eval_path = Path(eval_dir)
    eval_path.mkdir(parents=True, exist_ok=True)

    # 1. Models
    preprocessor_file = models_path / "preprocessor.joblib"
    anomaly_file = models_path / "anomaly_detector.joblib"
    classifier_file = models_path / "threat_classifier.joblib"

    preprocessor.save_pipeline(preprocessor_file)
    anomaly_trainer.save(anomaly_file)
    classifier_trainer.save(classifier_file)

    # Also mirror into machine-learning/models for folder compatibility
    alt_models_path = Path("machine-learning/models")
    alt_models_path.mkdir(parents=True, exist_ok=True)
    preprocessor.save_pipeline(alt_models_path / "preprocessor.joblib")
    anomaly_trainer.save(alt_models_path / "anomaly_detector.joblib")
    classifier_trainer.save(alt_models_path / "threat_classifier.joblib")

    # 2. Evaluation Reports
    reporter = EvaluationReporter(output_dir=eval_path)
    reporter.save_feature_importance(feature_importance_df)
    reporter.save_confusion_matrix(classifier_eval["confusion_matrix_df"])
    reporter.save_classification_report(classifier_eval["classification_report"])

    # 3. Model Metadata Catalog
    metadata_file = models_path / "model_metadata.json"
    metadata: Dict[str, Any] = {
        "model_version": "1.0.0-phase3",
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "training_dataset": {
            "name": load_meta["file_name"],
            "source": load_meta["file_path"],
            "is_sample_dataset": is_sample,
            "disclaimer": (
                "DEVELOPMENT SAMPLE RESULTS ONLY. Not indicative of real-world detection capability."
                if is_sample
                else "PRODUCTION BENCHMARK MODEL."
            ),
        },
        "dataset_split": {
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "test_size_fraction": test_size,
            "random_state": random_state,
            "stratified": use_stratify,
        },
        "feature_engineering": {
            "total_features": len(feature_names),
            "feature_names": feature_names,
            "top_10_features": feature_importance_df.head(10)["feature"].tolist(),
        },
        "anomaly_detector": {
            "hyperparameters": anomaly_trainer.get_hyperparameters(),
            "evaluation": {
                "flagged_anomalies": anomaly_eval["flagged_anomalies"],
                "anomaly_rate": anomaly_eval["anomaly_rate"],
            },
        },
        "threat_classifier": {
            "hyperparameters": classifier_trainer.get_hyperparameters(),
            "classes": classifier_trainer.classes_,
            "evaluation": {
                "test_accuracy": classifier_eval["accuracy"],
                "f1_macro": classifier_eval["f1_macro"],
                "f1_weighted": classifier_eval["f1_weighted"],
            },
        },
        "anti_leakage_guarantees": {
            "preprocessor_fitted_on_train_only": True,
            "target_excluded_from_features": True,
            "frozen_serializable_estimators": True,
        },
    }

    with open(metadata_file, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    # Mirror metadata to machine-learning/models
    with open(alt_models_path / "model_metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    # Save consolidated metrics
    reporter.save_model_metrics(
        classifier_metrics=classifier_eval,
        anomaly_metrics=anomaly_eval,
        metadata=metadata,
    )

    # Print summary to terminal
    EvaluationReporter.print_terminal_summary(
        classifier_metrics=classifier_eval,
        anomaly_metrics=anomaly_eval,
        is_development_sample=is_sample,
    )

    print(f"[OK] Model Artifacts Saved to: {models_path.resolve()}")
    print(f"[OK] Evaluation Reports in:    {eval_path.resolve()}")
    print("=" * 80 + "\n")

    return metadata


if __name__ == "__main__":
    train_pipeline()
