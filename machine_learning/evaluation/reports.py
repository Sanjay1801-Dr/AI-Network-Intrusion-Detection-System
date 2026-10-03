"""Report generation and export module for model evaluation artifacts."""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional
import pandas as pd

logger = logging.getLogger("nids.reports")


class EvaluationReporter:
    """Serializes evaluation metrics, reports, and confusion matrices to disk."""

    DEFAULT_OUTPUT_DIR: Path = Path("machine_learning/evaluation")

    def __init__(self, output_dir: Optional[Path] = None) -> None:
        self.output_dir = output_dir or self.DEFAULT_OUTPUT_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def save_feature_importance(self, df_importance: pd.DataFrame, filename: str = "feature_importance.csv") -> Path:
        """Save feature importances CSV."""
        path = self.output_dir / filename
        df_importance.to_csv(path, index=False)
        logger.info("Saved feature importance to: %s", path)
        return path

    def save_confusion_matrix(self, cm_df: pd.DataFrame, filename: str = "confusion_matrix.csv") -> Path:
        """Save confusion matrix CSV."""
        path = self.output_dir / filename
        cm_df.to_csv(path, index=True)
        logger.info("Saved confusion matrix to: %s", path)
        return path

    def save_classification_report(self, report_dict: Dict[str, Any], filename: str = "classification_report.json") -> Path:
        """Save detailed classification report JSON."""
        path = self.output_dir / filename
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2)
        logger.info("Saved classification report to: %s", path)
        return path

    def save_model_metrics(
        self,
        classifier_metrics: Dict[str, Any],
        anomaly_metrics: Dict[str, Any],
        metadata: Dict[str, Any],
        filename: str = "model_metrics.json",
    ) -> Path:
        """Save combined metrics summary JSON."""
        path = self.output_dir / filename

        # Clean non-serializable objects (like DataFrames)
        clean_classifier = {k: v for k, v in classifier_metrics.items() if not isinstance(v, pd.DataFrame)}

        combined = {
            "evaluation_timestamp": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata,
            "threat_classifier_metrics": clean_classifier,
            "anomaly_detector_metrics": anomaly_metrics,
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(combined, f, indent=2)
        logger.info("Saved consolidated metrics to: %s", path)
        return path

    @staticmethod
    def print_terminal_summary(
        classifier_metrics: Dict[str, Any],
        anomaly_metrics: Dict[str, Any],
        is_development_sample: bool = False,
    ) -> None:
        """Print an executive evaluation summary in terminal."""
        border = "=" * 80
        print("\n" + border)
        print(" MODEL PERFORMANCE EVALUATION SUMMARY ".center(78))
        print(border)

        if is_development_sample:
            print("\n" + "!" * 80)
            print("  WARNING: DEVELOPMENT SAMPLE IN USE.")
            print("  Model metrics are for pipeline validation only and must not be interpreted")
            print("  as real-world security detection performance.")
            print("!" * 80)

        print("\n[+] SUPERVISED THREAT CLASSIFIER (Random Forest):")
        print(f"  - Test Accuracy:        {classifier_metrics['accuracy'] * 100:.2f}%")
        print(f"  - Macro F1-Score:       {classifier_metrics['f1_macro']:.4f}")
        print(f"  - Weighted F1-Score:    {classifier_metrics['f1_weighted']:.4f}")
        print(f"  - Test Flow Count:      {classifier_metrics['sample_count']}")
        print(f"  - Detected Classes:     {', '.join(classifier_metrics['classes'])}")

        print("\n[+] UNSUPERVISED ANOMALY DETECTOR (Isolation Forest):")
        print(f"  - Total Evaluated:      {anomaly_metrics['total_samples']}")
        print(f"  - Flagged as Anomalous: {anomaly_metrics['flagged_anomalies']} ({anomaly_metrics['anomaly_rate'] * 100:.1f}%)")
        print(f"  - Flagged as Normal:    {anomaly_metrics['flagged_normal']}")
        score_dist = anomaly_metrics["score_distribution"]
        print(f"  - Anomaly Score Range:  Min={score_dist['min']:.4f}, Median={score_dist['median']:.4f}, Max={score_dist['max']:.4f}")

        if "supervised_validation" in anomaly_metrics:
            val = anomaly_metrics["supervised_validation"]
            print(f"  - Anomaly Detection Rate (Recall on Attacks): {val['anomaly_recall_detection_rate'] * 100:.1f}%")
            print(f"  - False Alarm Rate (on Benign Traffic):      {val['false_alarm_rate'] * 100:.1f}%")

        print("\n" + border + "\n")
