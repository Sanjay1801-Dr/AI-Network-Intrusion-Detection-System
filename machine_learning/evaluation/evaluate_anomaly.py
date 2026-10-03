"""Evaluation module for unsupervised anomaly detection."""

import logging
from typing import Any, Dict, Optional, Union
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

logger = logging.getLogger("nids.eval_anomaly")


class AnomalyEvaluator:
    """Evaluates unsupervised anomaly detection behavior with or without ground-truth intrusion labels."""

    @staticmethod
    def evaluate(
        anomaly_predictions: np.ndarray,
        anomaly_scores: np.ndarray,
        ground_truth_intrusion: Optional[Union[pd.Series, np.ndarray]] = None,
    ) -> Dict[str, Any]:
        """Compute diagnostic metrics for anomaly detection.

        Args:
            anomaly_predictions: Binary array where 0 = Normal, 1 = Anomaly.
            anomaly_scores: Normalized anomaly scores in [0.0, 1.0] (higher = more anomalous).
            ground_truth_intrusion: Optional binary array (0 = Benign, 1 = Attack) for validation.

        Returns:
            Dictionary containing distribution metrics and (if labels available) detection accuracy metrics.
        """
        preds = np.asarray(anomaly_predictions).astype(int)
        scores = np.asarray(anomaly_scores).astype(float)
        total_samples = len(preds)

        flagged_anomalies = int(np.sum(preds == 1))
        anomaly_rate = round(flagged_anomalies / total_samples, 4) if total_samples > 0 else 0.0

        results: Dict[str, Any] = {
            "total_samples": total_samples,
            "flagged_anomalies": flagged_anomalies,
            "flagged_normal": total_samples - flagged_anomalies,
            "anomaly_rate": anomaly_rate,
            "score_distribution": {
                "min": round(float(np.min(scores)), 4) if total_samples > 0 else 0.0,
                "median": round(float(np.median(scores)), 4) if total_samples > 0 else 0.0,
                "mean": round(float(np.mean(scores)), 4) if total_samples > 0 else 0.0,
                "max": round(float(np.max(scores)), 4) if total_samples > 0 else 0.0,
            },
        }

        # If supervised ground truth binary indicator is provided for benchmark validation
        if ground_truth_intrusion is not None:
            y_true = np.asarray(ground_truth_intrusion).astype(int)
            cm = confusion_matrix(y_true, preds, labels=[0, 1])
            tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

            # Detection rate = Recall on attack class (TP / (TP + FN))
            detection_rate = round(float(recall_score(y_true, preds, pos_label=1, zero_division=0)), 4)
            # False Alarm Rate = FP / (FP + TN)
            false_alarm_rate = round(float(fp / (fp + tn)), 4) if (fp + tn) > 0 else 0.0
            prec = round(float(precision_score(y_true, preds, pos_label=1, zero_division=0)), 4)
            f1 = round(float(f1_score(y_true, preds, pos_label=1, zero_division=0)), 4)

            results["supervised_validation"] = {
                "true_positives": int(tp),
                "false_positives": int(fp),
                "true_negatives": int(tn),
                "false_negatives": int(fn),
                "anomaly_precision": prec,
                "anomaly_recall_detection_rate": detection_rate,
                "anomaly_f1_score": f1,
                "false_alarm_rate": false_alarm_rate,
                "note": (
                    "Unsupervised anomaly detection flags deviations from baseline distribution; "
                    "metrics indicate degree of alignment between statistical outliers and attack labels."
                ),
            }

        return results
