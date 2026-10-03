"""Evaluation metrics and confusion matrix computation for supervised threat classification."""

import logging
from typing import Any, Dict, List, Optional, Union
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

logger = logging.getLogger("nids.eval_classifier")


class ClassifierEvaluator:
    """Computes comprehensive multi-class evaluation metrics, reports, and confusion matrices."""

    @staticmethod
    def evaluate(
        y_true: Union[pd.Series, np.ndarray, List[str]],
        y_pred: Union[pd.Series, np.ndarray, List[str]],
        class_labels: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Calculate multi-class classification metrics.

        Args:
            y_true: Ground truth labels.
            y_pred: Model predicted labels.
            class_labels: Optional explicit list of class names.

        Returns:
            Dictionary containing accuracy, precision, recall, F1, per-class breakdown,
            and formatted confusion matrix data.
        """
        y_t = np.asarray(y_true).astype(str)
        y_p = np.asarray(y_pred).astype(str)

        if class_labels is None:
            class_labels = sorted(list(set(y_t).union(set(y_p))))

        # High-level aggregate metrics
        acc = float(accuracy_score(y_t, y_p))
        prec_macro = float(precision_score(y_t, y_p, labels=class_labels, average="macro", zero_division=0))
        prec_weighted = float(precision_score(y_t, y_p, labels=class_labels, average="weighted", zero_division=0))
        rec_macro = float(recall_score(y_t, y_p, labels=class_labels, average="macro", zero_division=0))
        rec_weighted = float(recall_score(y_t, y_p, labels=class_labels, average="weighted", zero_division=0))
        f1_macro = float(f1_score(y_t, y_p, labels=class_labels, average="macro", zero_division=0))
        f1_weighted = float(f1_score(y_t, y_p, labels=class_labels, average="weighted", zero_division=0))

        # Detailed per-class classification report
        report_dict = classification_report(
            y_t,
            y_p,
            labels=class_labels,
            output_dict=True,
            zero_division=0,
        )

        # Confusion Matrix
        cm = confusion_matrix(y_t, y_p, labels=class_labels)
        cm_df = pd.DataFrame(cm, index=class_labels, columns=class_labels)

        results = {
            "accuracy": round(acc, 4),
            "precision_macro": round(prec_macro, 4),
            "precision_weighted": round(prec_weighted, 4),
            "recall_macro": round(rec_macro, 4),
            "recall_weighted": round(rec_weighted, 4),
            "f1_macro": round(f1_macro, 4),
            "f1_weighted": round(f1_weighted, 4),
            "sample_count": len(y_t),
            "classes": class_labels,
            "classification_report": report_dict,
            "confusion_matrix_dict": cm_df.to_dict(),
            "confusion_matrix_df": cm_df,
        }

        logger.info(
            "Classifier Evaluation: Accuracy=%.4f, Macro-F1=%.4f, Weighted-F1=%.4f",
            acc,
            f1_macro,
            f1_weighted,
        )

        return results
