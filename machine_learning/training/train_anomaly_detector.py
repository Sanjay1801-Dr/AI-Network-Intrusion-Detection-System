"""Training module for unsupervised network flow anomaly detection using Isolation Forest."""

import logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

logger = logging.getLogger("nids.train_anomaly")


class AnomalyDetectorTrainer:
    """Trainer and serializer for unsupervised Isolation Forest anomaly detection.

    Scoring convention:
    - Raw Isolation Forest: +1 = inlier (normal), -1 = outlier (anomaly).
    - Project binary prediction: 0 = Normal Flow, 1 = Anomalous Flow.
    - Normalized Anomaly Score: [0.0, 1.0] where 0.0 is completely nominal and 1.0 is severely anomalous.
      Note: This represents an outlier deviation degree, NOT a Bayesian probability.
    """

    DEFAULT_CONTAMINATION: float = 0.05
    DEFAULT_N_ESTIMATORS: int = 150
    DEFAULT_RANDOM_STATE: int = 42

    def __init__(
        self,
        contamination: float = DEFAULT_CONTAMINATION,
        n_estimators: int = DEFAULT_N_ESTIMATORS,
        max_samples: Union[str, float, int] = "auto",
        random_state: int = DEFAULT_RANDOM_STATE,
        n_jobs: int = -1,
    ) -> None:
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.random_state = random_state
        self.n_jobs = n_jobs
        self.model: Optional[IsolationForest] = None
        self.is_fitted_: bool = False

    def fit(self, X_train: np.ndarray) -> IsolationForest:
        """Fit Isolation Forest on preprocessed feature vectors.

        Args:
            X_train: 2D NumPy array of preprocessed, scaled feature vectors (no labels).

        Returns:
            Fitted IsolationForest instance.
        """
        if X_train.ndim != 2 or X_train.shape[0] == 0:
            raise ValueError(f"X_train must be a non-empty 2D array, got shape {X_train.shape}")

        logger.info(
            "Fitting IsolationForest (estimators=%d, contamination=%.3f, samples=%d, features=%d)",
            self.n_estimators,
            self.contamination,
            X_train.shape[0],
            X_train.shape[1],
        )

        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            max_samples=self.max_samples,
            random_state=self.random_state,
            n_jobs=self.n_jobs,
        )

        self.model.fit(X_train)
        self.is_fitted_ = True
        logger.info("IsolationForest fitted successfully.")
        return self.model

    def predict_with_scores(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Generate binary predictions, raw decision scores, and normalized anomaly scores.

        Args:
            X: 2D NumPy array of preprocessed features.

        Returns:
            Tuple of:
            - binary_predictions: 1D array where 0 = normal, 1 = anomaly
            - raw_decision_scores: raw score from decision_function (negative = anomalous)
            - normalized_scores: float in [0.0, 1.0] where higher = more anomalous
        """
        if not self.is_fitted_ or self.model is None:
            raise RuntimeError("AnomalyDetectorTrainer must be fitted before generating predictions.")

        # Raw predictions: +1 for normal, -1 for anomalous
        raw_preds = self.model.predict(X)
        # Convert to project convention: 0 = Normal, 1 = Anomalous
        binary_preds = np.where(raw_preds == -1, 1, 0)

        # decision_function yields signed distance to separating hyperplane:
        # Negative values are outliers, positive values are inliers
        raw_scores = self.model.decision_function(X)

        # Normalize into [0.0, 1.0] anomaly severity index:
        # Boundary is at 0.0 -> normalized score = 0.50
        # Significant inlier (+0.25) -> normalized score = 0.0
        # Significant outlier (-0.25) -> normalized score = 1.0
        normalized_scores = np.clip(0.50 - (raw_scores * 2.0), 0.0, 1.0)
        normalized_scores = np.round(normalized_scores, 4)

        return binary_preds, raw_scores, normalized_scores

    def save(self, path: Union[str, Path]) -> Path:
        """Serialize fitted model to disk using joblib."""
        if not self.is_fitted_ or self.model is None:
            raise RuntimeError("Cannot save an unfitted anomaly detection model.")
        target_path = Path(path)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, target_path)
        logger.info("Saved anomaly detector model to %s", target_path)
        return target_path

    @classmethod
    def load(cls, path: Union[str, Path]) -> "AnomalyDetectorTrainer":
        """Load a serialized IsolationForest model into a trainer instance."""
        target_path = Path(path)
        if not target_path.exists():
            raise FileNotFoundError(f"Model file not found at: {target_path}")

        loaded_model = joblib.load(target_path)
        if not isinstance(loaded_model, IsolationForest):
            raise TypeError(f"Expected IsolationForest model, got {type(loaded_model)}")

        trainer = cls(
            contamination=getattr(loaded_model, "contamination", cls.DEFAULT_CONTAMINATION),
            n_estimators=getattr(loaded_model, "n_estimators", cls.DEFAULT_N_ESTIMATORS),
            random_state=getattr(loaded_model, "random_state", cls.DEFAULT_RANDOM_STATE),
        )
        trainer.model = loaded_model
        trainer.is_fitted_ = True
        return trainer

    def get_hyperparameters(self) -> Dict[str, Any]:
        """Return dictionary of model hyperparameters."""
        return {
            "model_type": "IsolationForest",
            "algorithm": "Unsupervised Outlier Isolation",
            "n_estimators": self.n_estimators,
            "contamination": self.contamination,
            "max_samples": str(self.max_samples),
            "random_state": self.random_state,
        }
