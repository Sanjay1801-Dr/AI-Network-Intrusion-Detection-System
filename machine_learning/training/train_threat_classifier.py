"""Training module for supervised multi-class threat classification using Random Forest."""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

logger = logging.getLogger("nids.train_classifier")


class ThreatClassifierTrainer:
    """Trainer, feature importance analyzer, and serializer for Random Forest threat classification."""

    DEFAULT_N_ESTIMATORS: int = 100
    DEFAULT_MAX_DEPTH: Optional[int] = 16
    DEFAULT_RANDOM_STATE: int = 42

    def __init__(
        self,
        n_estimators: int = DEFAULT_N_ESTIMATORS,
        max_depth: Optional[int] = DEFAULT_MAX_DEPTH,
        min_samples_split: int = 2,
        min_samples_leaf: int = 1,
        class_weight: str = "balanced",
        random_state: int = DEFAULT_RANDOM_STATE,
        n_jobs: int = -1,
    ) -> None:
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.min_samples_leaf = min_samples_leaf
        self.class_weight = class_weight
        self.random_state = random_state
        self.n_jobs = n_jobs

        self.model: Optional[RandomForestClassifier] = None
        self.classes_: List[str] = []
        self.is_fitted_: bool = False

    def fit(self, X_train: np.ndarray, y_train: Union[pd.Series, np.ndarray]) -> RandomForestClassifier:
        """Fit Random Forest on preprocessed training features and normalized threat labels.

        Args:
            X_train: 2D NumPy array of scaled training features.
            y_train: 1D array or Series of normalized category labels (e.g. BENIGN, DoS, Port Scan).

        Returns:
            Fitted RandomForestClassifier.
        """
        if X_train.shape[0] != len(y_train):
            raise ValueError(
                f"Feature count ({X_train.shape[0]}) does not match label count ({len(y_train)})"
            )

        # Convert to numpy array of strings
        y_arr = np.asarray(y_train).astype(str)
        unique_classes, counts = np.unique(y_arr, return_counts=True)
        self.classes_ = list(unique_classes)

        logger.info(
            "Fitting RandomForestClassifier with %d classes: %s",
            len(unique_classes),
            dict(zip(unique_classes, counts)),
        )

        self.model = RandomForestClassifier(
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            min_samples_split=self.min_samples_split,
            min_samples_leaf=self.min_samples_leaf,
            class_weight=self.class_weight,
            random_state=self.random_state,
            n_jobs=self.n_jobs,
        )

        self.model.fit(X_train, y_arr)
        self.is_fitted_ = True
        logger.info("RandomForestClassifier fitted successfully.")
        return self.model

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict multi-class threat categories."""
        if not self.is_fitted_ or self.model is None:
            raise RuntimeError("ThreatClassifierTrainer must be fitted before predict().")
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict class probability distribution across all learned threat categories."""
        if not self.is_fitted_ or self.model is None:
            raise RuntimeError("ThreatClassifierTrainer must be fitted before predict_proba().")
        return self.model.predict_proba(X)

    def extract_feature_importance(self, feature_names: List[str]) -> pd.DataFrame:
        """Extract and sort Gini feature importances.

        Args:
            feature_names: List of column names matching X dimensions.

        Returns:
            DataFrame containing feature names and importance scores, sorted descending.
        """
        if not self.is_fitted_ or self.model is None:
            raise RuntimeError("Classifier must be fitted before extracting feature importance.")

        importances = self.model.feature_importances_
        if len(feature_names) != len(importances):
            # Fallback if names length mismatch
            feature_names = [f"feature_{i}" for i in range(len(importances))]

        df_importance = pd.DataFrame({
            "feature": feature_names,
            "importance": np.round(importances, 6),
        }).sort_values(by="importance", ascending=False).reset_index(drop=True)

        df_importance["cumulative_importance"] = np.round(
            df_importance["importance"].cumsum(), 6
        )
        return df_importance

    def save(self, path: Union[str, Path]) -> Path:
        """Serialize fitted model to disk using joblib."""
        if not self.is_fitted_ or self.model is None:
            raise RuntimeError("Cannot save an unfitted threat classifier.")
        target_path = Path(path)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, target_path)
        logger.info("Saved threat classifier model to %s", target_path)
        return target_path

    @classmethod
    def load(cls, path: Union[str, Path]) -> "ThreatClassifierTrainer":
        """Load a serialized RandomForestClassifier model into a trainer instance."""
        target_path = Path(path)
        if not target_path.exists():
            raise FileNotFoundError(f"Model file not found at: {target_path}")

        loaded_model = joblib.load(target_path)
        if not isinstance(loaded_model, RandomForestClassifier):
            raise TypeError(f"Expected RandomForestClassifier, got {type(loaded_model)}")

        trainer = cls(
            n_estimators=getattr(loaded_model, "n_estimators", cls.DEFAULT_N_ESTIMATORS),
            max_depth=getattr(loaded_model, "max_depth", cls.DEFAULT_MAX_DEPTH),
            random_state=getattr(loaded_model, "random_state", cls.DEFAULT_RANDOM_STATE),
        )
        trainer.model = loaded_model
        trainer.classes_ = list(loaded_model.classes_)
        trainer.is_fitted_ = True
        return trainer

    def get_hyperparameters(self) -> Dict[str, Any]:
        """Return dictionary of classifier hyperparameters."""
        return {
            "model_type": "RandomForestClassifier",
            "algorithm": "Supervised Multi-Class Ensembling",
            "n_estimators": self.n_estimators,
            "max_depth": self.max_depth,
            "min_samples_split": self.min_samples_split,
            "min_samples_leaf": self.min_samples_leaf,
            "class_weight": self.class_weight,
            "random_state": self.random_state,
        }
