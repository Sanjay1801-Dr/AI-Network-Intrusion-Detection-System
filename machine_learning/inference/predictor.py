"""Runtime inference engine for dual-stage anomaly detection and threat classification."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
import pandas as pd

from machine_learning.pipelines.preprocessing import NetworkDataPreprocessor
from machine_learning.training.train_anomaly_detector import AnomalyDetectorTrainer
from machine_learning.training.train_threat_classifier import ThreatClassifierTrainer

logger = logging.getLogger("nids.inference")


class NetworkPredictor:
    """Production-grade inference engine integrating preprocessor, anomaly detector, and threat classifier.

    Core Philosophy:
    - Anomaly detection identifies statistical outliers and unusual flow dynamics (unsupervised).
    - Threat classification identifies known attack signatures based on supervised patterns.
    - An anomaly is NOT automatically assumed to be malicious.
    - Confidence represents the classifier's estimated class posterior probability, not an absolute truth.
    """

    DEFAULT_PREPROCESSOR_PATH = Path("machine_learning/models/preprocessor.joblib")
    DEFAULT_ANOMALY_PATH = Path("machine_learning/models/anomaly_detector.joblib")
    DEFAULT_CLASSIFIER_PATH = Path("machine_learning/models/threat_classifier.joblib")
    DEFAULT_METADATA_PATH = Path("machine_learning/models/model_metadata.json")

    def __init__(
        self,
        preprocessor_path: Optional[Union[str, Path]] = None,
        anomaly_model_path: Optional[Union[str, Path]] = None,
        classifier_model_path: Optional[Union[str, Path]] = None,
        metadata_path: Optional[Union[str, Path]] = None,
    ) -> None:
        self.preprocessor_path = Path(preprocessor_path or self.DEFAULT_PREPROCESSOR_PATH)
        self.anomaly_path = Path(anomaly_model_path or self.DEFAULT_ANOMALY_PATH)
        self.classifier_path = Path(classifier_model_path or self.DEFAULT_CLASSIFIER_PATH)
        self.metadata_path = Path(metadata_path or self.DEFAULT_METADATA_PATH)

        self.preprocessor: Optional[NetworkDataPreprocessor] = None
        self.anomaly_trainer: Optional[AnomalyDetectorTrainer] = None
        self.classifier_trainer: Optional[ThreatClassifierTrainer] = None
        self.metadata: Dict[str, Any] = {}
        self.is_loaded_: bool = False

    def load_artifacts(self) -> "NetworkPredictor":
        """Load all serialized pipelines, estimators, and metadata from disk."""
        if not self.preprocessor_path.exists():
            raise FileNotFoundError(f"Preprocessor artifact missing at: {self.preprocessor_path}")
        if not self.anomaly_path.exists():
            raise FileNotFoundError(f"Anomaly detector artifact missing at: {self.anomaly_path}")
        if not self.classifier_path.exists():
            raise FileNotFoundError(f"Threat classifier artifact missing at: {self.classifier_path}")

        logger.info("Loading inference artifacts from disk...")
        self.preprocessor = NetworkDataPreprocessor.load_pipeline(self.preprocessor_path)
        self.anomaly_trainer = AnomalyDetectorTrainer.load(self.anomaly_path)
        self.classifier_trainer = ThreatClassifierTrainer.load(self.classifier_path)

        if self.metadata_path.exists():
            try:
                with open(self.metadata_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
            except Exception as exc:
                logger.warning("Failed to load metadata file: %s", exc)

        self.is_loaded_ = True
        logger.info("NetworkPredictor initialized and operational.")
        return self

    def _ensure_loaded(self) -> None:
        """Ensure models are loaded prior to inference."""
        if not self.is_loaded_:
            self.load_artifacts()

    @staticmethod
    def _coerce_input_dataframe(data: Union[Dict[str, Any], List[Dict[str, Any]], pd.DataFrame]) -> Tuple[pd.DataFrame, bool]:
        """Convert input data (dict, list of dicts, or DataFrame) into a DataFrame."""
        if isinstance(data, dict):
            if not data:
                raise ValueError("Input dictionary cannot be empty.")
            return pd.DataFrame([data]), True
        elif isinstance(data, list):
            if not data:
                raise ValueError("Input list of records cannot be empty.")
            return pd.DataFrame(data), False
        elif isinstance(data, pd.DataFrame):
            if data.empty:
                raise ValueError("Input DataFrame cannot be empty.")
            return data.copy(), False
        else:
            raise TypeError(f"Unsupported input type: {type(data)}. Expected dict, list of dicts, or DataFrame.")

    def _transform_features(self, df: pd.DataFrame) -> np.ndarray:
        """Pass input flows through the frozen preprocessing pipeline."""
        self._ensure_loaded()
        assert self.preprocessor is not None
        # Drop any accidental target column in test payload to prevent leakage
        clean_df = df.drop(columns=["label", "class", "threat_type"], errors="ignore")
        return self.preprocessor.transform(clean_df)

    def predict_anomaly(
        self,
        data: Union[Dict[str, Any], List[Dict[str, Any]], pd.DataFrame],
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """Execute unsupervised anomaly detection on network flow input."""
        self._ensure_loaded()
        df, is_single = self._coerce_input_dataframe(data)
        X = self._transform_features(df)

        assert self.anomaly_trainer is not None
        binary_preds, raw_scores, norm_scores = self.anomaly_trainer.predict_with_scores(X)

        results = []
        for i in range(len(df)):
            is_anom = bool(binary_preds[i] == 1)
            score = float(norm_scores[i])
            results.append({
                "is_anomaly": is_anom,
                "anomaly_label": "ANOMALOUS" if is_anom else "NORMAL",
                "anomaly_score": score,
                "raw_decision_score": round(float(raw_scores[i]), 4),
                "interpretation": (
                    f"Outlier divergence score: {score:.3f} (0.0=nominal, 1.0=severe outlier)."
                ),
            })

        return results[0] if is_single else results

    def predict_threat(
        self,
        data: Union[Dict[str, Any], List[Dict[str, Any]], pd.DataFrame],
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """Execute supervised multi-class threat classification."""
        self._ensure_loaded()
        df, is_single = self._coerce_input_dataframe(data)
        X = self._transform_features(df)

        assert self.classifier_trainer is not None
        preds = self.classifier_trainer.predict(X)
        probas = self.classifier_trainer.predict_proba(X)
        classes = self.classifier_trainer.classes_

        results = []
        for i in range(len(df)):
            pred_class = str(preds[i])
            class_probs = {cls: round(float(probas[i][idx]), 4) for idx, cls in enumerate(classes)}
            confidence = float(np.max(probas[i]))

            results.append({
                "predicted_label": pred_class,
                "is_intrusion": bool(pred_class != "BENIGN"),
                "confidence": round(confidence, 4),
                "confidence_type": "estimated_class_probability",
                "class_probabilities": class_probs,
            })

        return results[0] if is_single else results

    def predict(
        self,
        data: Union[Dict[str, Any], List[Dict[str, Any]], pd.DataFrame],
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """Unified defensive inference: anomaly detection + threat classification + risk assessment."""
        self._ensure_loaded()
        df, is_single = self._coerce_input_dataframe(data)

        # 1. Run Anomaly Detection
        anomaly_results = self.predict_anomaly(df)
        if isinstance(anomaly_results, dict):
            anomaly_results = [anomaly_results]

        # 2. Run Threat Classification
        threat_results = self.predict_threat(df)
        if isinstance(threat_results, dict):
            threat_results = [threat_results]

        # 3. Combine into unified security decision
        combined = []
        for i in range(len(df)):
            anom = anomaly_results[i]
            threat = threat_results[i]

            # Compute composite risk level:
            # - CRITICAL: High confidence attack classification + elevated anomaly
            # - HIGH: Attack classification with moderate/high confidence OR severe anomaly
            # - MEDIUM: Anomaly detected with benign classification OR low confidence attack
            # - LOW: Normal flow, low anomaly score, benign classification
            is_anom = anom["is_anomaly"]
            anom_score = anom["anomaly_score"]
            is_attack = threat["is_intrusion"]
            confidence = threat["confidence"]

            if is_attack and confidence >= 0.85 and anom_score >= 0.60:
                risk_level = "CRITICAL"
                action = "Immediate SOC Alert & Automated Host Triage"
            elif is_attack and confidence >= 0.70:
                risk_level = "HIGH"
                action = "SOC Incident Queue Escalation"
            elif is_attack or (is_anom and anom_score >= 0.75):
                risk_level = "MEDIUM"
                action = "Flow Telemetry Inspection & Behavioral Audit"
            elif is_anom:
                risk_level = "MEDIUM"
                action = "Log Deviation for Baseline Drift Analysis"
            else:
                risk_level = "LOW"
                action = "Standard Flow Logging"

            summary = (
                f"Flow evaluated: Anomaly={anom['anomaly_label']} (score {anom_score:.2f}), "
                f"Classification='{threat['predicted_label']}' (est. prob {confidence * 100:.1f}%). "
                f"Assigned Risk Level: {risk_level}."
            )

            combined.append({
                "anomaly": anom,
                "classification": threat,
                "risk_assessment": {
                    "risk_level": risk_level,
                    "recommended_action": action,
                    "summary": summary,
                },
            })

        return combined[0] if is_single else combined
