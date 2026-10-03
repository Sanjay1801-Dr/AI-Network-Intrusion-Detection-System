"""Service layer coordinating machine learning inference and model lifecycle."""

import logging
from pathlib import Path
from typing import Any, Dict, Optional
from backend.app.core.config import settings
from backend.app.core.errors import ModelInferenceException, AppException
from machine_learning.inference.predictor import NetworkPredictor

logger = logging.getLogger("nids.services.prediction")


class PredictionService:
    """Singleton service managing model persistence, life cycle, and runtime inference.

    Architectural Guarantees:
    - Models are loaded once at startup and reused for all subsequent inference requests.
    - Models are NEVER trained or refitted during prediction requests.
    - If models are missing or corrupted, the service logs the technical fault server-side
      and returns controlled 503 Service Unavailable responses without leaking filesystem paths.
    """

    _predictor: Optional[NetworkPredictor] = None
    _status: str = "uninitialized"  # "ready" | "unavailable" | "degraded" | "uninitialized"
    _error_message: Optional[str] = None

    @classmethod
    def resolve_model_paths(cls) -> Dict[str, Path]:
        """Resolve paths to serialized Phase 3 model artifacts with automatic fallbacks."""
        base_dir = Path(settings.MODEL_DIRECTORY)
        candidate_dirs = [
            Path("machine_learning/models"),
            Path("machine-learning/models"),
            base_dir,
        ]

        preprocessor_fallbacks = ["preprocessor.joblib", "feature_scaler_v1.joblib"]
        anomaly_fallbacks = ["anomaly_detector.joblib", "isolation_forest_v1.joblib"]
        classifier_fallbacks = ["threat_classifier.joblib", "threat_classifier_rf_v1.joblib"]
        metadata_fallbacks = ["model_metadata.json"]

        for cand in candidate_dirs:
            if not cand.exists():
                continue
            prep = next((cand / f for f in [getattr(settings, "PREPROCESSOR_FILENAME", "preprocessor.joblib")] + preprocessor_fallbacks if (cand / f).exists()), None)
            anom = next((cand / f for f in [settings.ANOMALY_MODEL_FILENAME] + anomaly_fallbacks if (cand / f).exists()), None)
            clf = next((cand / f for f in [settings.CLASSIFIER_MODEL_FILENAME] + classifier_fallbacks if (cand / f).exists()), None)
            meta = next((cand / f for f in [getattr(settings, "METADATA_FILENAME", "model_metadata.json")] + metadata_fallbacks if (cand / f).exists()), None)

            if prep and anom and clf:
                return {
                    "preprocessor": prep,
                    "anomaly": anom,
                    "classifier": clf,
                    "metadata": meta if meta else cand / "model_metadata.json",
                }

        return {
            "preprocessor": base_dir / getattr(settings, "PREPROCESSOR_FILENAME", "preprocessor.joblib"),
            "anomaly": base_dir / settings.ANOMALY_MODEL_FILENAME,
            "classifier": base_dir / settings.CLASSIFIER_MODEL_FILENAME,
            "metadata": base_dir / getattr(settings, "METADATA_FILENAME", "model_metadata.json"),
        }

    @classmethod
    def initialize(cls, force_reload: bool = False) -> bool:
        """Load serialized ML models once into memory.

        Returns:
            bool: True if models loaded successfully and are ready, False otherwise.
        """
        if cls._predictor is not None and cls._status == "ready" and not force_reload:
            return True

        paths = cls.resolve_model_paths()

        # Check required files
        missing_files = [
            name for name, p in paths.items()
            if name != "metadata" and not p.exists()
        ]

        if missing_files:
            cls._status = "unavailable"
            cls._error_message = f"Missing model artifacts: {', '.join(missing_files)}"
            logger.error(
                "PredictionService initialization failed: %s (Searched directory: %s)",
                cls._error_message,
                paths["preprocessor"].parent,
            )
            return False

        try:
            logger.info("Initializing NetworkPredictor from %s...", paths["preprocessor"].parent)
            predictor = NetworkPredictor(
                preprocessor_path=paths["preprocessor"],
                anomaly_model_path=paths["anomaly"],
                classifier_model_path=paths["classifier"],
                metadata_path=paths["metadata"],
            )
            predictor.load_artifacts()
            cls._predictor = predictor
            cls._status = "ready"
            cls._error_message = None
            logger.info("PredictionService initialized successfully. ML Engine is READY.")
            return True
        except Exception as exc:
            cls._status = "degraded"
            cls._error_message = "Failed to deserialize model artifacts."
            logger.error(
                "PredictionService failed to load ML models: %s",
                exc,
                exc_info=True,
            )
            return False

    @classmethod
    def is_ready(cls) -> bool:
        """Check if the ML inference engine is loaded and operational."""
        return cls._status == "ready" and cls._predictor is not None

    @classmethod
    def get_status(cls) -> str:
        """Get the current operational status of the ML subsystem."""
        return cls._status

    @classmethod
    def predict(cls, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute dual-stage prediction on validated network flow data.

        Args:
            flow_data: Validated dictionary containing flow telemetry attributes.

        Returns:
            Structured prediction result with anomaly, classification, and risk_assessment sections.

        Raises:
            ModelInferenceException: If ML models are unavailable (HTTP 503).
            AppException: If an unexpected internal prediction failure occurs (HTTP 500).
        """
        if not cls.is_ready():
            # Attempt lazy initialization in case models were placed after startup
            if not cls.initialize():
                raise ModelInferenceException(
                    message="Machine learning inference service is currently unavailable. Please verify model artifacts.",
                    details={"service_status": cls._status},
                )

        assert cls._predictor is not None

        try:
            # Predict uses the frozen pre-fitted estimators; no retraining occurs
            result = cls._predictor.predict(flow_data)
            return result
        except ModelInferenceException:
            raise
        except Exception as exc:
            logger.error("Internal prediction computation error: %s", exc, exc_info=True)
            raise AppException(
                message="An unexpected internal error occurred during prediction inference.",
                error_code="INTERNAL_PREDICTION_ERROR",
                status_code=500,
            )
