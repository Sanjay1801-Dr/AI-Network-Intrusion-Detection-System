"""Application configuration settings management using Pydantic Settings."""

from typing import List, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable overrides."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # Application Information
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    APP_NAME: str = "AI Network Intrusion Detection System"
    APP_VERSION: str = "1.0.0-phase1"

    # Server Bind
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    API_V1_PREFIX: str = "/api/v1"

    # Security
    SECRET_KEY: str = "ids-secure-secret-key-phase1-dev-only-min-32-chars-long"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    ALGORITHM: str = "HS256"

    # CORS Allowed Origins
    ALLOWED_ORIGINS: Union[List[str], str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        """Parse comma-separated string into a list of origins if necessary."""
        if isinstance(v, str) and not v.startswith("["):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        elif isinstance(v, list):
            return v
        return [str(v)]

    # Database
    DATABASE_URL: str = "sqlite:///./network_ids.db"
    DB_ECHO_SQL: bool = False
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20

    # Machine Learning Settings
    MODEL_DIRECTORY: str = "./machine-learning/models"
    ANOMALY_MODEL_FILENAME: str = "isolation_forest_v1.joblib"
    CLASSIFIER_MODEL_FILENAME: str = "threat_classifier_rf_v1.joblib"
    FEATURE_SCALER_FILENAME: str = "feature_scaler_v1.joblib"
    CONFIDENCE_THRESHOLD: float = 0.75
    ANOMALY_CONTAMINATION: float = 0.03

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FILE_PATH: str = "./logs/nids_system.log"
    ENABLE_AUDIT_LOGGING: bool = True


# Global settings singleton
settings = Settings()
