"""Application configuration settings management using Pydantic Settings (Phase 10)."""

from typing import List, Union
from pydantic import AliasChoices, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable overrides and production validation."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # 1. Application & Environment
    ENVIRONMENT: str = Field(
        default="development",
        validation_alias=AliasChoices("NIDS_ENVIRONMENT", "ENVIRONMENT"),
        description="Operating environment: development | staging | production",
    )
    DEBUG: bool = Field(
        default=True,
        validation_alias=AliasChoices("NIDS_DEBUG", "DEBUG"),
    )
    APP_NAME: str = "AI Network Intrusion Detection System"
    APP_VERSION: str = "1.0.0-phase10"

    # 2. Server Bind & Gateway
    HOST: str = Field(
        default="127.0.0.1",
        validation_alias=AliasChoices("NIDS_HOST", "HOST"),
    )
    PORT: int = Field(
        default=8000,
        validation_alias=AliasChoices("NIDS_PORT", "PORT"),
    )
    API_V1_PREFIX: str = "/api/v1"

    # 3. Security & JWT Access Tokens
    SECRET_KEY: str = Field(
        default="ids-secure-secret-key-phase1-dev-only-min-32-chars-long",
        validation_alias=AliasChoices("NIDS_JWT_SECRET", "SECRET_KEY", "SECURITY_SECRET_KEY"),
        description="HMAC SHA-256 signing secret for operator JWT access tokens",
    )
    ALGORITHM: str = Field(
        default="HS256",
        validation_alias=AliasChoices("NIDS_JWT_ALGORITHM", "ALGORITHM"),
    )
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(
        default=480,
        validation_alias=AliasChoices("NIDS_JWT_EXPIRE_MINUTES", "ACCESS_TOKEN_EXPIRE_MINUTES"),
        description="Access token lifespan in minutes",
    )

    # 4. CORS Allowed Origins
    ALLOWED_ORIGINS: Union[List[str], str] = Field(
        default=[
            "http://127.0.0.1:5173",
            "http://localhost:5173",
            "http://127.0.0.1:3000",
            "http://localhost:3000",
        ],
        validation_alias=AliasChoices("NIDS_CORS_ORIGINS", "ALLOWED_ORIGINS"),
    )

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        """Parse comma-separated string into a list of origins if necessary."""
        if isinstance(v, str) and not v.startswith("["):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        elif isinstance(v, list):
            return [str(origin).strip() for origin in v if str(origin).strip()]
        return [str(v).strip()]

    # 5. Database Persistence
    DATABASE_URL: str = Field(
        default="sqlite:///./network_ids.db",
        validation_alias=AliasChoices("NIDS_DATABASE_URL", "DATABASE_URL"),
        description="Database connection URI (SQLite for local dev, PostgreSQL for production)",
    )
    DB_ECHO_SQL: bool = False
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20

    # 6. Machine Learning Settings
    MODEL_DIRECTORY: str = "machine_learning/models"
    PREPROCESSOR_FILENAME: str = "preprocessor.joblib"
    ANOMALY_MODEL_FILENAME: str = "anomaly_detector.joblib"
    CLASSIFIER_MODEL_FILENAME: str = "threat_classifier.joblib"
    METADATA_FILENAME: str = "model_metadata.json"
    CONFIDENCE_THRESHOLD: float = 0.70
    ANOMALY_CONTAMINATION: float = 0.05

    # 7. Logging & Diagnostics
    LOG_LEVEL: str = Field(
        default="INFO",
        validation_alias=AliasChoices("NIDS_LOG_LEVEL", "LOG_LEVEL"),
    )
    LOG_FILE_PATH: str = "./logs/nids_system.log"
    ENABLE_AUDIT_LOGGING: bool = True

    # 8. Rate Limiting & Abuse Protection (Phase 11)
    RATE_LIMIT_ENABLED: bool = Field(
        default=True,
        validation_alias=AliasChoices("NIDS_RATE_LIMIT_ENABLED", "RATE_LIMIT_ENABLED"),
        description="Globally toggle API rate limiting (True in production and staging)",
    )
    RATE_LIMIT_LOGIN: str = Field(
        default="5/minute",
        validation_alias=AliasChoices("NIDS_RATE_LIMIT_LOGIN", "RATE_LIMIT_LOGIN"),
        description="Rate limit for POST /api/v1/auth/login",
    )
    RATE_LIMIT_PREDICT: str = Field(
        default="60/minute",
        validation_alias=AliasChoices("NIDS_RATE_LIMIT_PREDICT", "RATE_LIMIT_PREDICT"),
        description="Rate limit for POST /api/v1/predict",
    )
    RATE_LIMIT_READ: str = Field(
        default="120/minute",
        validation_alias=AliasChoices("NIDS_RATE_LIMIT_READ", "RATE_LIMIT_READ"),
        description="Rate limit for read endpoints (GET /predictions, GET /alerts, GET /auth/me)",
    )
    RATE_LIMIT_MUTATION: str = Field(
        default="30/minute",
        validation_alias=AliasChoices("NIDS_RATE_LIMIT_MUTATION", "RATE_LIMIT_MUTATION"),
        description="Rate limit for state-changing mutation endpoints (PATCH /alerts/{id}/acknowledge, resolve)",
    )

    # ==========================================================================
    # Validation Rules
    # ==========================================================================

    @field_validator("PORT")
    @classmethod
    def validate_port(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError(f"Server port must be an integer between 1 and 65535, received {v}")
        return v

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper_v = str(v).upper().strip()
        if upper_v not in valid_levels:
            raise ValueError(f"Log level must be one of {valid_levels}, received '{v}'")
        return upper_v

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        if not v or not str(v).strip():
            raise ValueError("Database URL cannot be empty.")
        val = str(v).strip()
        valid_prefixes = ("sqlite:", "postgresql:", "postgres:", "postgresql+psycopg2:", "postgresql+asyncpg:")
        if not any(val.startswith(p) for p in valid_prefixes):
            raise ValueError(
                "Database URL must be a valid SQLite or PostgreSQL connection string "
                f"(supported prefixes: {valid_prefixes})"
            )
        return val

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        if not v or not str(v).strip():
            raise ValueError("JWT secret key cannot be empty.")
        return str(v).strip()

    @field_validator(
        "RATE_LIMIT_LOGIN",
        "RATE_LIMIT_PREDICT",
        "RATE_LIMIT_READ",
        "RATE_LIMIT_MUTATION",
        mode="before",
    )
    @classmethod
    def validate_rate_limit_format(cls, v: str) -> str:
        if not v or not str(v).strip():
            raise ValueError("Rate limit value cannot be empty.")
        val = str(v).strip()
        try:
            from limits import parse
            parse(val)
        except Exception as exc:
            raise ValueError(
                f"Invalid rate limit format: '{val}'. Expected format like '5/minute', '60/hour'."
            ) from exc
        return val

    @model_validator(mode="after")
    def validate_production_hardening(self) -> "Settings":
        """Enforce strict production hardening rules when running in production mode."""
        env = self.ENVIRONMENT.lower().strip()
        if env in ("production", "prod"):
            # 1. Insecure placeholder secret rejection
            insecure_placeholders = {
                "CHANGE_ME_IN_DEVELOPMENT",
                "change-this-to-a-secure-random-secret-key-in-production-min-32-chars",
                "ids-secure-secret-key-phase1-dev-only-min-32-chars-long",
                "ids-local-dev-secret-key-phase1-testing-32chars",
                "secret",
                "admin",
                "password",
                "123456",
                "changeme",
            }
            if self.SECRET_KEY in insecure_placeholders or len(self.SECRET_KEY) < 32:
                raise ValueError(
                    "Insecure or placeholder JWT secret detected in production environment. "
                    "A strong, randomly generated secret of at least 32 characters must be supplied."
                )

            # 2. Reject wildcard CORS origin in production
            cors_list = self.ALLOWED_ORIGINS if isinstance(self.ALLOWED_ORIGINS, list) else [self.ALLOWED_ORIGINS]
            if "*" in cors_list:
                raise ValueError(
                    "Wildcard '*' CORS origin is strictly disallowed in production environment. "
                    "Explicitly configure trusted client origins."
                )

            # 3. Reject disabling rate limiting in production
            if not self.RATE_LIMIT_ENABLED:
                raise ValueError(
                    "Rate limiting cannot be disabled in production environment "
                    "(NIDS_RATE_LIMIT_ENABLED must be True)."
                )

        return self

    # ==========================================================================
    # Compatibility Property Aliases
    # ==========================================================================

    @property
    def NIDS_ENVIRONMENT(self) -> str:
        return self.ENVIRONMENT

    @property
    def NIDS_DATABASE_URL(self) -> str:
        return self.DATABASE_URL

    @property
    def NIDS_JWT_SECRET(self) -> str:
        return self.SECRET_KEY

    @property
    def NIDS_JWT_ALGORITHM(self) -> str:
        return self.ALGORITHM

    @property
    def NIDS_JWT_EXPIRE_MINUTES(self) -> int:
        return self.ACCESS_TOKEN_EXPIRE_MINUTES

    @property
    def NIDS_CORS_ORIGINS(self) -> List[str]:
        return self.ALLOWED_ORIGINS if isinstance(self.ALLOWED_ORIGINS, list) else [self.ALLOWED_ORIGINS]

    @property
    def NIDS_HOST(self) -> str:
        return self.HOST

    @property
    def NIDS_PORT(self) -> int:
        return self.PORT

    @property
    def NIDS_LOG_LEVEL(self) -> str:
        return self.LOG_LEVEL

    @property
    def NIDS_RATE_LIMIT_ENABLED(self) -> bool:
        return self.RATE_LIMIT_ENABLED

    @property
    def NIDS_RATE_LIMIT_LOGIN(self) -> str:
        return self.RATE_LIMIT_LOGIN

    @property
    def NIDS_RATE_LIMIT_PREDICT(self) -> str:
        return self.RATE_LIMIT_PREDICT

    @property
    def NIDS_RATE_LIMIT_READ(self) -> str:
        return self.RATE_LIMIT_READ

    @property
    def NIDS_RATE_LIMIT_MUTATION(self) -> str:
        return self.RATE_LIMIT_MUTATION


# Global settings singleton
settings = Settings()
