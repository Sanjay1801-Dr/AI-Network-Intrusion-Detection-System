"""Focused tests for Phase 10 Production Configuration & Deployment Readiness."""

import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.core.config import Settings
from backend.app.main import app


@pytest.fixture
def client():
    return TestClient(app)


# ==============================================================================
# 1. CONFIGURATION VALIDATION & PRODUCTION HARDENING
# ==============================================================================

def test_development_accepts_safe_defaults():
    """Verify development configuration boots cleanly with safe local defaults."""
    s = Settings()
    assert s.ENVIRONMENT in ("development", "staging")
    assert s.PORT == 8000
    assert s.HOST == "127.0.0.1"
    assert s.LOG_LEVEL in ("DEBUG", "INFO", "WARNING", "ERROR")
    assert s.DATABASE_URL.startswith("sqlite:") or s.DATABASE_URL.startswith("postgresql:")


def test_production_rejects_insecure_placeholder_jwt_secret():
    """Verify production environment strictly rejects insecure placeholder JWT secret."""
    with pytest.raises(ValueError, match="Insecure or placeholder JWT secret"):
        Settings(
            NIDS_ENVIRONMENT="production",
            NIDS_JWT_SECRET="CHANGE_ME_IN_DEVELOPMENT",
        )


def test_production_rejects_short_jwt_secret():
    """Verify production environment rejects JWT secret with fewer than 32 characters."""
    with pytest.raises(ValueError, match="Insecure or placeholder JWT secret"):
        Settings(
            NIDS_ENVIRONMENT="production",
            NIDS_JWT_SECRET="too_short_secret_key",
        )


def test_production_accepts_strong_secret():
    """Verify production environment accepts strong, randomly generated secrets >= 32 characters."""
    strong_secret = "nids-ultra-secure-production-signing-key-minimum-32-chars-long"
    s = Settings(
        NIDS_ENVIRONMENT="production",
        NIDS_JWT_SECRET=strong_secret,
        NIDS_CORS_ORIGINS="http://nids.soc.internal",
    )
    assert s.ENVIRONMENT == "production"
    assert s.SECRET_KEY == strong_secret


def test_production_rejects_wildcard_cors():
    """Verify production environment rejects wildcard '*' CORS allowed origins."""
    strong_secret = "nids-ultra-secure-production-signing-key-minimum-32-chars-long"
    with pytest.raises(ValueError, match="Wildcard '\\*' CORS origin is strictly disallowed"):
        Settings(
            NIDS_ENVIRONMENT="production",
            NIDS_JWT_SECRET=strong_secret,
            NIDS_CORS_ORIGINS="*",
        )


def test_environment_variable_parsing():
    """Verify custom NIDS_* environment variable overrides are parsed accurately."""
    s = Settings(
        NIDS_ENVIRONMENT="staging",
        NIDS_HOST="0.0.0.0",
        NIDS_PORT=8080,
        NIDS_LOG_LEVEL="WARNING",
        NIDS_CORS_ORIGINS="http://client-a.internal, http://client-b.internal",
        NIDS_DATABASE_URL="postgresql+psycopg2://user:pass@localhost:5432/nids",
    )
    assert s.ENVIRONMENT == "staging"
    assert s.HOST == "0.0.0.0"
    assert s.PORT == 8080
    assert s.LOG_LEVEL == "WARNING"
    assert s.ALLOWED_ORIGINS == ["http://client-a.internal", "http://client-b.internal"]
    assert s.DATABASE_URL == "postgresql+psycopg2://user:pass@localhost:5432/nids"


def test_invalid_port_rejected():
    """Verify port numbers outside 1-65535 raise a validation error."""
    with pytest.raises(ValueError, match="Server port must be an integer between 1 and 65535"):
        Settings(NIDS_PORT=99999)

    with pytest.raises(ValueError, match="Server port must be an integer between 1 and 65535"):
        Settings(NIDS_PORT=-1)


def test_invalid_database_url_rejected():
    """Verify unsupported database dialects are rejected with a clear message."""
    with pytest.raises(ValueError, match="Database URL must be a valid SQLite or PostgreSQL"):
        Settings(NIDS_DATABASE_URL="mongodb://localhost:27017/nids")


def test_invalid_log_level_rejected():
    """Verify invalid log levels are rejected."""
    with pytest.raises(ValueError, match="Log level must be one of"):
        Settings(NIDS_LOG_LEVEL="VERBOSE_TRACE")


# ==============================================================================
# 2. RUNTIME SECURITY HEADERS & HEALTH SAFETY
# ==============================================================================

def test_security_headers_injected(client):
    """Verify that HTTP responses include standard defensive security headers."""
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert res.headers.get("Referrer-Policy") == "no-referrer"


def test_health_endpoint_does_not_expose_secrets(client):
    """Verify GET /api/health exposes safe operational metrics and zero credentials or secrets."""
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()

    # Check allowed operational keys
    assert "status" in data
    assert "service" in data
    assert "version" in data
    assert "environment" in data
    assert "timestamp" in data
    assert "components" in data

    # Ensure sensitive credentials are NOT leaked in response
    serialized = str(data).lower()
    for sensitive_word in ("secret", "password", "token", "///", "postgres:", "sqlite:"):
        assert sensitive_word not in serialized, f"Sensitive info '{sensitive_word}' leaked in health endpoint"


# ==============================================================================
# 3. ENVIRONMENT FILE & SECRET INTEGRITY
# ==============================================================================

def test_frontend_env_example_has_no_backend_secrets():
    """Verify frontend/.env.example contains only browser-safe variables and no backend secrets."""
    frontend_env_path = Path("frontend/.env.example")
    assert frontend_env_path.exists(), "frontend/.env.example must exist"
    content = frontend_env_path.read_text(encoding="utf-8")

    assert "VITE_API_BASE_URL" in content
    assert "JWT_SECRET" not in content
    assert "DATABASE_URL" not in content
    assert "POSTGRES_PASSWORD" not in content


def test_root_env_example_has_no_real_credentials():
    """Verify root .env.example contains safe placeholders and no hardcoded credentials."""
    root_env_path = Path(".env.example")
    assert root_env_path.exists(), ".env.example must exist"
    lines = root_env_path.read_text(encoding="utf-8").splitlines()

    # Verify placeholder JWT secret is explicitly used
    jwt_secret_lines = [line.strip() for line in lines if line.startswith("NIDS_JWT_SECRET=")]
    assert len(jwt_secret_lines) == 1
    assert jwt_secret_lines[0] == "NIDS_JWT_SECRET=CHANGE_ME_IN_DEVELOPMENT"

    # Verify no un-commented password definitions exist
    uncommented_password_lines = [
        line.strip() for line in lines
        if "PASSWORD=" in line and not line.strip().startswith("#")
    ]
    assert len(uncommented_password_lines) == 0, (
        f"Found active password definition in .env.example: {uncommented_password_lines}"
    )

    # Verify any password or secret references use safe placeholders
    for line in lines:
        stripped = line.strip()
        if "PASSWORD=" in stripped or "SECRET=" in stripped:
            assert any(
                placeholder in stripped
                for placeholder in ("CHANGE_ME", "supply_secure_password", "placeholder")
            ), f"Credential line lacks safe placeholder pattern: {stripped}"

