"""Main FastAPI application entrypoint for AI-Based Network Intrusion Detection System."""

from contextlib import asynccontextmanager
import logging
from typing import AsyncGenerator
from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from backend.app.core.config import settings
from backend.app.core.errors import register_exception_handlers
from backend.app.db.session import engine, Base
import backend.app.models  # Ensure all model tables are registered with Base.metadata
from backend.app.schemas.health import HealthResponse
from backend.app.services.health_service import HealthService
from backend.app.services.prediction_service import PredictionService
from backend.app.api.v1.api import api_router
from backend.app.core.logging import setup_logging, RequestAuditMiddleware
from backend.app.core.limiter import limiter, rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

# Initialize centralized structured logging
setup_logging(settings.LOG_LEVEL)
logger = logging.getLogger("nids.api")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifecycle manager for startup and shutdown procedures."""
    logger.info("Starting up %s (Version: %s)", settings.APP_NAME, settings.APP_VERSION)
    logger.info("Active environment: %s, Debug: %s", settings.ENVIRONMENT, settings.DEBUG)

    # Initialize database tables on startup (especially for local SQLite dev)
    try:
        logger.info("Initializing database schema on %s...", settings.DATABASE_URL.split("///")[-1])
        Base.metadata.create_all(bind=engine)
        # Idempotently ensure Phase 8 lifecycle timestamp columns exist (for SQLite dev)
        with engine.connect() as conn:
            if "sqlite" in settings.DATABASE_URL:
                cols = [row[1] for row in conn.exec_driver_sql("PRAGMA table_info(alerts)").fetchall()]
                if cols and "acknowledged_at" not in cols:
                    conn.exec_driver_sql("ALTER TABLE alerts ADD COLUMN acknowledged_at TIMESTAMP")
                if cols and "resolved_at" not in cols:
                    conn.exec_driver_sql("ALTER TABLE alerts ADD COLUMN resolved_at TIMESTAMP")
                conn.commit()
        logger.info("Database tables initialized successfully.")
    except Exception as exc:
        logger.error("Database initialization failed: %s", exc)

    # Initialize ML models on startup
    try:
        logger.info("Initializing Machine Learning inference engine...")
        PredictionService.initialize()
        if PredictionService.is_ready():
            logger.info("ML inference engine initialized and ready.")
        else:
            logger.warning("ML inference engine initialized with status: %s", PredictionService.get_status())
    except Exception as exc:
        logger.error("Failed to initialize ML inference engine: %s", exc)

    yield

    logger.info("Shutting down %s...", settings.APP_NAME)


def create_application() -> FastAPI:
    """Application factory configuring middleware, exception handlers, and route controllers."""
    application = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=(
            "Production-style AI-Based Network Intrusion Detection System REST API. "
            "Analyzes network traffic telemetry, flags anomalies, classifies attack patterns, "
            "and delivers actionable security intelligence."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # Configure CORS for local React development
    logger.info("Configuring CORS with allowed origins: %s", settings.ALLOWED_ORIGINS)
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Operational audit logging & security headers middleware
    application.add_middleware(RequestAuditMiddleware)

    # Attach API rate limiter state and exception handler (Phase 11)
    application.state.limiter = limiter
    application.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

    # Register centralized exception handlers
    register_exception_handlers(application)

    # 1. Health-check endpoint directly accessible at GET /api/health
    @application.get(
        "/api/health",
        response_model=HealthResponse,
        status_code=status.HTTP_200_OK,
        tags=["Health"],
        summary="Backend System Health Check",
        description="Confirms that the FastAPI backend service and subcomponents are active and operational.",
    )
    def api_health() -> HealthResponse:
        return HealthService.get_system_health()

    # Root redirect / greeting
    @application.get("/", tags=["Root"], include_in_schema=False)
    def root_redirect():
        return {
            "name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "status": "operational",
            "docs": "/docs",
            "health": "/api/health",
        }

    # 2. Versioned API routers (includes /api/v1/...)
    application.include_router(api_router, prefix=settings.API_V1_PREFIX)

    return application


# Global FastAPI application instance
app = create_application()
