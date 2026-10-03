"""Centralized logging configuration and operational request audit middleware (Phase 10)."""

from datetime import datetime, timezone
import logging
import sys
import time
from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("nids.audit")


def setup_logging(log_level: str = "INFO") -> None:
    """Configure structured, production-friendly logging format without exposing sensitive credentials."""
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    # Configure root logger handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(fmt=log_format, datefmt=date_format))

    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    # Replace existing handlers cleanly
    root_logger.handlers = [handler]

    # Configure application loggers
    for logger_name in ("nids", "nids.api", "nids.security", "nids.audit"):
        logging.getLogger(logger_name).setLevel(numeric_level)


class RequestAuditMiddleware(BaseHTTPMiddleware):
    """Operational middleware that records HTTP request metadata, status, duration,

    and injects essential security response headers without leaking sensitive payloads or tokens.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.perf_counter()

        # Execute downstream request pipeline
        try:
            response: Response = await call_next(request)
        except Exception:
            # Let centralized exception handlers capture and format the response
            raise

        duration_ms = (time.perf_counter() - start_time) * 1000.0

        # Inject standard HTTP security headers (Phase 10)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"

        # Log request operational telemetry (excluding sensitive headers and bodies)
        method = request.method
        path = request.url.path
        status_code = response.status_code

        # Sanitized audit message
        log_msg = f"{method} {path} - {status_code} ({duration_ms:.2f}ms)"

        if status_code >= 500:
            logger.error(log_msg)
        elif status_code >= 400:
            logger.warning(log_msg)
        elif path == "/api/health":
            logger.debug(log_msg)
        else:
            logger.info(log_msg)

        return response
