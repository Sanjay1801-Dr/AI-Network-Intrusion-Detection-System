"""Centralized error handling and standardized exception definitions."""

from datetime import datetime, timezone
from typing import Any, Optional
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException


class AppException(Exception):
    """Base application exception for domain-level errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "INTERNAL_SERVER_ERROR",
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        self.details = details


class ResourceNotFoundException(AppException):
    """Raised when an entity is not found in the persistence layer."""

    def __init__(self, resource_name: str, identifier: Any) -> None:
        super().__init__(
            message=f"{resource_name} with identifier '{identifier}' was not found.",
            error_code="RESOURCE_NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class ConflictException(AppException):
    """Raised when an entity state transition conflicts with business rules (HTTP 409)."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(
            message=message,
            error_code="STATE_CONFLICT",
            status_code=status.HTTP_409_CONFLICT,
            details=details,
        )


class UnauthorizedException(AppException):
    """Raised when authentication credentials are missing, invalid, or expired (HTTP 401)."""

    def __init__(self, message: str = "Invalid authentication credentials.", details: Optional[Any] = None) -> None:
        super().__init__(
            message=message,
            error_code="UNAUTHORIZED",
            status_code=status.HTTP_401_UNAUTHORIZED,
            details=details,
        )


class ForbiddenException(AppException):
    """Raised when an authenticated user lacks required role/permissions for an action (HTTP 403)."""

    def __init__(self, message: str = "Insufficient permissions to perform this operation.", details: Optional[Any] = None) -> None:
        super().__init__(
            message=message,
            error_code="FORBIDDEN",
            status_code=status.HTTP_403_FORBIDDEN,
            details=details,
        )


class ValidationException(AppException):
    """Raised when data validation fails before ingestion."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(
            message=message,
            error_code="INVALID_PAYLOAD",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            details=details,
        )


class ModelInferenceException(AppException):
    """Raised when ML inference engine fails to compute prediction."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(
            message=message,
            error_code="ML_INFERENCE_ERROR",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            details=details,
        )


def create_error_response(
    status_code: int,
    error_code: str,
    message: str,
    details: Optional[Any] = None,
) -> JSONResponse:
    """Helper to return uniform JSON error responses across the entire API."""
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "error",
            "error_code": error_code,
            "message": message,
            "details": details,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


def sanitize_error_detail(obj: Any) -> Any:
    """Recursively clean error structures to ensure standard JSON compliance (no NaN/inf, no raw Exception instances)."""
    import math
    if isinstance(obj, list):
        return [sanitize_error_detail(item) for item in obj]
    elif isinstance(obj, dict):
        return {str(k): sanitize_error_detail(v) for k, v in obj.items()}
    elif isinstance(obj, float):
        if math.isnan(obj):
            return "NaN"
        if math.isinf(obj):
            return "Infinity" if obj > 0 else "-Infinity"
        return obj
    elif isinstance(obj, Exception):
        return str(obj)
    return obj


def register_exception_handlers(app: FastAPI) -> None:
    """Register custom exception handlers on the FastAPI application."""

    @app.exception_handler(AppException)
    async def app_exception_handler(_: Request, exc: AppException) -> JSONResponse:
        return create_error_response(
            status_code=exc.status_code,
            error_code=exc.error_code,
            message=exc.message,
            details=sanitize_error_detail(exc.details),
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        return create_error_response(
            status_code=exc.status_code,
            error_code=f"HTTP_{exc.status_code}",
            message=str(exc.detail),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
        from fastapi.encoders import jsonable_encoder
        clean_errors = sanitize_error_detail(jsonable_encoder(exc.errors()))
        return create_error_response(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            error_code="UNPROCESSABLE_ENTITY",
            message="Request parameter validation failed.",
            details=clean_errors,
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(_: Request, exc: Exception) -> JSONResponse:
        import logging
        logging.getLogger("nids.api.errors").error("Unhandled exception: %s", exc, exc_info=True)
        return create_error_response(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error_code="UNHANDLED_EXCEPTION",
            message="An unexpected internal error occurred while processing the request.",
        )
