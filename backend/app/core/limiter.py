"""Centralized API rate limiting and abuse protection module (Phase 11).

Implements application-level rate limiting using slowapi with:
- Authenticated user identity tracking (user:<username>)
- Client IP tracking for unauthenticated endpoints (ip:<client_ip>)
- Strict rejection of untrusted/spoofable client IP headers
- Standardized HTTP 429 JSON responses with Retry-After and rate limit headers
- Sanitized security audit logging excluding credentials and tokens
"""

import logging
import time
from typing import Optional
from fastapi import Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded

from backend.app.core.config import settings
from backend.app.core.security import decode_access_token

logger = logging.getLogger("nids.security.ratelimit")


def get_rate_limit_identity(request: Request) -> str:
    """Determine rate limit identity based on authenticated user or socket client IP.

    Strategy:
    1. Authenticated Requests: If an Authorization: Bearer <token> header is present and valid,
       extracts the authenticated operator username ('user:<username>'). This ensures that
       rate limits follow the authenticated identity regardless of network IP changes and prevents
       NAT/shared IP collision between multiple valid operators.
    2. Unauthenticated Requests: If no valid Bearer token is present (e.g. login endpoint),
       identifies the client by peer socket IP ('ip:<client_host>').
    3. Security Anti-Spoofing: Does NOT trust arbitrary or spoofable 'X-Forwarded-For' headers
       to prevent attackers from bypassing login brute-force controls.
    """
    # 1. Check for authenticated Bearer token
    auth_header = request.headers.get("authorization", "")
    if auth_header and auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
        try:
            payload = decode_access_token(token)
            username = payload.get("username") or payload.get("sub")
            if username:
                return f"user:{username}"
        except Exception:
            # Token invalid/expired - fall through to socket IP
            pass

    # 2. Peer socket client IP (unspoofable peer address)
    client_host = request.client.host if request.client and request.client.host else "127.0.0.1"
    return f"ip:{client_host}"


# Global Limiter instance configured with settings toggle
limiter = Limiter(
    key_func=get_rate_limit_identity,
    enabled=settings.RATE_LIMIT_ENABLED,
    headers_enabled=False,  # Headers injected safely via exception handler
)


def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """Production-safe HTTP 429 response handler.

    Returns clean standardized JSON envelope without leaking internal stack traces,
    filesystem paths, or database internals, while providing standard Retry-After
    and rate limit metadata headers.
    """
    headers = {}
    view_limit = getattr(request.state, "view_rate_limit", None)

    if view_limit and hasattr(request.app.state, "limiter"):
        try:
            limiter_inst = request.app.state.limiter
            window_stats = limiter_inst.limiter.get_window_stats(
                view_limit[0], *view_limit[1]
            )
            reset_in = 1 + window_stats[0]
            retry_after = max(1, int(reset_in - time.time()))
            headers["Retry-After"] = str(retry_after)
            headers["X-RateLimit-Limit"] = str(view_limit[0].amount)
            headers["X-RateLimit-Remaining"] = str(window_stats[1])
            headers["X-RateLimit-Reset"] = str(int(reset_in))
        except Exception as header_exc:
            logger.debug("Could not calculate rate limit headers: %s", header_exc)

    # Resolve safe identity for audit logging (never log passwords or tokens)
    try:
        identity = get_rate_limit_identity(request)
    except Exception:
        identity = "unknown"

    logger.warning(
        "Rate limit exceeded: %s %s - Client: %s - Limit: %s - HTTP 429",
        request.method,
        request.url.path,
        identity,
        getattr(exc, "detail", "exceeded"),
    )

    # Record Security Audit Log (Never log tokens, passwords, or request body)
    try:
        from backend.app.schemas.audit import AuditAction, AuditOutcome, AuditResourceType
        from backend.app.services.audit_service import AuditService

        identity_type = "user" if identity.startswith("user:") else ("ip" if identity.startswith("ip:") else "unknown")
        username = identity[5:] if identity.startswith("user:") else None
        client_ip = request.client.host if request.client else None
        limit_rule = str(getattr(exc, "detail", "exceeded"))

        AuditService.log_event(
            action=AuditAction.RATE_LIMIT_EXCEEDED,
            resource_type=AuditResourceType.RATE_LIMIT,
            outcome=AuditOutcome.DENIED,
            username=username,
            ip_address=client_ip,
            request_method=request.method,
            request_path=request.url.path,
            status_code=429,
            details={
                "identity_type": identity_type,
                "rule": limit_rule,
                "message": "Rate limit exceeded",
            },
        )
    except Exception as audit_err:
        logger.debug("Failed to record rate limit audit event: %s", audit_err)

    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded. Please try again later."},
        headers=headers,
    )
