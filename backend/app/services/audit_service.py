"""Centralized security audit logging service (Phase 12).

Provides reliable, non-blocking persistence for security-relevant operational actions:
- Authentication (LOGIN_SUCCESS, LOGIN_FAILURE, LOGOUT)
- Authorization (ACCESS_DENIED)
- Prediction & Alert Lifecycle (PREDICTION_CREATED, ALERT_ACKNOWLEDGED, ALERT_RESOLVED)
- WebSocket Handshake (WEBSOCKET_AUTH_SUCCESS, WEBSOCKET_AUTH_FAILURE)
- Rate Limiting (RATE_LIMIT_EXCEEDED)

Strict Security Guarantee:
Never stores passwords, password hashes, JWTs, Authorization headers, or raw sensitive payloads.
Failure in audit persistence is safely caught and logged without disrupting primary operations.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional, Tuple, Union
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app.db.session import SessionLocal
from backend.app.models.audit import AuditLogRecord
from backend.app.schemas.audit import AuditAction, AuditOutcome, AuditResourceType

logger = logging.getLogger("nids.audit.service")

FORBIDDEN_KEYS = {
    "password",
    "password_hash",
    "hashed_password",
    "token",
    "access_token",
    "authorization",
    "secret",
    "secret_key",
    "cookie",
    "jwt",
    "credentials",
}


def sanitize_audit_details(details: Optional[Union[Dict[str, Any], str, Any]]) -> Optional[str]:
    """Recursively scrub sensitive keys and serialize details to safe JSON string."""
    if details is None:
        return None

    if isinstance(details, str):
        # Prevent storing strings containing literal sensitive markers
        lower_str = details.lower()
        if any(banned in lower_str for banned in ("bearer ", "password", "token")):
            return json.dumps({"note": "Sanitized unformatted detail"})
        return details

    def scrub(obj: Any) -> Any:
        if isinstance(obj, dict):
            cleaned = {}
            for k, v in obj.items():
                if str(k).lower() in FORBIDDEN_KEYS:
                    cleaned[k] = "[REDACTED]"
                else:
                    cleaned[k] = scrub(v)
            return cleaned
        elif isinstance(obj, list):
            return [scrub(item) for item in obj]
        elif isinstance(obj, (int, float, bool)) or obj is None:
            return obj
        return str(obj)

    try:
        scrubbed = scrub(details)
        return json.dumps(scrubbed)
    except Exception as exc:
        logger.debug("Failed to JSON-serialize audit details: %s", exc)
        return json.dumps({"note": "Detail serialization error"})


class AuditService:
    """Centralized management service for security audit trail operations."""

    session_factory = SessionLocal

    @classmethod
    def log_event(
        cls,
        db: Optional[Session] = None,
        action: Union[AuditAction, str] = AuditAction.SECURITY_ERROR,
        resource_type: Union[AuditResourceType, str] = AuditResourceType.SYSTEM,
        outcome: Union[AuditOutcome, str] = AuditOutcome.SUCCESS,
        username: Optional[str] = None,
        user_role: Optional[str] = None,
        resource_id: Optional[Union[str, int]] = None,
        ip_address: Optional[str] = None,
        request_method: Optional[str] = None,
        request_path: Optional[str] = None,
        status_code: Optional[int] = None,
        details: Optional[Union[Dict[str, Any], str]] = None,
    ) -> Optional[AuditLogRecord]:
        """Record an audit trail event.

        Uses the provided session if available, otherwise creates an independent short-lived
        session so that transaction rollbacks in business logic do not drop security audit logs.
        Guaranteed not to raise exceptions to callers.
        """
        action_val = action.value if isinstance(action, AuditAction) else str(action)
        resource_type_val = resource_type.value if isinstance(resource_type, AuditResourceType) else str(resource_type)
        outcome_val = outcome.value if isinstance(outcome, AuditOutcome) else str(outcome)
        sanitized_details = sanitize_audit_details(details)

        record = AuditLogRecord(
            action=action_val,
            resource_type=resource_type_val,
            outcome=outcome_val,
            username=username,
            user_role=user_role,
            resource_id=str(resource_id) if resource_id is not None else None,
            ip_address=ip_address,
            request_method=request_method,
            request_path=request_path,
            status_code=status_code,
            details=sanitized_details,
            created_at=datetime.now(timezone.utc),
        )

        # Autonomous session if db is not provided
        if db is None:
            session = cls.session_factory()
            try:
                session.add(record)
                session.commit()
                session.refresh(record)
                return record
            except Exception as exc:
                session.rollback()
                logger.error("Failed to commit autonomous audit log record: %s", exc)
                return None
            finally:
                session.close()
        else:
            try:
                db.add(record)
                db.commit()
                db.refresh(record)
                return record
            except Exception as exc:
                db.rollback()
                logger.error("Failed to commit audit log record on session: %s", exc)
                # Attempt fallback autonomous commit
                try:
                    fallback_session = cls.session_factory()
                    fallback_session.add(record)
                    fallback_session.commit()
                    fallback_session.refresh(record)
                    fallback_session.close()
                    return record
                except Exception as fb_exc:
                    logger.error("Fallback audit commit also failed: %s", fb_exc)
                    return None

    @staticmethod
    def query_audit_logs(
        db: Session,
        limit: int = 20,
        offset: int = 0,
        username: Optional[str] = None,
        action: Optional[str] = None,
        outcome: Optional[str] = None,
        resource_type: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Tuple[List[AuditLogRecord], int]:
        """Query historical audit logs with filtering and newest-first ordering."""
        query = db.query(AuditLogRecord)

        if username:
            query = query.filter(AuditLogRecord.username.ilike(f"%{username.strip()}%"))
        if action:
            query = query.filter(AuditLogRecord.action == action.strip().upper())
        if outcome:
            query = query.filter(AuditLogRecord.outcome == outcome.strip().upper())
        if resource_type:
            query = query.filter(AuditLogRecord.resource_type == resource_type.strip().upper())
        if start_time:
            query = query.filter(AuditLogRecord.timestamp >= start_time)
        if end_time:
            query = query.filter(AuditLogRecord.timestamp <= end_time)

        total_count = query.count()
        records = (
            query.order_by(AuditLogRecord.timestamp.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return records, total_count

    @staticmethod
    def get_security_summary(db: Session) -> Dict[str, int]:
        """Compute high-level security event counts for SOC monitoring overview."""
        try:
            total_events = db.query(func.count(AuditLogRecord.id)).scalar() or 0
            failed_logins = (
                db.query(func.count(AuditLogRecord.id))
                .filter(AuditLogRecord.action == AuditAction.LOGIN_FAILURE.value)
                .scalar()
                or 0
            )
            access_denied = (
                db.query(func.count(AuditLogRecord.id))
                .filter(AuditLogRecord.action == AuditAction.ACCESS_DENIED.value)
                .scalar()
                or 0
            )
            rate_limit_exceeded = (
                db.query(func.count(AuditLogRecord.id))
                .filter(AuditLogRecord.action == AuditAction.RATE_LIMIT_EXCEEDED.value)
                .scalar()
                or 0
            )

            return {
                "total_events": int(total_events),
                "failed_logins": int(failed_logins),
                "access_denied": int(access_denied),
                "rate_limit_exceeded": int(rate_limit_exceeded),
            }
        except Exception as exc:
            logger.error("Error computing security summary: %s", exc)
            return {
                "total_events": 0,
                "failed_logins": 0,
                "access_denied": 0,
                "rate_limit_exceeded": 0,
            }
