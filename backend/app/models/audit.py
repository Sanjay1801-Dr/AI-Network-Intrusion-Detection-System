"""SQLAlchemy ORM model for security audit logs and operator activity tracking (Phase 12)."""

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    String,
    Text,
)
from backend.app.db.session import Base


def utc_now() -> datetime:
    """Return timezone-aware current UTC time."""
    return datetime.now(timezone.utc)


class AuditLogRecord(Base):
    """Structured security audit trail recording sensitive operational actions.

    Answers:
    - Who performed the action? (username, user_role, ip_address)
    - What action was performed? (action, request_method, request_path)
    - When did it happen? (timestamp)
    - Which resource was affected? (resource_type, resource_id)
    - What was the outcome? (outcome: SUCCESS | FAILURE | DENIED, status_code)
    - What safe contextual metadata exists? (details)

    Explicit Privacy Guarantee:
    Never stores passwords, password hashes, JWTs, Authorization headers,
    raw credentials, or secret keys.
    """

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)
    username = Column(String(50), nullable=True, index=True)
    user_role = Column(String(20), nullable=True)
    action = Column(String(50), nullable=False, index=True)
    resource_type = Column(String(50), nullable=False, index=True)
    resource_id = Column(String(50), nullable=True)
    outcome = Column(String(20), nullable=False, index=True)  # SUCCESS | FAILURE | DENIED
    ip_address = Column(String(45), nullable=True)
    request_method = Column(String(10), nullable=True)
    request_path = Column(String(255), nullable=True)
    status_code = Column(Integer, nullable=True)
    details = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
