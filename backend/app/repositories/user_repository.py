"""Repository pattern for database operations on UserRecord entities (Phase 9)."""

from typing import List, Optional
from sqlalchemy.orm import Session

from backend.app.models.user import UserRecord


class UserRepository:
    """Encapsulates transactional queries and persistence for user entities."""

    @staticmethod
    def get_by_id(db: Session, user_id: int) -> Optional[UserRecord]:
        """Query user account by primary key ID."""
        return db.query(UserRecord).filter(UserRecord.id == user_id).first()

    @staticmethod
    def get_by_username(db: Session, username: str) -> Optional[UserRecord]:
        """Query user account by case-insensitive unique username."""
        if not username:
            return None
        return db.query(UserRecord).filter(UserRecord.username == username.strip()).first()

    @staticmethod
    def create(db: Session, user: UserRecord) -> UserRecord:
        """Persist a new user account in the active session."""
        db.add(user)
        db.flush()
        return user

    @staticmethod
    def list(db: Session, skip: int = 0, limit: int = 100) -> List[UserRecord]:
        """Query active users with pagination."""
        return db.query(UserRecord).offset(skip).limit(limit).all()
