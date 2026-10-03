"""Pydantic schemas for authentication and RBAC user access control (Phase 9)."""

from datetime import datetime
from enum import Enum
from pydantic import BaseModel, ConfigDict, Field


class UserRole(str, Enum):
    """Allowed user roles for Role-Based Access Control."""
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"


class LoginRequest(BaseModel):
    """Payload for user authentication."""
    username: str = Field(..., min_length=1, max_length=50, description="Operator account username")
    password: str = Field(..., min_length=1, max_length=128, description="Operator account password")


class UserResponse(BaseModel):
    """Safe public user profile without sensitive password hashes or internal secrets."""
    model_config = ConfigDict(from_attributes=True)

    id: int = Field(..., description="Unique operator account identifier")
    username: str = Field(..., description="Operator username")
    role: str = Field(..., description="Assigned RBAC role: ADMIN | ANALYST | VIEWER")
    is_active: bool = Field(..., description="Account active status")
    created_at: datetime = Field(..., description="Account creation timestamp")


class TokenResponse(BaseModel):
    """Standardized JWT authentication token response."""
    access_token: str = Field(..., description="JWT Bearer access token")
    token_type: str = Field("bearer", description="Token scheme type")
    user: UserResponse = Field(..., description="Authenticated user account details")


class TokenData(BaseModel):
    """Internal decoded claims from validated JWT access token."""
    sub: str = Field(..., description="Subject identity (user ID)")
    username: str = Field(..., description="Username")
    role: str = Field(..., description="Role assigned in token claims")
    type: str = Field("access", description="Token type claim")
