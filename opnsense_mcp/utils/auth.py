"""Authentication utilities for the OPNsense MCP server."""

import os
from datetime import datetime, timedelta
from typing import Any

from pydantic import BaseModel

from opnsense_mcp.utils.jwt_helper import create_jwt
from opnsense_mcp.utils.passlib_shim import pwd_context

# Default secret key - should be overridden by environment variable
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


class Token(BaseModel):
    """JWT token response model."""

    access_token: str
    token_type: str


class TokenData(BaseModel):
    """Token payload data model."""

    username: str | None = None


class User(BaseModel):
    """User model."""

    username: str
    disabled: bool | None = None


class UserInDB(User):
    """User model with hashed password for database storage."""

    hashed_password: str


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash.

    Args:
        plain_password: Plain text password to verify.
        hashed_password: Hashed password to compare against.

    Returns:
        True if password matches, False otherwise.

    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Generate password hash.

    Args:
        password: Plain text password to hash.

    Returns:
        Hashed password string.

    """
    return pwd_context.hash(password)


def get_user(users_db: dict[str, dict[str, Any]], username: str) -> UserInDB | None:
    """
    Get user from database.

    Args:
        users_db: User database dictionary.
        username: Username to look up.

    Returns:
        UserInDB instance if found, None otherwise.

    """
    if username in users_db:
        user_dict = users_db[username]
        return UserInDB(**user_dict)
    return None


def authenticate_user(
    users_db: dict[str, dict[str, Any]], username: str, password: str
) -> UserInDB | bool:
    """
    Authenticate a user.

    Args:
        users_db: User database dictionary.
        username: Username to authenticate.
        password: Password to verify.

    Returns:
        UserInDB instance if authentication successful, False otherwise.

    """
    user = get_user(users_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(
    data: dict[str, Any], expires_delta: timedelta | None = None
) -> str:
    """
    Create a JWT access token.

    Args:
        data: Data to encode in the token.
        expires_delta: Token expiration time delta.

    Returns:
        Encoded JWT token string.

    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})
    return create_jwt(to_encode, SECRET_KEY, ALGORITHM)


if __name__ == "__main__":
    # Generate a password hash for testing
    print(get_password_hash("password"))
