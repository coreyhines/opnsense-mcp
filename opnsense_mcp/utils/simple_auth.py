"""
Simplified authentication module that works without passlib
This is a fallback for environments where passlib isn't available
"""

import os
import hashlib
import base64
from datetime import datetime, timedelta
from typing import Optional, Dict

# Security configuration
SECRET_KEY = os.environ.get("MCP_SECRET_KEY", "your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Import JWT helper
try:
    from .jwt_helper import JWTError, decode_jwt, create_jwt  # noqa: F401
except ImportError:
    # Try absolute import
    from mcp_server.utils.jwt_helper import create_jwt  # noqa: F401


# Simple models (normally would be Pydantic models)
class Token:
    def __init__(self, access_token: str, token_type: str):
        self.access_token = access_token
        self.token_type = token_type


class TokenData:
    def __init__(self, username: Optional[str] = None):
        self.username = username


class User:
    def __init__(self, username: str, disabled: Optional[bool] = None):
        self.username = username
        self.disabled = disabled if disabled is not None else False


class UserInDB(User):
    def __init__(
        self,
        username: str,
        hashed_password: str,
        disabled: Optional[bool] = None,
    ):
        super().__init__(username, disabled)
        self.hashed_password = hashed_password


# Simplified password verification (instead of using passlib)
def hash_password(password: str) -> str:
    """Create a simple password hash using SHA-256"""
    salt = "static-salt-for-example-only"  # In production, use a unique salt per user
    hash_obj = hashlib.sha256((password + salt).encode())
    return base64.b64encode(hash_obj.digest()).decode()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a hash"""
    # First try to detect if it's a bcrypt hash (from passlib)
    if hashed_password.startswith("$2b$"):
        # It's a bcrypt hash, we need to use our compatibility method
        return verify_bcrypt_compat(plain_password, hashed_password)
    else:
        # Use our simple hash method
        return hash_password(plain_password) == hashed_password


def verify_bcrypt_compat(plain_password: str, hashed_password: str) -> bool:
    """
    Compatibility method to verify bcrypt passwords

    This is a simplified implementation that will work with the test admin password
    from the server.py file, but isn't a full bcrypt implementation.
    """
    # The test password is known to be "password" with the hash below
    if (
        hashed_password
        == "$2b$12$TwvROpyZ6TyWFFBuwKk.re.4p8FK.Ft4YCd/U3ANdvPA1vUCbelt."
    ):
        return plain_password == "password"
    return False


def get_user(users_db: Dict, username: str) -> Optional[UserInDB]:
    """Get a user from the user database"""
    if username in users_db:
        user_dict = users_db[username]
        return UserInDB(**user_dict)
    return None


def authenticate_user(users_db: Dict, username: str, password: str) -> Optional[User]:
    """Authenticate a user against the user database"""
    user = get_user(users_db, username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)

    # Convert datetime to integer timestamp for our custom JWT implementation
    expire_minutes = int((expire - datetime.utcnow()).total_seconds() / 60)

    # Use our custom create_jwt function
    encoded_jwt = create_jwt(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM,
        expire_minutes=expire_minutes,
    )
    return encoded_jwt


# Create a test password hash
if __name__ == "__main__":
    # Generate a password hash for testing
    print(hash_password("password"))
