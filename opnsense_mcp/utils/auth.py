#!/usr/bin/env python3

import os
from datetime import datetime, timedelta

from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from pydantic import BaseModel

from opnsense_mcp.utils.jwt_helper import create_jwt

# Security configurations
SECRET_KEY = os.environ.get("MCP_SECRET_KEY", "your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Simplified password context using just bcrypt
pwd_context = CryptContext(schemes=["bcrypt"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    disabled: bool | None = None


class UserInDB(User):
    hashed_password: str


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(users_db, username: str):
    if username in users_db:
        user_dict = users_db[username]
        return UserInDB(**user_dict)
    return None


def authenticate_user(users_db, username: str, password: str):
    user = get_user(users_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)

    # Convert datetime to integer timestamp for our custom JWT implementation
    expire_minutes = int((expire - datetime.utcnow()).total_seconds() / 60)

    # Use our custom create_jwt function
    return create_jwt(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM,
        expire_minutes=expire_minutes,
    )


if __name__ == "__main__":
    # Generate a password hash for testing
    print(get_password_hash("password"))
