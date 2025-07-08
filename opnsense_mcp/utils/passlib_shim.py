"""Passlib compatibility shim for password hashing functionality."""

from passlib.context import CryptContext

# Create password context for hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
