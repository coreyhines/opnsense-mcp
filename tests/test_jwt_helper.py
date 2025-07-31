#!/usr/bin/env python3
"""Test script for JWT helper implementation."""

import pytest

from opnsense_mcp.utils.jwt_helper import JWTError, create_jwt, decode_jwt

# Test constants
SECRET_KEY = "test-secret-key"  # pragma: allowlist secret
TEST_USERNAME = "test-user"


def test_jwt_creation_and_verification():
    """Test JWT token creation and verification."""
    # Create a test token
    token_payload = {"sub": TEST_USERNAME}
    token = create_jwt(token_payload, SECRET_KEY, algorithm="HS256", expire_minutes=30)

    # Decode and verify the token
    payload = decode_jwt(token, SECRET_KEY, algorithms=["HS256"])

    # Verify payload contents
    assert payload.get("sub") == TEST_USERNAME
    assert "exp" in payload
    assert "iat" in payload


def test_jwt_expiration():
    """Test JWT token expiration handling."""
    token_payload = {"sub": TEST_USERNAME}
    # Create a token with a past expiration time
    import time

    token_payload["exp"] = int(time.time()) - 60  # Expired 1 minute ago

    expired_token = create_jwt(
        token_payload, SECRET_KEY, algorithm="HS256", expire_minutes=0
    )

    # Should raise an error for expired token
    with pytest.raises(JWTError, match="Token expired"):
        decode_jwt(expired_token, SECRET_KEY, algorithms=["HS256"])


def test_jwt_invalid_signature():
    """Test JWT token with invalid signature."""
    # Create a valid token first
    token_payload = {"sub": TEST_USERNAME}
    token = create_jwt(token_payload, SECRET_KEY, algorithm="HS256", expire_minutes=30)

    # Create invalid token by modifying signature
    parts = token.rsplit(".", 1)
    invalid_token = parts[0] + ".invalidSignature"

    # Should raise an error for invalid signature
    with pytest.raises(JWTError, match="Invalid signature"):
        decode_jwt(invalid_token, SECRET_KEY, algorithms=["HS256"])
