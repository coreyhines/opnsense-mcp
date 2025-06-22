#!/usr/bin/env python3
"""Test script for JWT helper implementation."""

import sys
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    # Try to import our custom JWT implementation
    from opnsense_mcp.utils.jwt_helper import JWTError, create_jwt, decode_jwt

    # Test constants
    SECRET_KEY = "test-secret-key"  # pragma: allowlist secret
    TEST_USERNAME = "test-user"

    # Create a test token
    print("Creating test JWT token...")
    token_payload = {"sub": TEST_USERNAME}
    token = create_jwt(token_payload, SECRET_KEY, algorithm="HS256", expire_minutes=30)
    print(f"Token created: {token}")

    # Decode and verify the token
    print("\nDecoding and verifying token...")
    try:
        payload = decode_jwt(token, SECRET_KEY, algorithms=["HS256"])
        print("Token verified successfully!")
        print(f"Payload: {payload}")

        if payload.get("sub") == TEST_USERNAME:
            print("Username matches expected value ✓")
        else:
            print("Username does not match expected value ✗")

        if "exp" in payload:
            print("Expiration timestamp included ✓")
        else:
            print("Expiration timestamp missing ✗")
    except JWTError as e:
        print(f"Token verification failed: {e}")

    # Test token expiration
    print("\nTesting token expiration...")
    expired_token = create_jwt(
        token_payload, SECRET_KEY, algorithm="HS256", expire_minutes=-1
    )
    try:
        payload = decode_jwt(expired_token, SECRET_KEY, algorithms=["HS256"])
        print("Error: Expired token was accepted ✗")
    except ValueError as e:
        if "expired" in str(e).lower():
            print("Expired token correctly rejected ✓")
        else:
            print(f"Unexpected error: {e}")

    # Test invalid signature
    print("\nTesting invalid signature...")
    parts = token.rsplit(".", 1)
    invalid_token = parts[0] + ".invalidSignature"
    try:
        payload = decode_jwt(invalid_token, SECRET_KEY, algorithms=["HS256"])
        print("Error: Invalid signature was accepted ✗")
    except ValueError as e:
        if "signature" in str(e).lower():
            print("Invalid signature correctly rejected ✓")
        else:
            print(f"Unexpected error: {e}")

    print("\nAll JWT tests completed!")

except ImportError as e:
    print(f"Failed to import JWT helper: {e}")
    sys.exit(1)
