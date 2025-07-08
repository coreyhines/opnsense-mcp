"""JWT helper functions for token creation and validation."""

import base64
import hashlib
import hmac
import json
import time
from typing import Any


def b64encode(data: str | bytes) -> str:
    """Encode data to base64 URL-safe string."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def b64decode(data: str) -> bytes:
    """Decode base64 URL-safe string to bytes."""
    data += "=" * (4 - len(data) % 4) if len(data) % 4 != 0 else ""
    return base64.urlsafe_b64decode(data)


def create_jwt(
    payload: dict[str, Any],
    secret_key: str,
    algorithm: str = "HS256",
    expire_minutes: int = 30,
) -> str:
    """Create a JWT token."""
    # Create header
    header = {"alg": algorithm, "typ": "JWT"}

    # Add expiration to payload
    if expire_minutes > 0:
        payload["exp"] = int(time.time()) + (expire_minutes * 60)
    payload["iat"] = int(time.time())

    # Encode header and payload
    header_b64 = b64encode(json.dumps(header))
    payload_b64 = b64encode(json.dumps(payload))

    # Create signature
    message = f"{header_b64}.{payload_b64}"
    if algorithm == "HS256":
        signature = hmac.new(
            secret_key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256
        ).digest()
    else:
        msg = f"Algorithm {algorithm} not supported"
        raise ValueError(msg)

    signature_b64 = b64encode(signature)

    # Return complete token
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def decode_jwt(
    token: str,
    secret_key: str,
    algorithms: list[str] | None = None,
) -> dict[str, Any]:
    """Decode and verify a JWT token."""
    if algorithms is None:
        algorithms = ["HS256"]

    try:
        # Split token
        parts = token.split(".")
        if len(parts) != 3:
            raise JWTError("Invalid token format")

        header_b64, payload_b64, signature_b64 = parts

        # Decode header
        header = json.loads(b64decode(header_b64).decode("utf-8"))
        algorithm = header.get("alg")

        if algorithm not in algorithms:
            raise JWTError(f"Algorithm {algorithm} not allowed")

        # Verify signature
        message = f"{header_b64}.{payload_b64}"
        if algorithm == "HS256":
            expected_signature = hmac.new(
                secret_key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256
            ).digest()
        else:
            raise JWTError(f"Algorithm {algorithm} not supported")

        actual_signature = b64decode(signature_b64)
        if not hmac.compare_digest(expected_signature, actual_signature):
            raise JWTError("Invalid signature")

        # Decode payload
        payload = json.loads(b64decode(payload_b64).decode("utf-8"))

        # Check expiration
        if "exp" in payload and payload["exp"] < time.time():
            raise JWTError("Token expired")

        return payload

    except Exception as e:
        if isinstance(e, JWTError):
            raise
        raise JWTError(f"Token validation failed: {str(e)}") from e


# Define JWT error for compatibility
class JWTError(Exception):
    """Error raised when JWT verification fails."""
