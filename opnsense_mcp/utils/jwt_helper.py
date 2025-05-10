"""
Custom JWT module to replace jose dependency
"""

import base64
import json
import time
import hmac
import hashlib


def b64encode(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).replace(b"=", b"").decode("utf-8")


def b64decode(data):
    data += "=" * (4 - len(data) % 4) if len(data) % 4 != 0 else ""
    return base64.urlsafe_b64decode(data)


def create_jwt(payload, secret_key, algorithm="HS256", expire_minutes=30):
    """Create a JWT token"""
    # Create header
    header = {"alg": algorithm, "typ": "JWT"}

    # Prepare payload with expiration
    expiration = int(time.time()) + expire_minutes * 60
    payload["exp"] = expiration

    # Encode header and payload
    encoded_header = b64encode(json.dumps(header))
    encoded_payload = b64encode(json.dumps(payload))

    # Create signature
    message = f"{encoded_header}.{encoded_payload}"

    if algorithm == "HS256":
        if isinstance(secret_key, str):
            secret_key = secret_key.encode("utf-8")
        signature = hmac.new(
            secret_key, message.encode("utf-8"), hashlib.sha256
        ).digest()
        encoded_signature = b64encode(signature)
    else:
        raise ValueError(f"Algorithm {algorithm} not supported")

    # Return complete JWT
    return f"{encoded_header}.{encoded_payload}.{encoded_signature}"


def decode_jwt(token, secret_key, algorithms=None):
    """Decode and verify a JWT token"""
    if algorithms is None:
        algorithms = ["HS256"]

    # Split token
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid token format")

    encoded_header, encoded_payload, encoded_signature = parts

    # Verify signature
    message = f"{encoded_header}.{encoded_payload}"

    if isinstance(secret_key, str):
        secret_key = secret_key.encode("utf-8")

    # Check the algorithms
    header = json.loads(b64decode(encoded_header))
    if header["alg"] not in algorithms:
        raise ValueError(f"Algorithm {header['alg']} not allowed")

    if header["alg"] == "HS256":
        expected_sig = hmac.new(
            secret_key, message.encode("utf-8"), hashlib.sha256
        ).digest()
        signature = b64decode(encoded_signature)

        if not hmac.compare_digest(signature, expected_sig):
            raise ValueError("Signature verification failed")
    else:
        raise ValueError(f"Algorithm {header['alg']} not supported")

    # Parse and return payload
    payload = json.loads(b64decode(encoded_payload))

    # Check expiration
    if "exp" in payload:
        if payload["exp"] < time.time():
            raise ValueError("Token has expired")

    return payload


# Define JWT error for compatibility
class JWTError(Exception):
    """Error raised when JWT verification fails"""

    pass
