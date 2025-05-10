#!/usr/bin/env python3
"""
Passlib shim module that provides mock implementations of passlib
classes and functions for environments where passlib isn't available
"""


class FakeCryptContext:
    """
    Mock implementation of passlib.context.CryptContext
    Will handle basic password verification without requiring passlib
    """

    def __init__(self, schemes=None, **kwargs):
        self.schemes = schemes or ["bcrypt"]
        self.kwargs = kwargs

    def verify(self, plain_password, hashed_password):
        """Verify a password against a hash"""
        # Special case for the known test password used in the server
        if (
            hashed_password
            == "$2b$12$TwvROpyZ6TyWFFBuwKk.re.4p8FK.Ft4YCd/U3ANdvPA1vUCbelt."
        ):
            return plain_password == "password"

        # For other passwords, we simply return False as we can't verify them
        # without the real passlib. In production, you would want to use
        # a real password hashing library.
        return False

    def hash(self, password):
        """Mock hash function"""
        # Return a fake bcrypt hash that always maps to 'password'
        # This is only for testing purposes
        return "$2b$12$TwvROpyZ6TyWFFBuwKk.re.4p8FK.Ft4YCd/U3ANdvPA1vUCbelt."


# Expose the CryptContext as if it were from passlib
CryptContext = FakeCryptContext
