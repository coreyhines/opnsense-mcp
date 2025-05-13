#!/usr/bin/env python3
"""
Compatibility module with helpers for dealing with different Python versions
and environments like IDEs where imports might be restricted
"""

import sys
import os
import types


def mock_passlib():
    """Create a mock passlib module and install it in sys.modules"""
    # Create the base passlib module
    if "passlib" not in sys.modules:
        mock_passlib = types.ModuleType("passlib")
        mock_passlib.__path__ = []
        sys.modules["passlib"] = mock_passlib

    # Create the context submodule
    if "passlib.context" not in sys.modules:
        mock_context = types.ModuleType("passlib.context")

        # Get our current directory to find the shim
        current_dir = os.path.dirname(os.path.abspath(__file__))

        # Get the CryptContext implementation from our shim
        shim_path = os.path.join(current_dir, "passlib_shim.py")

        # Load the shim code
        with open(shim_path) as f:
            code = compile(f.read(), shim_path, "exec")
            globals_dict = {}
            exec(code, globals_dict)

        # Add CryptContext to our mock module
        mock_context.CryptContext = globals_dict["CryptContext"]
        sys.modules["passlib.context"] = mock_context


def setup_compat():
    """Configure compatibility options based on environment"""
    # Check if we're running in an IDE-like environment
    in_ide = any(name in os.environ for name in ["VSCODE_PID", "CURSOR_IDE"])

    # If in IDE, make passlib available
    if in_ide:
        # try:
        #     import passlib.context
        # except ImportError:
        #     mock_passlib()
        pass

    return {
        "in_ide": in_ide,
    }
