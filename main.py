#!/usr/bin/env python3
"""
OPNsense MCP Server entry point.

This module provides a simple entry point for running the OPNsense MCP server.
It redirects to the actual MCP server implementation in opnsense_mcp.server.
"""

import argparse
import os

from opnsense_mcp.server import main as mcp_main
from opnsense_mcp.utils.logging import setup_logging


def main() -> None:
    """
    Start the OPNsense MCP Server.

    This function parses command line arguments and starts the MCP server.
    The server communicates over stdio using the Model Context Protocol.
    """
    parser = argparse.ArgumentParser(description="OPNsense MCP Server")
    parser.add_argument("--log-file", type=str, help="Path to log file (optional)")
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level",
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.log_file, args.log_level)

    # Set environment variable for JWT secret key if not set
    if not os.environ.get("MCP_SECRET_KEY"):
        # NOTE: Hardcoded secret key for development only. Change in production!
        # Bandit: # nosec
        os.environ["MCP_SECRET_KEY"] = (
            "development-secret-key"  # pragma: allowlist secret
        )

    # Set up MCP environment
    os.environ["PYTHONUNBUFFERED"] = "1"
    os.environ["PYTHONIOENCODING"] = "utf-8"
    os.environ["MCP_TRANSPORT"] = "stdio"

    # Run the MCP server
    mcp_main()


if __name__ == "__main__":
    main()
