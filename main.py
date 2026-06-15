#!/usr/bin/env python3
"""
OPNsense MCP Server entry point.

This module provides a simple entry point for running the OPNsense MCP server.
It redirects to the actual MCP server implementation in opnsense_mcp.server.
"""

import argparse
import os

from opnsense_mcp.utils.logging import setup_logging


def main() -> None:
    """
    Start the OPNsense MCP Server.

    Supports stdio (default) and streamable-http transports.
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
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        choices=["stdio", "streamable-http", "http", "sse"],
        help="MCP transport protocol (default: stdio)",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Host to bind for HTTP transport (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Port to bind for HTTP transport (default: 8765)",
    )

    args = parser.parse_args()

    setup_logging(args.log_file, args.log_level)

    if not os.environ.get("MCP_SECRET_KEY"):
        os.environ["MCP_SECRET_KEY"] = (
            "development-secret-key"  # pragma: allowlist secret
        )

    os.environ["PYTHONUNBUFFERED"] = "1"
    os.environ["PYTHONIOENCODING"] = "utf-8"

    if args.transport == "stdio":
        os.environ["MCP_TRANSPORT"] = "stdio"
        from opnsense_mcp.server import main as mcp_main

        mcp_main()
    else:
        from opnsense_mcp.fastmcp_server import build_mcp_server

        mcp = build_mcp_server()
        mcp.run(
            transport=args.transport,
            host=args.host,
            port=args.port,
            show_banner=False,
        )


if __name__ == "__main__":
    main()
