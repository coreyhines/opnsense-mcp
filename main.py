#!/usr/bin/env python3

import uvicorn
import argparse
import os
from mcp_server import MCPServer
from mcp_server.utils.logging import setup_logging


def main():
    parser = argparse.ArgumentParser(description="OPNsense MCP Server")
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host to bind the server to",
    )
    parser.add_argument(
        "--port", type=int, default=8000, help="Port to bind the server to"
    )
    parser.add_argument(
        "--config",
        type=str,
        default="vars/key.yaml",
        help="Path to configuration file",
    )
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
        # NOTE: Hardcoded secret key for development only. Change in production! Bandit: # nosec
        os.environ["MCP_SECRET_KEY"] = "development-secret-key"  # nosec

    # Initialize the MCP server
    server = MCPServer(args.config)

    # Run the server
    uvicorn.run(server.app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
