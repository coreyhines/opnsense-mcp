"""Error handling utilities for the OPNsense MCP server."""

import logging
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


class MCPError(Exception):
    """Base exception class for MCP-related errors."""

    def __init__(
        self,
        status_code: int,
        message: str,
        error_code: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """
        Initialize MCP error.

        Args:
            status_code: HTTP status code.
            message: Error message.
            error_code: Optional error code.
            details: Optional error details.

        """
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.error_code = error_code
        self.details = details or {}


async def mcp_exception_handler(request: Request, exc: MCPError) -> JSONResponse:
    """
    Handle MCP exceptions and return appropriate JSON response.

    Args:
        request: FastAPI request object.
        exc: MCP exception instance.

    Returns:
        JSON response with error details.

    """
    logger.error(f"MCP Error: {exc.message}", exc_info=exc)
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": exc.error_code or "internal_error",
                "message": exc.message,
                "details": exc.details,
            }
        },
    )


async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Handle general exceptions and return appropriate JSON response.

    Args:
        request: FastAPI request object.
        exc: Exception instance.

    Returns:
        JSON response with error details.

    """
    logger.error(f"Unexpected error: {str(exc)}", exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "internal_error",
                "message": "An unexpected error occurred",
                "details": {},
            }
        },
    )
