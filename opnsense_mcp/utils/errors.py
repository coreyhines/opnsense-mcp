import logging
from typing import Any

from fastapi import Request, status
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


class MCPException(Exception):
    def __init__(
        self,
        status_code: int,
        message: str,
        details: str | dict[str, Any] = None,
    ):
        self.status_code = status_code
        self.message = message
        self.details = details
        super().__init__(message)


async def mcp_exception_handler(request: Request, exc: MCPException):
    logger.error(f"MCP Error: {exc.message}", exc_info=exc)
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.message,
            "details": exc.details,
            "path": request.url.path,
        },
    )


async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unexpected error: {str(exc)}", exc_info=exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal server error",
            "details": str(exc),
            "path": request.url.path,
        },
    )
