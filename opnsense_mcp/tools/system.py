"""System status monitoring tool for OPNsense."""

import logging
from typing import Any

from pydantic import BaseModel

from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)


class SystemStatus(BaseModel):
    """Model for system status information."""

    hostname: str | None = None
    version: str | None = None
    uptime: str | None = None
    load_average: list[float] | None = None
    cpu_usage: float | None = None
    memory_usage: float | None = None
    disk_usage: dict[str, Any] | None = None
    temperature: dict[str, Any] | None = None


class SystemTool:
    """Tool for retrieving system status information from OPNsense."""

    def __init__(self, client: OPNsenseClient | None) -> None:
        """
        Initialize the system tool.

        Args:
            client: OPNsense client instance for API communication.

        """
        self.client = client

    async def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        """
        Execute system status check.

        Args:
            params: Execution parameters (unused for system status).

        Returns:
            Dictionary containing system status information.

        """
        try:
            if not self.client:
                return {"status": "error", "error": "No client available", "system": {}}

            # Get basic system information
            system_info = await self.client.get_system_status()

            # Try to get additional health data if available
            health_data = {}
            try:
                # Use public method if available, otherwise basic info
                if hasattr(self.client, "get_system_health"):
                    health_data = await self.client.get_system_health()
                else:
                    # Fallback to basic system info
                    health_data = system_info.get("data", {})
            except Exception as health_error:
                logger.warning(f"Could not retrieve health data: {health_error}")
                health_data = {}

            # Combine system info and health data
            combined_status = {**system_info, **health_data}

            return {"status": "success", "system": combined_status}

        except Exception as e:
            logger.exception("Failed to get system status")
            return {"status": "error", "error": str(e), "system": {}}
