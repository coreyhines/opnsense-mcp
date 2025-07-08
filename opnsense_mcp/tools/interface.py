"""Interface management tool for OPNsense."""

import logging
from typing import Any

from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)


class InterfaceTool:
    """Tool for retrieving interface information from OPNsense."""

    def __init__(self, client: OPNsenseClient | None) -> None:
        """
        Initialize the interface tool.

        Args:
            client: OPNsense client instance for API communication.

        """
        self.client = client

    async def get_interface_status(self) -> dict[str, Any]:
        """
        Get status information for all interfaces.

        Returns:
            Dictionary containing interface status information.

        """
        try:
            if not self.client:
                return {"status": "error", "error": "No client available"}

                # Get interface status from the API
            response = await self.client.get_interfaces()

        except Exception as e:
            logger.exception("Failed to get interface status")
            return {"status": "error", "error": str(e)}
        else:
            return {"interfaces": response, "status": "success"}

    async def get_interface_statistics(self) -> dict[str, Any]:
        """
        Get network statistics for all interfaces.

        Returns:
            Dictionary containing interface statistics.

        """
        try:
            if not self.client:
                return {"status": "error", "error": "No client available"}

                # This would need to be implemented based on OPNsense API
            # For now, return a placeholder

        except Exception as e:
            logger.exception("Failed to get interface statistics")
            return {"status": "error", "error": str(e)}
        else:
            return {"statistics": {}, "status": "success"}

    async def get_interface_configuration(self) -> dict[str, Any]:
        """
        Get configuration details for all interfaces.

        Returns:
            Dictionary containing interface configuration.

        """
        try:
            if not self.client:
                return {"status": "error", "error": "No client available"}

            # This would need to be implemented based on OPNsense API
            # For now, return a placeholder
            return {"configuration": {}, "status": "success"}

        except Exception as e:
            logger.exception("Failed to get interface configuration")
            return {"status": "error", "error": str(e)}

    async def get_interface_overview(self) -> dict[str, Any]:
        """
        Get overview information for all interfaces.

        Returns:
            Dictionary containing interface overview.

        """
        try:
            if not self.client:
                return {"status": "error", "error": "No client available"}

            # This would need to be implemented based on OPNsense API
            # For now, return a placeholder
            return {"overview": {}, "status": "success"}

        except Exception as e:
            logger.exception("Failed to get interface overview")
            return {"status": "error", "error": str(e)}

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Execute interface information retrieval.

        Args:
            params: Optional execution parameters (unused for interface tool).

        Returns:
            Dictionary containing interface information.

        """
        try:
            if not self.client:
                return {"status": "error", "error": "No client available"}

            # Get comprehensive interface information
            status_info = await self.get_interface_status()
            statistics_info = await self.get_interface_statistics()
            configuration_info = await self.get_interface_configuration()
            overview_info = await self.get_interface_overview()

            return {
                "status": status_info,
                "statistics": statistics_info,
                "configuration": configuration_info,
                "overview": overview_info,
                "status": "success",
            }

        except Exception as e:
            logger.exception("Failed to execute interface tool")
            return {"status": "error", "error": str(e)}
