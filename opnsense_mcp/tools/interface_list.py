"""Interface list management tool for OPNsense."""

import logging
from typing import Any

from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)


class InterfaceListTool:
    """Tool for getting available firewall interface names."""

    def __init__(self, client: OPNsenseClient | None) -> None:
        """
        Initialize the interface list tool.

        Args:
            client: OPNsense client instance for API communication.

        """
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Get available interface names for firewall rules.

        Args:
            params: Optional execution parameters (unused for interface list).

        Returns:
            Dictionary containing interface names and descriptions.

        """
        try:
            if not self.client:
                return {
                    "interfaces": {},
                    "status": "error",
                    "error": "No client available",
                }

            # Get interface list from the API
            response = await self.client.get_firewall_interface_list()

            if response.get("status") == "success":
                interfaces = response.get("interfaces", {})
                return {
                    "interfaces": interfaces,
                    "total": len(interfaces),
                    "status": "success",
                }
            return {
                "interfaces": {},
                "status": "error",
                "error": response.get("error", "Unknown error"),
            }

        except Exception as e:
            logger.exception("Failed to get interface list")
            return {"interfaces": {}, "status": "error", "error": str(e)}
