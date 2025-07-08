"""ARP table tool implementation."""

import logging
from typing import Any

from base_tool import BaseTool
from client import OPNsenseClient

logger = logging.getLogger(__name__)


class ArpTool(BaseTool):
    """Tool for retrieving ARP/NDP table information."""

    def __init__(self, client: OPNsenseClient | None = None) -> None:
        """
        Initialize the ARP tool.

        Args:
            client: Optional OPNsense client instance

        """
        super().__init__()
        self.client = client or OPNsenseClient(mock=True)

    async def execute(self, params: dict[str, Any] = None) -> dict[str, Any]:
        """
        Execute the ARP tool.

        Args:
            params: Optional parameters
                - ip: Filter by IP address
                - mac: Filter by MAC address
                - limit: Maximum number of entries to return

        Returns:
            dict: ARP table information

        """
        logger.debug(f"Executing ARP tool with params: {params}")
        try:
            result = await self.client.get_arp_table(params)
            return {"result": result, "error": None}
        except Exception as e:
            logger.exception(f"Error executing ARP tool: {e}")
            return {"result": None, "error": str(e)}
