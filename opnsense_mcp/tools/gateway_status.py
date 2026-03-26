"""Gateway/WAN health status tool for OPNsense."""

import logging
from typing import Any

from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)


class GatewayStatusTool:
    """Tool for showing WAN gateway health (latency, packet loss)."""

    name = "gateway_status"
    description = "Show WAN gateway health (latency, packet loss)"
    input_schema = {
        "type": "object",
        "properties": {},
        "required": [],
    }

    def __init__(self, client: OPNsenseClient | None) -> None:
        """
        Initialize the gateway status tool.

        Args:
            client: OPNsense client instance for API communication.

        """
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Get WAN/gateway health status.

        Args:
            params: Not used.

        Returns:
            Dictionary containing gateway list and status.

        """
        if not self.client:
            return {"status": "error", "error": "No client available"}

        try:
            gateways = await self.client.get_gateway_status()
            return {
                "gateways": gateways,
                "count": len(gateways),
                "status": "success",
            }
        except Exception as e:
            logger.exception("Failed to get gateway status")
            return {"status": "error", "error": str(e)}
