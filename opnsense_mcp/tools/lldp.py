"""LLDP (Link Layer Discovery Protocol) neighbor table management tool."""

import logging
from typing import Any

from pydantic import BaseModel

from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)


class LLDPEntry(BaseModel):
    """Model for LLDP neighbor table entries."""

    intf: str
    chassis_id: str
    port_id: str
    port_descr: str | None = None
    sys_name: str | None = None
    sys_descr: str | None = None
    sys_cap: str | None = None
    mgmt_ip: str | None = None


class LLDPTool:
    """Tool for retrieving LLDP neighbor table information."""

    name = "lldp"
    description = "Show LLDP neighbor table"
    input_schema = {"type": "object", "properties": {}, "required": []}

    def __init__(self, client: OPNsenseClient | None) -> None:
        """
        Initialize the LLDP tool.

        Args:
            client: OPNsense client instance for API communication.

        """
        self.client = client

    async def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        """
        Execute LLDP neighbor table lookup.

        Args:
            params: Execution parameters (unused for LLDP).

        Returns:
            Dictionary containing LLDP neighbor results.

        """
        try:
            if not self.client:
                return {
                    "neighbors": [],
                    "status": "error",
                    "error": "No client available",
                }

            neighbors = await self.client.get_lldp_table()
            return {"neighbors": neighbors, "status": "success"}
        except Exception as e:
            logger.exception("Failed to get LLDP neighbors")
            return {"neighbors": [], "status": "error", "error": str(e)}
