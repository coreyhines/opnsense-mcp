"""ARP/NDP table management tool for OPNsense."""

import logging
from typing import Any

from pydantic import BaseModel

from opnsense_mcp.utils.api import OPNsenseClient
from opnsense_mcp.utils.oui_lookup import OUILookup

logger = logging.getLogger(__name__)

oui_lookup = OUILookup()


class ARPEntry(BaseModel):
    """Model for ARP/NDP table entries."""

    mac: str
    ip: str
    intf: str
    manufacturer: str | None = None
    hostname: str | None = None
    expires: int | None = None
    permanent: bool | None = None
    type: str | None = None
    description: str | None = None


class ARPTool:
    """Tool for retrieving ARP/NDP table information."""

    def __init__(self, client: OPNsenseClient | None = None) -> None:
        """
        Initialize the ARP tool.

        Args:
            client: OPNsense client instance for API communication.

        """
        self.client = client

    async def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        """
        Execute the ARP tool with given parameters.

        Args:
            params: Dictionary containing optional filters like mac, ip, or search.

        Returns:
            Dictionary containing ARP table results and error information.

        """
        if not self.client:
            return {"result": None, "error": "No client available"}

        try:
            result = await self.client.get_arp_table(params)
            return {"result": result, "error": None}
        except Exception as e:
            logger.exception("Error executing ARP tool")
            return {"result": None, "error": str(e)}

    def _fill_manufacturer(self, entry):
        if not entry.get("manufacturer"):
            mac = entry.get("mac")
            if mac:
                entry["manufacturer"] = oui_lookup.lookup(mac) or ""
        return entry

    def _get_dummy_data(self) -> dict[str, Any]:
        """Return dummy data for testing."""
        return {
            "arp": [
                {
                    "ip": "192.168.1.1",
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "intf": "em0",
                    "manufacturer": "TestCorp",
                }
            ],
            "ndp": [
                {
                    "ip": "fe80::1",
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "intf": "em0",
                    "manufacturer": "TestCorp",
                }
            ],
            "status": "success",
        }
