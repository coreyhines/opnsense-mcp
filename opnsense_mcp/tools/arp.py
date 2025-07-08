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

    def __init__(self: "ARPTool", client: OPNsenseClient | None = None) -> None:
        """
        Initialize the ARP tool.

        Args:
        ----
            client: OPNsense client instance for API communication.

        """
        self.client = client

    async def execute(self: "ARPTool", params: dict[str, Any]) -> dict[str, Any]:
        """
        Execute the ARP tool with given parameters.

        Args:
        ----
            params: Dictionary containing optional filters like mac, ip, or search.

        Returns:
        -------
            Dictionary containing ARP and NDP table results and error information.

        """
        if not self.client:
            return {
                "arp": [],
                "ndp": [],
                "status": "error",
                "error": "No client available",
            }

        try:
            # Accepts 'search', 'ip', 'mac', or defaults to '*'
            query = params.get("search") or params.get("ip") or params.get("mac") or "*"
            arp_entries = await self.client.search_arp_table(query)
            ndp_entries = await self.client.search_ndp_table(query)
            arp_entries = [self._fill_manufacturer(entry) for entry in arp_entries]
            ndp_entries = [self._fill_manufacturer(entry) for entry in ndp_entries]
        except Exception as e:
            logger.exception("Error executing ARP tool")
            return {"arp": [], "ndp": [], "status": "error", "error": str(e)}
        else:
            return {"arp": arp_entries, "ndp": ndp_entries, "status": "success"}

    def _fill_manufacturer(self: "ARPTool", entry: dict[str, Any]) -> dict[str, Any]:
        """Fill manufacturer info for ARP/NDP entry if missing."""
        if not entry.get("manufacturer"):
            mac = entry.get("mac")
            if mac:
                entry["manufacturer"] = oui_lookup.lookup(mac)
        return entry

    def _get_dummy_data(self: "ARPTool") -> dict[str, Any]:
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
