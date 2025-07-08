"""DHCP lease management tool for OPNsense."""

import logging
from typing import Any

from pydantic import BaseModel

from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)


class DHCPLease(BaseModel):
    """Model for DHCP lease entries."""

    ip: str
    mac: str
    hostname: str | None = None
    starts: str | None = None
    ends: str | None = None
    state: str | None = None


class DHCPTool:
    """Tool for retrieving DHCP lease information from OPNsense."""

    name = "dhcp"
    description = "Show DHCPv4 and DHCPv6 lease tables"
    input_schema = {"type": "object", "properties": {}, "required": []}

    def __init__(self, client: OPNsenseClient | None) -> None:
        """
        Initialize the DHCP tool.

        Args:
            client: OPNsense client instance for API communication.

        """
        self.client = client

    def _normalize_lease_entry(self, entry: dict[str, Any]) -> dict[str, Any]:
        """
        Normalize lease entry to standard format.

        Args:
            entry: Raw lease entry from API.

        Returns:
            Normalized lease entry.

        """
        # Map 'address' to 'ip' if present
        if "address" in entry and "ip" not in entry:
            entry["ip"] = entry["address"]
        return entry

    async def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        """
        Execute DHCP lease table lookup for both IPv4 and IPv6.

        Args:
            params: Execution parameters (unused for DHCP).

        Returns:
            Dictionary containing DHCP lease results.

        """
        try:
            if not self.client:
                return {
                    "dhcpv4": [],
                    "dhcpv6": [],
                    "status": "error",
                    "error": "No client available",
                }

            # Get DHCPv4 leases
            dhcpv4_leases = await self.client.get_dhcpv4_leases()

            # Get DHCPv6 leases
            dhcpv6_leases = await self.client.get_dhcpv6_leases()

            # Normalize entries
            normalized_v4 = [
                self._normalize_lease_entry(lease) for lease in dhcpv4_leases
            ]
            normalized_v6 = [
                self._normalize_lease_entry(lease) for lease in dhcpv6_leases
            ]

            # Combine results
            return {
                "dhcpv4": normalized_v4,
                "dhcpv6": normalized_v6,
                "status": "success",
                "total_leases": len(normalized_v4) + len(normalized_v6),
            }

        except Exception as e:
            logger.exception("Failed to get DHCP leases")
            return {
                "dhcpv4": [],
                "dhcpv6": [],
                "status": "error",
                "error": str(e),
            }

    def _get_dummy_data(self) -> dict[str, Any]:
        """
        Get dummy DHCP data for testing.

        Returns:
            Dictionary with dummy DHCP lease data.

        """
        return {
            "dhcpv4": [
                {
                    "ip": "10.0.2.15",
                    "mac": "08:00:27:12:34:56",
                    "hostname": "test-device",
                    "starts": "2023-01-01 12:00:00",
                    "ends": "2023-01-02 12:00:00",
                    "state": "active",
                }
            ],
            "dhcpv6": [],
            "status": "success",
            "total_leases": 1,
        }
