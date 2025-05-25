#!/usr/bin/env python3

import logging
from typing import Any

from pydantic import BaseModel

logger = logging.getLogger(__name__)


class DHCPLease(BaseModel):
    ip: str
    mac: str
    hostname: str | None = None
    start: str | None = None
    end: str | None = None
    online: bool | None = None
    lease_type: str | None = None
    description: str | None = None


class DHCPTool:
    name = "dhcp"
    description = "Show DHCPv4 and DHCPv6 lease tables"
    inputSchema = {"type": "object", "properties": {}, "required": []}

    def __init__(self, client):
        self.client = client

    def _normalize_lease_entry(self, entry):
        # Map 'address' to 'ip' if present
        if "address" in entry and "ip" not in entry:
            entry["ip"] = entry.pop("address")
        return entry

    async def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        """Execute DHCP lease table lookup for both IPv4 and IPv6"""
        try:
            if self.client is None:
                logger.warning(
                    "No OPNsense client available, returning dummy DHCP data"
                )
                return self._get_dummy_data()
            leases_v4 = await self.client.get_dhcpv4_leases()
            leases_v6 = await self.client.get_dhcpv6_leases()
            lease_entries_v4 = [
                DHCPLease(**self._normalize_lease_entry(entry)).model_dump()
                for entry in leases_v4
            ]
            lease_entries_v6 = [
                DHCPLease(**self._normalize_lease_entry(entry)).model_dump()
                for entry in leases_v6
            ]
            # Determine status
            if leases_v4 is None and leases_v6 is None:
                dhcp_status = (
                    "API returned nothing (possible misconfiguration or "
                    "permissions issue)"
                )
            elif not lease_entries_v4 and not lease_entries_v6:
                dhcp_status = (
                    "No DHCP leases found. Check DHCP server status, "
                    "configuration, and API permissions."
                )
            else:
                dhcp_status = "OK"
        except Exception as e:
            logger.exception("Failed to get DHCP lease tables")
            return {
                "dhcpv4": [],
                "dhcpv6": [],
                "status": "error",
                "dhcp_status": f"Error retrieving DHCP leases: {str(e)}",
            }
        else:
            return {
                "dhcpv4": lease_entries_v4,
                "dhcpv6": lease_entries_v6,
                "status": "success",
                "dhcp_status": dhcp_status,
            }

    def _get_dummy_data(self):
        return {
            "dhcpv4": [
                {
                    "ip": "192.168.1.100",
                    "mac": "00:11:22:33:44:55",
                    "hostname": "dummy-client",
                    "start": ("2025-01-01T00:00:00"),
                    "end": ("2025-01-01T12:00:00"),
                    "online": True,
                    "lease_type": "dynamic",
                    "description": ("Dummy lease entry"),
                }
            ],
            "dhcpv6": [
                {
                    "ip": "2001:db8::100",
                    "mac": "00:11:22:33:44:66",
                    "hostname": "dummy6-client",
                    "start": ("2025-01-01T00:00:00"),
                    "end": ("2025-01-01T12:00:00"),
                    "online": True,
                    "lease_type": "dynamic",
                    "description": ("Dummy DHCPv6 lease entry"),
                }
            ],
            "status": "dummy",
        }
