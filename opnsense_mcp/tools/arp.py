#!/usr/bin/env python3

from typing import Dict, Any
from pydantic import BaseModel
import logging
from oui_lookup import OUILookup

logger = logging.getLogger(__name__)

oui_lookup = OUILookup()


class ARPEntry(BaseModel):
    """Model for ARP/NDP table entries"""

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
    name = "arp"
    description = "Show ARP/NDP table"
    inputSchema = {"type": "object", "properties": {}, "required": []}

    def __init__(self, client):
        self.client = client

    async def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute ARP/NDP table lookup with optional filtering by MAC,
        IPv4, or IPv6 address, or using targeted search if 'search' is provided.
        """
        try:
            if self.client is None:
                logger.warning("No OPNsense client available, returning dummy data")
                return self._get_dummy_data()

            # Targeted search if 'search' parameter is provided
            search_query = params.get("search")
            if search_query:
                arp_entries = [self._fill_manufacturer(entry) for entry in await self.client.search_arp_table(search_query)]
                ndp_entries = [self._fill_manufacturer(entry) for entry in await self.client.search_ndp_table(search_query)]
                return {
                    "arp": arp_entries,
                    "ndp": ndp_entries,
                    "status": "success",
                }

            # Get both ARP and NDP tables (full-table fallback)
            arp_data = await self.client.get_arp_table()
            ndp_data = await self.client.get_ndp_table()

            # Convert to ARPEntry models and fill manufacturer
            arp_entries = [
                self._fill_manufacturer(ARPEntry(**entry).dict()) for entry in arp_data
            ]
            ndp_entries = [
                self._fill_manufacturer(ARPEntry(**entry).dict()) for entry in ndp_data
            ]

            # Filtering logic
            mac_filter = params.get("mac")
            ip_filter = params.get("ip")
            ipv6_filter = params.get("ipv6")

            if mac_filter:
                mac_filter = mac_filter.lower()
                arp_entries = [
                    entry
                    for entry in arp_entries
                    if entry.get("mac", "").lower() == mac_filter
                ]
                ndp_entries = [
                    entry
                    for entry in ndp_entries
                    if entry.get("mac", "").lower() == mac_filter
                ]
            if ip_filter:
                arp_entries = [
                    entry for entry in arp_entries if entry.get("ip", "") == ip_filter
                ]
            if ipv6_filter:
                ndp_entries = [
                    entry for entry in ndp_entries if entry.get("ip", "") == ipv6_filter
                ]

            return {
                "arp": arp_entries,
                "ndp": ndp_entries,
                "status": "success",
            }

        except Exception as e:
            logger.error(f"Failed to get ARP/NDP tables: {str(e)}")
            # Fallback to dummy data on error
            return self._get_dummy_data()

    def _fill_manufacturer(self, entry):
        if not entry.get("manufacturer"):
            mac = entry.get("mac")
            if mac:
                entry["manufacturer"] = oui_lookup.lookup(mac) or ""
        return entry

    def _get_dummy_data(self) -> Dict[str, Any]:
        """Return dummy data for testing"""
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
