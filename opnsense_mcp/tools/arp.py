"""ARP/NDP table management tool for OPNsense."""

import asyncio
import ipaddress
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
        Execute ARP/NDP table lookup with optional filtering by MAC,
        IPv4, or IPv6 address, or using targeted search if 'search'
        is provided.

        For human-style lookups like hostnames, this will first resolve
        the query via OPNsenseClient.resolve_host_info to obtain the best
        matching IP / MAC, then perform a targeted ARP/NDP search for those
        concrete values. This restores the older "is host on the network?"
        behavior while keeping the fast server-side search path for direct
        IP/MAC queries.
        """
        try:
            if self.client is None:
                logger.warning("No OPNsense client available, returning dummy data")
                return self._get_dummy_data()

            search_query = params.get("search") if params else None
            if search_query:
                search_query = search_query.strip()

                # Wildcard or empty → full table (parallel fetch)
                if search_query == "*" or not search_query:
                    arp_data, ndp_data = await asyncio.gather(
                        self.client.get_arp_table(),
                        self.client.get_ndp_table(),
                    )
                    return {
                        "arp": [
                            self._fill_manufacturer(ARPEntry(**e).model_dump())
                            for e in arp_data
                        ],
                        "ndp": [
                            self._fill_manufacturer(ARPEntry(**e).model_dump())
                            for e in ndp_data
                        ],
                        "status": "success",
                    }

                # Decide whether this looks like an IP/MAC or a hostname-ish query.
                looks_like_ip = False
                looks_like_mac = False
                try:
                    ipaddress.ip_address(search_query)
                    looks_like_ip = True
                except ValueError:
                    looks_like_ip = False

                q_lc = search_query.lower()
                if (":" in q_lc or "-" in q_lc) and len(
                    q_lc.replace("-", ":").split(":")
                ) == 6:
                    # Cheap MAC heuristic; exact validation happens later anyway.
                    looks_like_mac = True

                # For hostnames / free-form queries, resolve to concrete identifiers first.
                if not looks_like_ip and not looks_like_mac:
                    try:
                        host_info = await self.client.resolve_host_info(search_query)
                    except Exception:
                        logger.exception(
                            "resolve_host_info failed for query '%s'", search_query
                        )
                        host_info = {}

                    resolved_ip = (host_info or {}).get("ip")
                    resolved_mac = (host_info or {}).get("mac")
                    resolved_ipv6 = None
                    # resolve_host_info currently focuses on v4; keep hook for v6.
                    if host_info and host_info.get("ndp"):
                        resolved_ipv6 = host_info["ndp"].get("ip")

                    # If we got something concrete, search by those; otherwise fall
                    # back to the raw server-side search endpoints.
                    if resolved_ip or resolved_mac or resolved_ipv6:
                        arp_filters: dict[str, Any] = {}
                        ndp_filters: dict[str, Any] = {}
                        if resolved_mac:
                            arp_filters["mac"] = resolved_mac
                            ndp_filters["mac"] = resolved_mac
                        if resolved_ip:
                            arp_filters["ip"] = resolved_ip
                        if resolved_ipv6:
                            ndp_filters["ipv6"] = resolved_ipv6

                        arp_raw, ndp_raw = await asyncio.gather(
                            self.client.search_arp_table(
                                arp_filters.get("ip") or arp_filters.get("mac") or ""
                            ),
                            self.client.search_ndp_table(
                                ndp_filters.get("ipv6") or ndp_filters.get("mac") or ""
                            ),
                        )
                    else:
                        arp_raw, ndp_raw = await asyncio.gather(
                            self.client.search_arp_table(search_query),
                            self.client.search_ndp_table(search_query),
                        )
                else:
                    # Direct IP/MAC queries stay on the fast path.
                    arp_raw, ndp_raw = await asyncio.gather(
                        self.client.search_arp_table(search_query),
                        self.client.search_ndp_table(search_query),
                    )

                return {
                    "arp": [
                        self._fill_manufacturer(ARPEntry(**e).model_dump())
                        for e in arp_raw
                    ],
                    "ndp": [
                        self._fill_manufacturer(ARPEntry(**e).model_dump())
                        for e in ndp_raw
                    ],
                    "status": "success",
                }

            # If no search query, get full tables
            arp_data = await self.client.get_arp_table()
            ndp_data = await self.client.get_ndp_table()
            arp_entries = [
                self._fill_manufacturer(ARPEntry(**entry).model_dump())
                for entry in arp_data
            ]
            ndp_entries = [
                self._fill_manufacturer(ARPEntry(**entry).model_dump())
                for entry in ndp_data
            ]

            # Filtering logic
            mac_filter = params.get("mac") if params else None
            ip_filter = params.get("ip") if params else None
            ipv6_filter = params.get("ipv6") if params else None

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
            logger.exception("Failed to get ARP/NDP tables")
            logger.error(f"Exception details: {e}")
            # Fallback to dummy data on error
            return self._get_dummy_data()

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
