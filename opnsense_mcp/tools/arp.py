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


def _looks_like_address(query: str) -> bool:
    """Is this query already a whole address or MAC, rather than a name?

    A whole address needs no resolving, so a miss on it means the neighbour is
    genuinely absent. A partial one -- a prefix, a subnet, half a MAC -- is a
    substring the tables can still match, and must not be handed to a resolver
    that would collapse the answer to one host.
    """
    try:
        ipaddress.ip_address(query)
    except ValueError:
        pass
    else:
        return True
    # Six hex pairs separated by ':' or '-'. Exact validation happens in the
    # table search; this only decides whether a resolver could add anything.
    parts = query.lower().replace("-", ":").split(":")
    return len(parts) == 6 and all(
        1 <= len(part) <= 2 and all(c in "0123456789abcdef" for c in part)
        for part in parts
    )


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

    name = "arp"
    description = "Show ARP/NDP table"
    input_schema = {
        "properties": {
            "ip": {
                "description": "Filter by IP address",
                "optional": True,
                "type": "string",
            },
            "mac": {
                "description": "Filter by MAC address",
                "optional": True,
                "type": "string",
            },
            "search": {
                "description": "Targeted search by IP/MAC/hostname",
                "optional": True,
                "type": "string",
            },
        },
        "required": [],
        "type": "object",
    }

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

        A 'search' query is put to both tables, which filter on the firewall
        and answer with every match. Only a query neither table matches, and
        that is not itself an address or MAC, is resolved through
        OPNsenseClient.resolve_host_info first: that is the "is this host on
        the network?" case, where a name has to become an address before a
        neighbour table can be asked about it. Resolving first was the defect
        in #40, because the resolver answers with one host.
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

                # Search the tables directly. Both search methods filter on
                # the firewall and return every match.
                arp_raw, ndp_raw = await asyncio.gather(
                    self.client.search_arp_table(search_query),
                    self.client.search_ndp_table(search_query),
                )

                # Only a query the tables cannot answer goes to
                # resolve_host_info, and only when it is not already an
                # address or a MAC: that is the "is this hostname on the
                # network" case, where a name has to become an address before
                # a neighbour table can be asked about it.
                #
                # It must not run while the tables have matches of their own.
                # It answers with a single host -- ndp_entries[0] -- and the
                # result was then searched for, so a prefix matching nine
                # neighbours came back as the first one and the other eight
                # were reported as not existing (#40).
                if (
                    not arp_raw
                    and not ndp_raw
                    and not _looks_like_address(search_query)
                ):
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

                    if resolved_ip or resolved_mac or resolved_ipv6:
                        arp_raw, ndp_raw = await asyncio.gather(
                            self.client.search_arp_table(
                                resolved_ip or resolved_mac or ""
                            ),
                            self.client.search_ndp_table(
                                resolved_ipv6 or resolved_mac or ""
                            ),
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
