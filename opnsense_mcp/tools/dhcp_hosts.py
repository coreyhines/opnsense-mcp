"""MCP tool to list DHCP host reservations (dnsmasq search_host rows)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from opnsense_mcp.utils.dhcp_host import DhcpHostRecord

if TYPE_CHECKING:
    from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)


def _matches_descr(record: DhcpHostRecord, descr: str) -> bool:
    """Return True when the reservation descr contains ``descr`` (case-insensitive)."""
    needle = descr.strip().lower()
    if not needle:
        return True
    haystack = str(record.raw.get("descr") or "").lower()
    return needle in haystack


class ListDhcpHostsTool:
    """List dnsmasq DHCP host reservations (static mappings), not active leases."""

    name = "list_dhcp_hosts"
    description = (
        "List DHCP host reservations from the dnsmasq host table (Services → DHCPv4 → "
        "Hosts). Unlike the dhcp tool (leases), this returns configured static mappings "
        "including IPv4, optional ::N IPv6 suffix, MAC, client_id, and descr."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "search": {
                "type": "string",
                "description": (
                    "Optional filter passed to OPNsense searchPhrase "
                    "(hostname, MAC, IP fragment, etc.)"
                ),
                "optional": True,
            },
            "descr": {
                "type": "string",
                "description": (
                    "Optional client-side filter: reservation descr substring "
                    "(e.g. VLAN2wired)"
                ),
                "optional": True,
            },
            "missing_ipv6": {
                "type": "boolean",
                "description": (
                    "When true, return only reservations with IPv4 but no ::N IPv6 suffix"
                ),
                "optional": True,
            },
        },
        "required": [],
    }

    def __init__(self, client: OPNsenseClient | None) -> None:
        """Initialize the tool."""
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Fetch and optionally filter host reservation rows."""
        params = params or {}
        if not self.client:
            return {"status": "error", "error": "No client available"}

        search = str(params.get("search") or "").strip()
        descr = str(params.get("descr") or "").strip()
        missing_ipv6 = bool(params.get("missing_ipv6", False))

        try:
            rows = await self.client.list_dhcp_hosts(search=search)
        except Exception as exc:
            logger.exception("Failed to list DHCP host reservations")
            return {"status": "error", "error": str(exc)}

        records = [DhcpHostRecord.from_row(row) for row in rows]
        if descr:
            records = [rec for rec in records if _matches_descr(rec, descr)]
        if missing_ipv6:
            records = [rec for rec in records if rec.ipv4 and not rec.ipv6_suffix]

        hosts = [rec.to_summary() for rec in records]
        missing_ipv6_count = sum(
            1 for host in hosts if host.get("ipv4") and not host.get("has_ipv6")
        )
        return {
            "status": "success",
            "count": len(hosts),
            "missing_ipv6_count": missing_ipv6_count,
            "hosts": hosts,
        }
