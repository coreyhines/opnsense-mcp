"""MCP tools for DHCP per-subnet DNS configuration."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)

_SCOPE_PROPERTIES = {
    "subnet": {
        "type": "string",
        "description": "Subnet in CIDR notation (e.g. 10.0.2.0/24)",
        "optional": True,
    },
    "interface": {
        "type": "string",
        "description": "Interface identifier or description (e.g. opt2, VLAN2wired)",
        "optional": True,
    },
}


class ListDhcpSubnetDnsTool:
    """Read DHCP-provided DNS servers for a subnet scope."""

    name = "list_dhcp_subnet_dns"
    description = (
        "List DHCP-provided DNS servers for a subnet scope (dnsmasq or Kea backends)"
    )
    input_schema = {
        "type": "object",
        "properties": _SCOPE_PROPERTIES,
        "anyOf": [{"required": ["subnet"]}, {"required": ["interface"]}],
    }

    def __init__(self, client: OPNsenseClient | None) -> None:
        """Initialize the list tool."""
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """List scoped DHCP DNS servers for IPv4 and IPv6."""
        if params is None:
            params = {}
        if not self.client:
            return {"status": "error", "error": "No client available"}

        subnet = str(params.get("subnet") or "").strip() or None
        interface = str(params.get("interface") or "").strip() or None
        if not subnet and not interface:
            return {
                "status": "error",
                "error": "Provide subnet (CIDR) and/or interface",
            }

        try:
            result = await self.client.list_dhcp_subnet_dns(
                subnet=subnet,
                interface=interface,
            )
            return {"status": "success", **result}
        except Exception as exc:
            logger.exception("Failed to list DHCP subnet DNS")
            return {"status": "error", "error": str(exc)}


class SetDhcpSubnetDnsTool:
    """Update DHCP-provided DNS servers for one address family."""

    name = "set_dhcp_subnet_dns"
    description = (
        "Update DHCP-provided DNS servers for one address family on a subnet scope "
        "(dnsmasq or Kea backends). Single address updates slot 1 unless slot=2."
    )
    input_schema = {
        "type": "object",
        "properties": {
            **_SCOPE_PROPERTIES,
            "family": {
                "type": "string",
                "description": "Address family to update: ipv4 or ipv6",
            },
            "dns_server": {
                "type": "string",
                "description": "Single DNS server address",
                "optional": True,
            },
            "dns_servers": {
                "type": "array",
                "items": {"type": "string"},
                "description": "One or two DNS server addresses",
                "optional": True,
            },
            "slot": {
                "type": "integer",
                "description": "Optional slot index (1 or 2) for single-address updates",
                "optional": True,
            },
        },
        "required": ["family"],
        "anyOf": [{"required": ["subnet"]}, {"required": ["interface"]}],
    }

    def __init__(self, client: OPNsenseClient | None) -> None:
        """Initialize the set tool."""
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Apply a slot-oriented DNS update for one family."""
        if params is None:
            params = {}
        if not self.client:
            return {"status": "error", "error": "No client available"}

        subnet = str(params.get("subnet") or "").strip() or None
        interface = str(params.get("interface") or "").strip() or None
        family = str(params.get("family") or "").strip()
        dns_server = str(params.get("dns_server") or "").strip() or None
        raw_servers = params.get("dns_servers")
        dns_servers: list[str] | None = None
        if isinstance(raw_servers, list):
            dns_servers = [str(item).strip() for item in raw_servers if str(item).strip()]
        slot_raw = params.get("slot")
        slot = int(slot_raw) if slot_raw is not None else None

        if not subnet and not interface:
            return {
                "status": "error",
                "error": "Provide subnet (CIDR) and/or interface",
            }
        if not family:
            return {"status": "error", "error": "family is required (ipv4 or ipv6)"}
        if not dns_server and not dns_servers:
            return {
                "status": "error",
                "error": "Provide dns_server or dns_servers",
            }
        if dns_server and dns_servers:
            return {
                "status": "error",
                "error": "Provide either dns_server or dns_servers, not both",
            }

        try:
            return await self.client.set_dhcp_subnet_dns(
                subnet=subnet,
                interface=interface,
                family=family,
                dns_server=dns_server,
                dns_servers=dns_servers,
                slot=slot,
            )
        except Exception as exc:
            logger.exception("Failed to set DHCP subnet DNS")
            return {"status": "error", "error": str(exc)}
