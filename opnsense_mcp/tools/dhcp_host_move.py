"""MCP tool to move a DHCP host reservation to a new address."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)


class MoveDhcpHostTool:
    """Move a dnsmasq host reservation to a new IPv4 and/or IPv6 address."""

    name = "move_dhcp_host"
    description = (
        "Move or rename a DHCP host reservation (dnsmasq). "
        "IPv4 is the reliable contract; IPv6 (::N suffix) applies only to "
        "stateful-DHCPv6 clients. Defaults to a dry run; pass apply=true to write. "
        "The client keeps its old address until it renews or reboots."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Hostname or MAC of the reservation to move",
            },
            "ipv4": {
                "type": ["integer", "string"],
                "description": "New IPv4: last octet (e.g. 2) or full address",
            },
            "ipv6": {
                "type": ["integer", "string"],
                "description": "New IPv6 suffix: e.g. 2 -> ::2, or '::abcd'",
            },
            "new_hostname": {
                "type": "string",
                "description": "New dnsmasq host reservation name (optional rename)",
            },
            "apply": {
                "type": "boolean",
                "description": "Apply the change. Omit/false = dry run.",
            },
        },
        "required": ["host"],
        "anyOf": [
            {"required": ["ipv4"]},
            {"required": ["ipv6"]},
            {"required": ["new_hostname"]},
        ],
    }

    def __init__(self, client: OPNsenseClient | None) -> None:
        """Initialize the tool."""
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Validate args and delegate the move to the client."""
        params = params or {}
        if not self.client:
            return {"status": "error", "error": "No client available"}

        identifier = str(params.get("host") or "").strip()
        if not identifier:
            return {"status": "error", "error": "host (hostname or MAC) is required"}

        ipv4 = params.get("ipv4")
        ipv6 = params.get("ipv6")
        new_hostname = params.get("new_hostname")
        if ipv4 is None and ipv6 is None and not str(new_hostname or "").strip():
            return {
                "status": "error",
                "error": "Provide ipv4, ipv6, and/or new_hostname",
            }

        apply = bool(params.get("apply", False))
        try:
            return await self.client.move_dhcp_host(
                identifier=identifier,
                ipv4=ipv4,
                ipv6=ipv6,
                new_hostname=str(new_hostname).strip() if new_hostname else None,
                dry_run=not apply,
            )
        except Exception as exc:
            logger.exception("Failed to move DHCP host")
            return {"status": "error", "error": str(exc)}
