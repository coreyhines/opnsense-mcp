"""MCP tool to create a DHCP host reservation."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)


class MkDhcpHostTool:
    """Create a dnsmasq DHCP host reservation (static mapping)."""

    name = "mk_dhcp_host"
    description = (
        "Create a DHCP host reservation in the dnsmasq host table "
        "(Services → DHCPv4 → Hosts). Requires hostname and MAC; at least one "
        "of ipv4 or ipv6 suffix must be provided. "
        "Optional client_id (DUID) improves stateful DHCPv6 matching when MAC "
        "alone is insufficient — copy from the dhcp tool v6 lease client_id. "
        "Defaults to a dry run; pass apply=true to write and reconfigure dnsmasq."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "hostname": {
                "type": "string",
                "description": "Hostname for the reservation (e.g. 'mydevice')",
            },
            "mac": {
                "type": "string",
                "description": "MAC address (e.g. 'aa:bb:cc:dd:ee:ff')",
            },
            "ipv4": {
                "type": "string",
                "description": "IPv4 address to assign (e.g. '10.0.8.50')",
            },
            "ipv6": {
                "type": ["integer", "string"],
                "description": "IPv6 suffix: integer (e.g. 50 → ::50) or '::abcd'",
            },
            "client_id": {
                "type": "string",
                "description": (
                    "Optional DHCP client identifier / DUID for IPv6 (e.g. "
                    "'00:03:00:01:52:54:00:ab:cd:01'). Accepts optional 'id:' prefix."
                ),
            },
            "descr": {
                "type": "string",
                "description": "Optional description",
            },
            "domain": {
                "type": "string",
                "description": "Optional domain for the host (e.g. 'lan')",
            },
            "apply": {
                "type": "boolean",
                "description": "Apply the change. Omit/false = dry run.",
            },
        },
        "required": ["hostname", "mac"],
        "anyOf": [
            {"required": ["ipv4"]},
            {"required": ["ipv6"]},
        ],
    }

    def __init__(self, client: OPNsenseClient | None) -> None:
        """Initialize the tool."""
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Validate args and delegate creation to the client."""
        params = params or {}
        if not self.client:
            return {"status": "error", "error": "No client available"}

        hostname = str(params.get("hostname") or "").strip()
        if not hostname:
            return {"status": "error", "error": "hostname is required"}

        mac = str(params.get("mac") or "").strip()
        if not mac:
            return {"status": "error", "error": "mac is required"}

        ipv4 = params.get("ipv4")
        ipv6 = params.get("ipv6")
        if ipv4 is None and ipv6 is None:
            return {"status": "error", "error": "Provide ipv4 and/or ipv6"}

        client_id = params.get("client_id")
        descr = str(params.get("descr") or "").strip()
        domain = str(params.get("domain") or "").strip()
        apply = bool(params.get("apply", False))

        try:
            return await self.client.add_dhcp_host(
                hostname=hostname,
                mac=mac,
                ipv4=str(ipv4).strip() if ipv4 is not None else None,
                ipv6=ipv6,
                client_id=str(client_id).strip() if client_id is not None else None,
                descr=descr,
                domain=domain,
                dry_run=not apply,
            )
        except Exception as exc:
            logger.exception("Failed to create DHCP host")
            return {"status": "error", "error": str(exc)}
