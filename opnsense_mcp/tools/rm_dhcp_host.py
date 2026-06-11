"""MCP tool to delete a DHCP host reservation."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)


class RmDhcpHostTool:
    """Delete a dnsmasq DHCP host reservation."""

    name = "rm_dhcp_host"
    description = (
        "Delete a DHCP host reservation from the dnsmasq host table "
        "(Services → DHCPv4 → Hosts). Accepts hostname, MAC, or reservation uuid. "
        "Defaults to a dry run; pass apply=true to delete and reconfigure dnsmasq."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Hostname, MAC, or reservation uuid to delete",
            },
            "apply": {
                "type": "boolean",
                "description": "Apply the deletion. Omit/false = dry run.",
            },
        },
        "required": ["host"],
    }

    def __init__(self, client: OPNsenseClient | None) -> None:
        """Initialize the tool."""
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Validate args and delegate deletion to the client."""
        params = params or {}
        if not self.client:
            return {"status": "error", "error": "No client available"}

        identifier = str(params.get("host") or "").strip()
        if not identifier:
            return {"status": "error", "error": "host (hostname, MAC, or uuid) is required"}

        apply = bool(params.get("apply", False))
        try:
            return await self.client.delete_dhcp_host(
                identifier=identifier,
                dry_run=not apply,
            )
        except Exception as exc:
            logger.exception("Failed to delete DHCP host")
            return {"status": "error", "error": str(exc)}
