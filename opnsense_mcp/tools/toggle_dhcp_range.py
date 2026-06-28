"""MCP tool to enable/disable a dnsmasq DHCP range."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)


class ToggleDhcpRangeTool:
    """Toggle a dnsmasq DHCP pool range (disable before moving DHCP to another server)."""

    name = "toggle_dhcp_range"
    description = (
        "Enable or disable a dnsmasq DHCP range on OPNsense. "
        "Identify the range by interface (e.g. opt10), subnet CIDR (e.g. 10.0.5.0/24), "
        "or range uuid. Defaults to dry run; pass apply=true to write and reconfigure dnsmasq."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "enabled": {
                "type": "boolean",
                "description": "True to enable the range, False to disable DHCP on it",
            },
            "interface": {
                "type": "string",
                "description": "Interface name (e.g. opt10) or description",
            },
            "subnet": {
                "type": "string",
                "description": "Subnet in CIDR notation (e.g. 10.0.5.0/24)",
            },
            "uuid": {
                "type": "string",
                "description": "Range uuid from dnsmasq settings",
            },
            "apply": {
                "type": "boolean",
                "description": "Apply changes (default false = dry run)",
                "default": False,
            },
        },
        "required": ["enabled"],
    }

    def __init__(self, client: OPNsenseClient | None) -> None:
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if params is None:
            params = {}
        if not self.client:
            return {"status": "error", "error": "No client available"}

        if "enabled" not in params:
            return {"status": "error", "error": "enabled is required"}

        enabled_raw = params["enabled"]
        if isinstance(enabled_raw, bool):
            enabled = enabled_raw
        elif isinstance(enabled_raw, str):
            enabled = enabled_raw.strip().lower() in ("true", "1", "yes", "on")
        else:
            enabled = bool(enabled_raw)

        subnet = str(params.get("subnet") or "").strip() or None
        interface = str(params.get("interface") or "").strip() or None
        uuid = str(params.get("uuid") or "").strip() or None
        if not any([subnet, interface, uuid]):
            return {
                "status": "error",
                "error": "Provide interface, subnet, or uuid",
            }

        apply = bool(params.get("apply", False))
        try:
            return await self.client.toggle_dhcp_range(
                enabled=enabled,
                subnet=subnet,
                interface=interface,
                uuid=uuid,
                dry_run=not apply,
            )
        except ValueError as exc:
            return {"status": "error", "error": str(exc)}
        except Exception as exc:
            logger.exception("Failed to toggle DHCP range")
            return {"status": "error", "error": str(exc)}
