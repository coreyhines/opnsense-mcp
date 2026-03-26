"""Firewall rule edit tool for OPNsense."""

import logging
from typing import Any

from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)

# Fields that can be edited on an existing rule
_EDITABLE_FIELDS = {
    "description",
    "interface",
    "direction",
    "ipprotocol",
    "protocol",
    "action",
    "enabled",
    "gateway",
}


class SetFwRuleTool:
    """Tool for editing fields of an existing firewall rule."""

    name = "set_fw_rule"
    description = "Edit fields of an existing firewall rule"
    input_schema = {
        "type": "object",
        "properties": {
            "rule_uuid": {
                "type": "string",
                "description": "UUID of the rule to edit (from fw_rules output)",
            },
            "description": {
                "type": "string",
                "description": "New rule description",
                "optional": True,
            },
            "interface": {
                "type": "string",
                "description": "Network interface (e.g. 'lan', 'wan', 'opt1')",
                "optional": True,
            },
            "direction": {
                "type": "string",
                "description": "'in' or 'out'",
                "optional": True,
            },
            "ipprotocol": {
                "type": "string",
                "description": "'inet' (IPv4) or 'inet6' (IPv6)",
                "optional": True,
            },
            "protocol": {
                "type": "string",
                "description": "Protocol: 'any', 'tcp', 'udp', 'icmp', etc.",
                "optional": True,
            },
            "source_net": {
                "type": "string",
                "description": "Source network/IP (e.g. 'any', '192.168.1.0/24')",
                "optional": True,
            },
            "source_port": {
                "type": "string",
                "description": "Source port or 'any'",
                "optional": True,
            },
            "destination_net": {
                "type": "string",
                "description": "Destination network/IP (e.g. 'any', '10.0.0.1')",
                "optional": True,
            },
            "destination_port": {
                "type": "string",
                "description": "Destination port or 'any'",
                "optional": True,
            },
            "action": {
                "type": "string",
                "description": "'pass', 'block', or 'reject'",
                "optional": True,
            },
            "enabled": {
                "type": "boolean",
                "description": "Enable or disable the rule",
                "optional": True,
            },
            "gateway": {
                "type": "string",
                "description": "Gateway for policy routing (optional)",
                "optional": True,
            },
            "apply": {
                "type": "boolean",
                "description": "Apply changes immediately (default: true)",
                "optional": True,
            },
        },
        "required": ["rule_uuid"],
    }

    def __init__(self, client: OPNsenseClient | None) -> None:
        """
        Initialize the firewall rule edit tool.

        Args:
            client: OPNsense client instance for API communication.

        """
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Edit fields of an existing firewall rule.

        Args:
            params: Dict with rule_uuid and any fields to update.

        Returns:
            Dictionary containing the rule UUID and status.

        """
        if params is None:
            params = {}

        if not self.client:
            return {"status": "error", "error": "No client available"}

        rule_uuid = params.get("rule_uuid", "").strip()
        if not rule_uuid:
            return {"status": "error", "error": "rule_uuid is required"}

        # Build the update payload from provided editable fields
        rule_data: dict[str, Any] = {}
        for field in _EDITABLE_FIELDS:
            if field in params:
                rule_data[field] = params[field]

        # Handle source/destination as nested dicts
        if "source_net" in params or "source_port" in params:
            rule_data["source"] = {
                "net": params.get("source_net", "any"),
                "port": params.get("source_port", "any"),
            }
        if "destination_net" in params or "destination_port" in params:
            rule_data["destination"] = {
                "net": params.get("destination_net", "any"),
                "port": params.get("destination_port", "any"),
            }

        if not rule_data:
            return {"status": "error", "error": "No fields to update were provided"}

        apply_changes = params.get("apply", True)

        try:
            await self.client.update_firewall_rule(rule_uuid, rule_data)

            applied = False
            if apply_changes:
                await self.client.apply_firewall_changes()
                applied = True

            return {
                "uuid": rule_uuid,
                "updated_fields": list(rule_data.keys()),
                "applied": applied,
                "status": "success",
            }
        except Exception as e:
            logger.exception("Failed to edit firewall rule")
            return {"status": "error", "error": str(e)}
