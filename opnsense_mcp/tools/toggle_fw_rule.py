"""Firewall rule toggle tool for OPNsense."""

import logging
from typing import Any

from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)


class ToggleFwRuleTool:
    """Tool for enabling or disabling an existing firewall rule."""

    name = "toggle_fw_rule"
    description = "Enable or disable a firewall rule"
    input_schema = {
        "type": "object",
        "properties": {
            "rule_uuid": {
                "type": "string",
                "description": "UUID of the rule to toggle (from fw_rules output)",
            },
            "enabled": {
                "type": "boolean",
                "description": "True to enable the rule, False to disable it",
            },
            "apply": {
                "type": "boolean",
                "description": "Apply changes immediately (default: true)",
                "optional": True,
            },
        },
        "required": ["rule_uuid", "enabled"],
    }

    def __init__(self, client: OPNsenseClient | None) -> None:
        """
        Initialize the firewall rule toggle tool.

        Args:
            client: OPNsense client instance for API communication.

        """
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Enable or disable a firewall rule by UUID.

        Args:
            params: Dict with rule_uuid, enabled, and optional apply.

        Returns:
            Dictionary containing the rule UUID, new enabled state, and status.

        """
        if params is None:
            params = {}

        if not self.client:
            return {"status": "error", "error": "No client available"}

        rule_uuid = params.get("rule_uuid", "").strip()
        if not rule_uuid:
            return {"status": "error", "error": "rule_uuid is required"}

        if "enabled" not in params:
            return {"status": "error", "error": "enabled is required"}

        enabled = bool(params["enabled"])
        apply_changes = params.get("apply", True)

        try:
            await self.client.toggle_firewall_rule(rule_uuid, enabled)

            applied = False
            if apply_changes:
                await self.client.apply_firewall_changes()
                applied = True

            return {
                "uuid": rule_uuid,
                "enabled": enabled,
                "applied": applied,
                "status": "success",
            }
        except Exception as e:
            logger.exception("Failed to toggle firewall rule")
            return {"status": "error", "error": str(e)}
