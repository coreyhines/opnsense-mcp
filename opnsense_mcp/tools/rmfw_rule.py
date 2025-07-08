"""Firewall rule deletion tool for OPNsense."""

import logging
from typing import Any

from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)


class RmfwRuleTool:
    """Tool for deleting firewall rules in OPNsense."""

    name = "rmfw_rule"
    description = "Delete firewall rules"
    input_schema = {
        "type": "object",
        "properties": {
            "rule_uuid": {
                "type": "string",
                "description": "UUID of the rule to delete",
            },
            "apply": {
                "type": "boolean",
                "description": "Whether to apply changes immediately",
                "default": True,
            },
        },
        "required": ["rule_uuid"],
    }

    def __init__(self, client: OPNsenseClient | None) -> None:
        """
        Initialize the firewall rule deletion tool.

        Args:
            client: OPNsense client instance for API communication.

        """
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Delete a firewall rule and optionally apply changes.

        Args:
            params: Rule deletion parameters including rule_uuid and apply flag.

        Returns:
            Dictionary containing rule deletion results.

        """
        if params is None:
            params = {}

        if not self.client:
            return {"status": "error", "error": "No client available"}

        rule_uuid = params.get("rule_uuid")
        if not rule_uuid:
            return {
                "status": "error",
                "error": "rule_uuid is required for rule deletion",
            }

        try:
            # Delete the rule
            result = await self.client.delete_firewall_rule(rule_uuid)

            if not result.get("success", False):
                return {
                    "status": "error",
                    "error": f"Failed to delete rule: {result.get('error', 'Unknown error')}",
                }

            # Apply changes if requested (default: true)
            apply_changes = params.get("apply", True)
            if apply_changes:
                await self.client.apply_firewall_changes()
                return {
                    "rule_uuid": rule_uuid,
                    "deleted": True,
                    "applied": True,
                    "status": "success",
                }

            return {
                "rule_uuid": rule_uuid,
                "deleted": True,
                "applied": False,
                "status": "success",
                "note": (
                    "Rule deleted but not applied. Use "
                    "apply_firewall_changes() to activate."
                ),
            }

        except Exception as e:
            logger.exception("Failed to delete firewall rule")
            return {"status": "error", "error": str(e)}
