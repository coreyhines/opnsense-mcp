"""Firewall rule deletion tool for OPNsense.

Deleting a filter rule takes a confirmation token, as fourteen of the other
deletes already do. This was the least protected of the four that did not: one
call, one argument, and `apply` defaulting to true, so a single call removed a
rule and reloaded the filter. A removed rule can change what traffic is
permitted, and the caller may not know what the rule contained.
"""

import logging
from typing import Any

from opnsense_mcp.utils.api import OPNsenseClient
from opnsense_mcp.utils.shaper_write_helpers import (
    issue_delete_confirm_token,
    validate_delete_confirm_token,
)

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
            "confirm": {
                "type": "string",
                "description": "Token returned by the previous call, to confirm.",
                "optional": True,
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

        Two calls: the first returns `status: "confirmation_required"` with a
        single-use `confirm_token`, deleting nothing; the second repeats the
        call carrying that token. The token is keyed on the rule uuid and
        expires, so it cannot be transplanted to another rule or replayed.

        Args:
            params: rule_uuid, an optional apply flag, and confirm on the
                second call.

        Returns:
            Dictionary containing rule deletion results.

        """
        if params is None:
            params = {}

        if not self.client:
            return {"status": "error", "error": "No client available"}

        confirm = str(params.get("confirm") or "")
        rule_uuid = params.get("rule_uuid")
        if not rule_uuid:
            return {
                "status": "error",
                "error": "rule_uuid is required for rule deletion",
            }

        # Checked before anything is sent, so an unconfirmed call cannot
        # delete and cannot reload the filter.
        if not validate_delete_confirm_token("fw_rule", str(rule_uuid), confirm):
            token = issue_delete_confirm_token("fw_rule", str(rule_uuid))
            return {
                "status": "confirmation_required",
                "rule_uuid": rule_uuid,
                "confirm_token": token["token"],
                "message": token["message"],
            }

        try:
            # delete_firewall_rule raises on API failure; success is {"result": "success"}
            await self.client.delete_firewall_rule(rule_uuid)

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
                    "Rule deleted but not applied. Call "
                    "fw_rule action='apply' to activate."
                ),
            }

        except Exception as e:
            logger.exception("Failed to delete firewall rule")
            return {"status": "error", "error": str(e)}
