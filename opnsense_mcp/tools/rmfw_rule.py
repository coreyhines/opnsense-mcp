#!/usr/bin/env python3

import logging
from typing import Any

logger = logging.getLogger(__name__)


class RmfwRuleTool:
    name = "rmfw_rule"
    description = "Delete firewall rules"
    inputSchema = {
        "type": "object",
        "properties": {
            "rule_uuid": {
                "type": "string",
                "description": "UUID of the rule to delete",
            },
            "apply": {"type": "boolean", "description": "Apply changes immediately"},
        },
        "required": ["rule_uuid"],
    }

    def __init__(self, client):
        self.client = client

    async def execute(self, params: dict[str, Any] = None) -> dict[str, Any]:
        """
        Delete a firewall rule and optionally apply changes.

        Parameters
        ----------
        - rule_uuid: UUID of the rule to delete (required)
        - apply: Whether to apply changes immediately (default: true)

        """
        try:
            if params is None:
                params = {}

            # Validate required parameter
            rule_uuid = params.get("rule_uuid")
            if not rule_uuid:
                return {
                    "error": ("rule_uuid is required to delete a firewall rule"),
                    "status": "error",
                }

            logger.info(f"Deleting firewall rule: {rule_uuid}")

            # Delete the rule
            result = await self.client.delete_firewall_rule(rule_uuid)

            if result.get("result") != "success":
                return {
                    "error": f"Failed to delete rule: {result}",
                    "status": "error",
                }

            logger.info(f"Successfully deleted rule with UUID: {rule_uuid}")

            # Apply changes if requested (default: true)
            apply_changes = params.get("apply", True)
            if apply_changes:
                logger.info("Applying firewall changes...")
                apply_result = await self.client.apply_firewall_changes()

                if apply_result.get("result") != "success":
                    return {
                        "error": (
                            f"Rule deleted but failed to apply changes: {apply_result}"
                        ),
                        "rule_uuid": rule_uuid,
                        "status": "partial_success",
                    }

                logger.info("Successfully applied firewall changes")

                return {
                    "rule_uuid": rule_uuid,
                    "revision": apply_result.get("revision"),
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
            return {
                "error": f"Failed to delete firewall rule: {e}",
                "status": "error",
            }
