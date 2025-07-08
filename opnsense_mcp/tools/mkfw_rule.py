"""Firewall rule creation tool for OPNsense."""

import logging
from typing import Any

from pydantic import BaseModel, field_validator

from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)


class FirewallRuleSpec(BaseModel):
    """Specification for creating a firewall rule."""

    description: str
    interface: str = "lan"
    direction: str = "in"
    ipprotocol: str = "inet"
    protocol: str = "any"
    source_net: str = "any"
    source_port: str = "any"
    destination_net: str = "any"
    destination_port: str = "any"
    action: str = "pass"
    enabled: bool = True
    gateway: str = ""

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        """
        Validate the action field value.

        Args:
            v: Action value to validate.

        Returns:
            Validated action value.

        """
        allowed = ["pass", "block", "reject"]
        if v.lower() not in allowed:
            msg = f"Action must be one of {allowed}"
            raise ValueError(msg)
        return v.lower()

    @field_validator("direction")
    @classmethod
    def validate_direction(cls, v: str) -> str:
        """
        Validate the direction field value.

        Args:
            v: Direction value to validate.

        Returns:
            Validated direction value.

        """
        allowed = ["in", "out"]
        if v.lower() not in allowed:
            msg = f"Direction must be one of {allowed}"
            raise ValueError(msg)
        return v.lower()

    @field_validator("ipprotocol")
    @classmethod
    def validate_ipprotocol(cls, v: str) -> str:
        """
        Validate the IP protocol field value.

        Args:
            v: IP protocol value to validate.

        Returns:
            Validated IP protocol value.

        """
        allowed = ["inet", "inet6"]
        if v.lower() not in allowed:
            msg = f"IP protocol must be one of {allowed}"
            raise ValueError(msg)
        return v.lower()


class MkfwRuleTool:
    """Tool for creating firewall rules in OPNsense."""

    name = "mkfw_rule"
    description = "Create firewall rules"
    input_schema = {
        "type": "object",
        "properties": {
            "description": {"type": "string"},
            "interface": {"type": "string", "default": "lan"},
            "direction": {"type": "string", "default": "in"},
            "ipprotocol": {"type": "string", "default": "inet"},
            "protocol": {"type": "string", "default": "any"},
            "source_net": {"type": "string", "default": "any"},
            "source_port": {"type": "string", "default": "any"},
            "destination_net": {"type": "string", "default": "any"},
            "destination_port": {"type": "string", "default": "any"},
            "action": {"type": "string", "default": "pass"},
            "enabled": {"type": "boolean", "default": True},
            "gateway": {"type": "string", "default": ""},
            "apply": {"type": "boolean", "default": True},
        },
        "required": ["description"],
    }

    def __init__(self, client: OPNsenseClient | None) -> None:
        """
        Initialize the firewall rule creation tool.

        Args:
            client: OPNsense client instance for API communication.

        """
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Create a new firewall rule and optionally apply changes.

        Args:
            params: Rule creation parameters including description, interface, etc.

        Returns:
            Dictionary containing rule creation results.

        """
        if params is None:
            params = {}

        if not self.client:
            return {"status": "error", "error": "No client available"}

        try:
            # Create rule specification
            rule_spec = FirewallRuleSpec(**params)

            # Get apply setting
            apply_changes = params.get("apply", True)

            # Create the rule using the client
            rule_uuid = await self.client.create_firewall_rule(rule_spec.model_dump())

            if apply_changes:
                await self.client.apply_firewall_changes()
                return {
                    "rule_uuid": rule_uuid,
                    "description": rule_spec.description,
                    "interface": rule_spec.interface,
                    "action": rule_spec.action,
                    "applied": True,
                    "status": "success",
                }

            return {
                "rule_uuid": rule_uuid,
                "description": rule_spec.description,
                "interface": rule_spec.interface,
                "action": rule_spec.action,
                "applied": False,
                "status": "success",
                "note": (
                    "Rule created but not applied. Use "
                    "apply_firewall_changes() to activate."
                ),
            }

        except Exception as e:
            logger.exception("Failed to create firewall rule")
            return {"status": "error", "error": str(e)}
