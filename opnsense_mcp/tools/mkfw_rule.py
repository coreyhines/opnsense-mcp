#!/usr/bin/env python3

import logging
from typing import Any

from pydantic import BaseModel, field_validator

logger = logging.getLogger(__name__)


class FirewallRuleSpec(BaseModel):
    """Model for firewall rule creation specification"""

    description: str
    interface: str = (
        ""  # Use empty string as default since "lan" is not valid on this
        # system
    )
    action: str = "pass"  # pass, block, reject
    protocol: str = "any"  # any, tcp, udp, icmp, etc.
    source_net: str = "any"
    source_port: str = "any"
    destination_net: str = "any"
    destination_port: str = "any"
    direction: str = "in"  # in, out
    ipprotocol: str = "inet"  # inet, inet6
    enabled: bool = True
    gateway: str = ""

    @field_validator("action")
    @classmethod
    def validate_action(cls, v):
        allowed = ["pass", "block", "reject"]
        if v.lower() not in allowed:
            raise ValueError(f"Action must be one of: {allowed}")
        return v.lower()

    @field_validator("direction")
    @classmethod
    def validate_direction(cls, v):
        allowed = ["in", "out"]
        if v.lower() not in allowed:
            raise ValueError(f"Direction must be one of: {allowed}")
        return v.lower()

    @field_validator("ipprotocol")
    @classmethod
    def validate_ipprotocol(cls, v):
        allowed = ["inet", "inet6"]
        if v.lower() not in allowed:
            raise ValueError(f"IP protocol must be one of: {allowed}")
        return v.lower()


class MkfwRuleTool:
    name = "mkfw_rule"
    description = "Create firewall rules"
    inputSchema = {
        "type": "object",
        "properties": {
            "description": {"type": "string", "description": "Rule description"},
            "interface": {"type": "string", "description": "Interface name"},
            "action": {
                "type": "string",
                "description": "Rule action (pass/block/reject)",
            },
            "protocol": {
                "type": "string",
                "description": "Protocol (any/tcp/udp/icmp)",
            },
            "source_net": {"type": "string", "description": "Source network"},
            "source_port": {"type": "string", "description": "Source port"},
            "destination_net": {"type": "string", "description": "Destination network"},
            "destination_port": {"type": "string", "description": "Destination port"},
            "enabled": {"type": "boolean", "description": "Enable rule"},
            "apply": {"type": "boolean", "description": "Apply changes immediately"},
        },
        "required": ["description"],
    }

    def __init__(self, client):
        self.client = client

    async def execute(self, params: dict[str, Any] = None) -> dict[str, Any]:
        """
        Create a new firewall rule and apply changes.

        Parameters
        ----------
        - description: Description of the rule (required)
        - interface: Interface name - use "wan", "opt1", etc. or leave empty
          for any (default: "")
        - action: pass, block, or reject (default: "pass")
        - protocol: any, tcp, udp, icmp, etc. (default: "any")
        - source_net: Source network/IP (default: "any")
        - source_port: Source port (default: "any")
        - destination_net: Destination network/IP (default: "any")
        - destination_port: Destination port (default: "any")
        - enabled: true or false (default: true)
        - gateway: Gateway to use (default: "")
        - apply: Whether to apply changes immediately (default: true)

        Note: This OPNsense instance uses interface names like "wan", "opt1"
        rather than "lan".

        """
        try:
            if params is None:
                params = {}

            # Validate required parameter
            if not params.get("description"):
                return {
                    "error": "Description is required for firewall rules",
                    "status": "error",
                }

            # Create and validate rule specification
            try:
                rule_spec = FirewallRuleSpec(**params)
            except Exception as e:
                return {
                    "error": f"Invalid rule parameters: {e}",
                    "status": "error",
                }

            # Build rule data for OPNsense API - simplified to match
            # documentation
            rule_data = {
                "description": rule_spec.description,
                "action": rule_spec.action,
                # Documentation shows uppercase
                "protocol": rule_spec.protocol.upper(),
                "source_net": rule_spec.source_net,
                "destination_net": rule_spec.destination_net,
            }

            # Only add optional fields if they're not defaults
            if rule_spec.interface:  # Only add if not empty
                rule_data["interface"] = rule_spec.interface
            # Only add if disabled (default is enabled)
            if rule_spec.enabled is False:
                rule_data["enabled"] = "0"
            if rule_spec.source_port != "any":
                rule_data["source_port"] = rule_spec.source_port
            if rule_spec.destination_port != "any":
                rule_data["destination_port"] = rule_spec.destination_port
            if rule_spec.gateway:
                rule_data["gateway"] = rule_spec.gateway

            logger.info(f"Creating firewall rule: {rule_spec.description}")
            logger.debug(f"Rule data: {rule_data}")

            # Create the rule
            result = await self.client.add_firewall_rule(rule_data)

            if result.get("result") != "success":
                return {
                    "error": f"Failed to create rule: {result}",
                    "status": "error",
                }

            rule_uuid = result.get("uuid")
            logger.info(f"Successfully created rule with UUID: {rule_uuid}")

            # Apply changes if requested (default: true)
            apply_changes = params.get("apply", True)
            if apply_changes:
                logger.info("Applying firewall changes...")
                apply_result = await self.client.apply_firewall_changes()

                if apply_result.get("result") != "success":
                    return {
                        "error": (
                            f"Rule created but failed to apply changes: {apply_result}"
                        ),
                        "rule_uuid": rule_uuid,
                        "status": "partial_success",
                    }

                logger.info("Successfully applied firewall changes")

                return {
                    "rule_uuid": rule_uuid,
                    "revision": apply_result.get("revision"),
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
            return {
                "error": f"Failed to create firewall rule: {e}",
                "status": "error",
            }
