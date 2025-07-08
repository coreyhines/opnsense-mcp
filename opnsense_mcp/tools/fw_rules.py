"""Firewall rules management tool for OPNsense."""

import logging
from typing import Any

from pydantic import BaseModel

from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)


class FirewallEndpoint(BaseModel):
    """Model for firewall rule endpoints."""

    net: str
    port: str


class FirewallRule(BaseModel):
    """Model for firewall rule entries."""

    id: str
    sequence: int
    interface: str
    direction: str
    ipprotocol: str
    protocol: str
    source: FirewallEndpoint
    destination: FirewallEndpoint
    action: str
    enabled: bool
    description: str | None = None
    gateway: str | None = None
    log: bool | None = None
    quick: bool | None = None


class FwRulesTool:
    """Tool for retrieving and managing firewall rules in OPNsense."""

    def __init__(self, client: OPNsenseClient | None) -> None:
        """
        Initialize the firewall rules tool.

        Args:
            client: OPNsense client instance for API communication.

        """
        self.client = client
        self._interface_groups_cache = None

    async def _get_interface_groups(self) -> list[dict[str, Any]]:
        """
        Get interface groups from OPNsense API.

        Returns:
            List of interface group dictionaries.

        """
        if self._interface_groups_cache is not None:
            return self._interface_groups_cache

        try:
            # Try to get interface groups via API
            response = await self.client._make_request(
                "GET", "/api/firewall/group/searchRule"
            )

            groups = []
            if response.get("total", 0) > 0:
                for group in response.get("rows", []):
                    groups.append(
                        {
                            "name": group.get("name", ""),
                            "members": group.get("members", []),
                            "description": group.get("description", ""),
                        }
                    )

            self._interface_groups_cache = groups

        except Exception as e:
            logger.warning(f"Failed to get interface groups: {e}")
            return []
        else:
            return groups

    async def _get_interface_aliases(self) -> list[dict[str, Any]]:
        """
        Get interface aliases from OPNsense API.

        Returns:
            List of interface alias dictionaries.

        """
        try:
            # Try to get interface aliases
            response = await self.client._make_request(
                "GET", "/api/interfaces/overview/export"
            )

            aliases = []
            if isinstance(response, dict):
                for key, value in response.items():
                    aliases.append(
                        {
                            "name": key,
                            "description": value.get("description", ""),
                            "device": value.get("device", ""),
                        }
                    )

        except Exception as e:
            logger.warning(f"Failed to get interface aliases: {e}")
            return []
        else:
            return aliases

    async def _resolve_interface_name(self, iface_query: str) -> list[str]:
        """
        Resolve interface name to list of actual interface names.

        Handles partial matches, aliases, and interface groups.

        Args:
            iface_query: Interface name query string.

        Returns:
            List of resolved interface names.

        """
        if not iface_query:
            return []

        # Exact match first
        if iface_query in ["lan", "wan", "opt1", "opt2", "loopback", "any"]:
            return [iface_query]

        resolved = []

        # Check interface groups
        groups = await self._get_interface_groups()
        for group in groups:
            if iface_query.lower() in group["name"].lower():
                resolved.extend(group["members"])

        # Check interface aliases
        aliases = await self._get_interface_aliases()
        for alias in aliases:
            if iface_query.lower() in alias["name"].lower():
                resolved.append(alias["name"])

        # If nothing found, return the original query
        if not resolved:
            resolved = [iface_query]

        return resolved

    async def _get_rules(self) -> list[dict[str, Any]]:
        """
        Get firewall rules from OPNsense API.

        Returns:
            List of firewall rule dictionaries.

        """
        try:
            endpoint = "/api/firewall/filter/searchRule"
            params = {
                "current": 1,
                "rowCount": 1000,
            }  # Increase row count to get more rules
            data = await self.client._make_request("GET", endpoint, params=params)

            rules = []
            if data.get("total", 0) > 0:
                for rule in data.get("rows", []):
                    rules.append(
                        {
                            "id": rule.get("uuid", ""),
                            "sequence": rule.get("sequence", 0),
                            "interface": rule.get("interface", ""),
                            "direction": rule.get("direction", ""),
                            "ipprotocol": rule.get("ipprotocol", ""),
                            "protocol": rule.get("protocol", ""),
                            "source": {
                                "net": rule.get("source", ""),
                                "port": rule.get("source_port", ""),
                            },
                            "destination": {
                                "net": rule.get("destination", ""),
                                "port": rule.get("destination_port", ""),
                            },
                            "action": rule.get("action", ""),
                            "enabled": rule.get("enabled", "") == "1",
                            "description": rule.get("description", ""),
                            "gateway": rule.get("gateway", ""),
                            "log": rule.get("log", "") == "1",
                            "quick": rule.get("quick", "") == "1",
                        }
                    )

        except Exception:
            logger.exception("Failed to get firewall rules")
            return []
        else:
            return rules

    async def _filter_rules_by_interface(
        self, rules: list[dict[str, Any]], interface_query: str
    ) -> list[dict[str, Any]]:
        """
        Filter rules by interface name.

        Filter rules by interface name with partial matching and group resolution.

        Args:
            rules: List of rule dictionaries to filter.
            interface_query: Interface name query string.

        Returns:
            List of filtered rule dictionaries.

        """
        if not interface_query:
            return rules

        # Resolve interface query to actual interface names
        resolved_interfaces = await self._resolve_interface_name(interface_query)

        filtered_rules = []
        for rule in rules:
            rule_interface = rule.get("interface", "")

            # Check if rule interface matches any resolved interface
            for resolved_iface in resolved_interfaces:
                if (
                    resolved_iface.lower() in rule_interface.lower()
                    or rule_interface.lower() in resolved_iface.lower()
                ):
                    filtered_rules.append(rule)
                    break  # Avoid duplicates

        return filtered_rules

    async def _filter_rules_by_action(
        self, rules: list[dict[str, Any]], action: str
    ) -> list[dict[str, Any]]:
        """
        Filter rules by action.

        Args:
            rules: List of rule dictionaries to filter.
            action: Action to filter by.

        Returns:
            List of filtered rule dictionaries.

        """
        if not action:
            return rules

        return [
            rule for rule in rules if rule.get("action", "").lower() == action.lower()
        ]

    async def _filter_rules_by_protocol(
        self, rules: list[dict[str, Any]], protocol: str
    ) -> list[dict[str, Any]]:
        """
        Filter rules by protocol.

        Args:
            rules: List of rule dictionaries to filter.
            protocol: Protocol to filter by.

        Returns:
            List of filtered rule dictionaries.

        """
        if not protocol:
            return rules

        return [
            rule
            for rule in rules
            if rule.get("protocol", "").lower() == protocol.lower()
        ]

    async def _filter_rules_by_enabled(
        self, rules: list[dict[str, Any]], enabled: bool
    ) -> list[dict[str, Any]]:
        """
        Filter rules by enabled status.

        Args:
            rules: List of rule dictionaries to filter.
            enabled: Enabled status to filter by.

        Returns:
            List of filtered rule dictionaries.

        """
        return [rule for rule in rules if rule.get("enabled", False) == enabled]

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Return the current firewall rule set with optional filtering.

        Args:
            params: Optional filtering parameters including interface, action, protocol, enabled.

        Returns:
            Dictionary containing firewall rules and metadata.

        """
        if params is None:
            params = {}

        try:
            if not self.client:
                return {
                    "rules": [],
                    "total": 0,
                    "status": "error",
                    "error": "No client available",
                }

            # Get all rules
            all_rules = await self._get_rules()

            # Apply filters
            filtered_rules = all_rules

            # Filter by interface
            if "interface" in params:
                filtered_rules = await self._filter_rules_by_interface(
                    filtered_rules, params["interface"]
                )

            # Filter by action
            if "action" in params:
                filtered_rules = await self._filter_rules_by_action(
                    filtered_rules, params["action"]
                )

            # Filter by protocol
            if "protocol" in params:
                filtered_rules = await self._filter_rules_by_protocol(
                    filtered_rules, params["protocol"]
                )

            # Filter by enabled status
            if "enabled" in params:
                filtered_rules = await self._filter_rules_by_enabled(
                    filtered_rules, params["enabled"]
                )

            return {
                "rules": filtered_rules,
                "total": len(filtered_rules),
                "total_all": len(all_rules),
                "status": "success",
                "filters_applied": {
                    "interface": params.get("interface"),
                    "action": params.get("action"),
                    "protocol": params.get("protocol"),
                    "enabled": params.get("enabled"),
                },
            }

        except Exception as e:
            logger.exception("Failed to get firewall rules")
            return {"rules": [], "total": 0, "status": "error", "error": str(e)}
