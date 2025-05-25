#!/usr/bin/env python3

import logging
from typing import Any

from pydantic import BaseModel

logger = logging.getLogger(__name__)


class FirewallEndpoint(BaseModel):
    net: str
    port: str


class FirewallRule(BaseModel):
    id: str
    sequence: int
    description: str
    interface: str
    protocol: str
    source: FirewallEndpoint
    destination: FirewallEndpoint
    action: str
    enabled: bool
    gateway: str = ""
    direction: str = "in"
    ipprotocol: str = "inet"
    source_type: str = "filter"  # Track which endpoint this came from


class FwRulesTool:
    def __init__(self, client):
        self.client = client
        self._interface_groups_cache = None
        self._interfaces_cache = None

    async def _get_interface_groups(self) -> dict[str, list[str]]:
        """Get interface groups and their member interfaces"""
        if self._interface_groups_cache is not None:
            return self._interface_groups_cache

        try:
            # Try to get interface groups via API
            response = await self.client._make_request(
                "GET", "/api/firewall/group/searchRule"
            )
            groups = {}

            # Parse groups from the response - this will depend on OPNsense API
            # structure
            if isinstance(response, dict) and "rows" in response:
                for row in response.get("rows", []):
                    group_name = row.get("interface", "")
                    if group_name and group_name not in groups:
                        groups[group_name] = []

        except Exception as e:
            logger.debug(f"Could not fetch interface groups: {e}")
            self._interface_groups_cache = {}
            return {}
        else:
            logger.debug(f"Found {len(groups)} interface groups")
            self._interface_groups_cache = groups
            return groups

    async def _get_interfaces(self) -> dict[str, str]:
        """Get all interfaces with their descriptions/aliases"""
        if self._interfaces_cache is not None:
            return self._interfaces_cache

        try:
            interfaces = await self.client.get_interfaces()
        except Exception as e:
            logger.debug(f"Could not fetch interfaces: {e}")
            self._interfaces_cache = {}
            return {}
        else:
            self._interfaces_cache = interfaces if isinstance(interfaces, dict) else {}
            return self._interfaces_cache

    async def _resolve_interface_name(self, iface_query: str) -> list[str]:
        """
        Resolve interface name to list of actual interface names.
        Handles partial matches, aliases, and interface groups.
        """
        if not iface_query:
            return []

        interfaces = await self._get_interfaces()
        groups = await self._get_interface_groups()
        resolved = set()

        # Direct match to real interface name
        if iface_query in interfaces:
            resolved.add(iface_query)

        # Check for group membership
        if iface_query in groups:
            resolved.update(groups[iface_query])

        # Partial match on interface names and descriptions
        for iface_name, iface_desc in interfaces.items():
            if (
                iface_query.lower() in iface_name.lower()
                or iface_query.lower() in str(iface_desc).lower()
            ):
                resolved.add(iface_name)

        # Partial match on group names
        for group_name, group_members in groups.items():
            if iface_query.lower() in group_name.lower():
                resolved.update(group_members)

        result = list(resolved) if resolved else [iface_query]
        logger.debug(f"Resolved interface '{iface_query}' to: {result}")
        return result

    async def _get_rules_from_endpoint(
        self, endpoint: str, source_type: str = "filter"
    ) -> list[dict[str, Any]]:
        """Get rules from a specific API endpoint"""
        try:
            logger.debug(f"Fetching rules from {endpoint}")
            params = {
                "current": 1,
                "rowCount": 1000,
            }  # Increase row count to get more rules
            data = await self.client._make_request("GET", endpoint, params=params)

            rules = []
            if isinstance(data, dict) and "rows" in data:
                for rule in data.get("rows", []):
                    rule["source_type"] = source_type
                    rules.append(rule)

        except Exception as e:
            logger.debug(f"Failed to get rules from {endpoint}: {e}")
            return []
        else:
            logger.debug(f"Retrieved {len(rules)} rules from {endpoint}")
            return rules

    async def _get_all_firewall_rules(self) -> list[dict[str, Any]]:
        """Get rules from all available firewall endpoints"""
        all_rules = []

        # Standard filter rules
        filter_rules = await self._get_rules_from_endpoint(
            "/api/firewall/filter/searchRule", "filter"
        )
        all_rules.extend(filter_rules)

        # Interface group rules
        group_rules = await self._get_rules_from_endpoint(
            "/api/firewall/group/searchRule", "group"
        )
        all_rules.extend(group_rules)

        # Try other potential endpoints
        other_endpoints = [
            "/api/firewall/nat/searchRule",
            "/api/firewall/alias/searchRule",
        ]

        for endpoint in other_endpoints:
            try:
                rules = await self._get_rules_from_endpoint(
                    endpoint, endpoint.split("/")[-2]
                )
                all_rules.extend(rules)
            except Exception as e:
                logger.debug(f"Endpoint {endpoint} not available: {e}")

        logger.info(f"Retrieved total of {len(all_rules)} rules from all endpoints")
        return all_rules

    async def _filter_rules_by_interface(
        self, rules: list[dict[str, Any]], interface_query: str
    ) -> list[dict[str, Any]]:
        """
        Filter rules by interface name (with partial matching and group
        resolution)
        """
        if not interface_query:
            return rules

        target_interfaces = await self._resolve_interface_name(interface_query)
        filtered_rules = []

        for rule in rules:
            rule_interface = rule.get("interface", "")

            # Check if rule interface matches any of our target interfaces
            if any(
                target in rule_interface or rule_interface in target
                for target in target_interfaces
            ):
                filtered_rules.append(rule)
                continue

            # Check source and destination networks for interface references
            source_net = (
                rule.get("source", {}).get("net", "")
                if isinstance(rule.get("source"), dict)
                else ""
            )
            dest_net = (
                rule.get("destination", {}).get("net", "")
                if isinstance(rule.get("destination"), dict)
                else ""
            )

            if any(
                target in source_net or target in dest_net
                for target in target_interfaces
            ):
                filtered_rules.append(rule)

        logger.debug(
            f"Filtered {len(rules)} rules down to {len(filtered_rules)} "
            f"matching interface '{interface_query}'"
        )
        return filtered_rules

    async def execute(self, params: dict[str, Any] = None) -> dict[str, Any]:
        """
        Return the current firewall rule set with optional filtering.

        Parameters
        ----------
        - interface: Filter by interface name (supports partial matching and
          groups)
        - action: Filter by action (pass, block, reject, etc.)
        - enabled: Filter by enabled status (true/false)
        - protocol: Filter by protocol

        """
        try:
            if params is None:
                params = {}

            # Get all rules from multiple endpoints
            all_rules = await self._get_all_firewall_rules()

            # Apply filters
            filtered_rules = all_rules

            # Filter by interface
            if params.get("interface"):
                filtered_rules = await self._filter_rules_by_interface(
                    filtered_rules, params["interface"]
                )

            # Filter by action
            if params.get("action"):
                action_filter = params["action"].lower()
                filtered_rules = [
                    rule
                    for rule in filtered_rules
                    if rule.get("action", "").lower() == action_filter
                ]

            # Filter by enabled status
            if "enabled" in params:
                enabled_filter = params["enabled"]
                if isinstance(enabled_filter, str):
                    enabled_filter = enabled_filter.lower() in (
                        "true",
                        "1",
                        "yes",
                    )
                filtered_rules = [
                    rule
                    for rule in filtered_rules
                    if bool(rule.get("enabled", False)) == bool(enabled_filter)
                ]

            # Filter by protocol
            if params.get("protocol"):
                protocol_filter = params["protocol"].lower()
                filtered_rules = [
                    rule
                    for rule in filtered_rules
                    if rule.get("protocol", "").lower() == protocol_filter
                ]

            # Process rules into standard format
            processed_rules = []
            for rule in filtered_rules:
                try:
                    # Ensure source and destination are proper dict format
                    source = rule.get("source", {})
                    if not isinstance(source, dict):
                        source = {"net": str(source), "port": "any"}
                    if "net" not in source:
                        source["net"] = "any"
                    if "port" not in source:
                        source["port"] = "any"

                    destination = rule.get("destination", {})
                    if not isinstance(destination, dict):
                        destination = {"net": str(destination), "port": "any"}
                    if "net" not in destination:
                        destination["net"] = "any"
                    if "port" not in destination:
                        destination["port"] = "any"

                    # Create standardized rule
                    processed_rule = {
                        "id": str(rule.get("uuid", rule.get("id", "unknown"))),
                        "sequence": int(rule.get("sequence", 0)),
                        "description": rule.get("description", ""),
                        "interface": rule.get("interface", ""),
                        "protocol": rule.get("protocol", "any"),
                        "source": source,
                        "destination": destination,
                        "action": rule.get("action", "pass"),
                        "enabled": bool(rule.get("enabled", False)),
                        "gateway": rule.get("gateway", ""),
                        "direction": rule.get("direction", "in"),
                        "ipprotocol": rule.get("ipprotocol", "inet"),
                        "source_type": rule.get("source_type", "filter"),
                    }
                    processed_rules.append(processed_rule)

                except Exception as e:
                    logger.warning(f"Failed to process rule: {e}")
                    continue

            # Add summary information
            summary = {
                "total_rules": len(all_rules),
                "filtered_rules": len(processed_rules),
                "filters_applied": {k: v for k, v in params.items() if v is not None},
                "source_types": list(
                    {rule.get("source_type", "unknown") for rule in processed_rules}
                ),
            }

        except Exception as e:
            logger.exception("Failed to get firewall rules")
            return {
                "error": f"Failed to get firewall rules: {e}",
                "status": "error",
            }
        else:
            return {
                "rules": processed_rules,
                "summary": summary,
                "status": "success",
            }
