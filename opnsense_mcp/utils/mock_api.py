#!/usr/bin/env python3
"""Mock API client for development and testing."""

from __future__ import annotations

import copy
import json
import logging
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class MockOPNsenseClient:
    """Mock OPNsense API client for development and testing."""

    def __init__(self, config: dict[str, Any]) -> None:
        """Initialize the mock client with config."""
        self.config = config
        # Get absolute path to mock data
        workspace_root = Path(__file__).parent.parent.parent
        mock_data_dir = config.get("development", {}).get(
            "mock_data_path", "examples/mock_data"
        )
        self.mock_data_path = workspace_root / mock_data_dir
        self._load_mock_data()
        # Mutable data is deep-copied from fixture on first mutation
        self._mutable_shaper: dict[str, Any] | None = None

    def _load_mock_data(self) -> None:
        """Load all mock data files."""
        self.mock_data = {}
        try:
            mock_path = Path(self.mock_data_path).resolve()
            logger.info(f"Looking for mock data in: {mock_path}")
            if not mock_path.exists():
                logger.error(f"Mock data path does not exist: {mock_path}")
                return

            for file_path in mock_path.glob("*.json"):
                try:
                    logger.info(f"Loading mock data from {file_path}")
                    with open(file_path) as f:
                        data = json.load(f)
                        self.mock_data[file_path.stem] = data
                        logger.debug(f"Loaded {file_path.stem} data: {data}")
                except Exception:
                    logger.exception(f"Failed to load {file_path.name}")

            logger.info(
                "Successfully loaded mock data. "
                f"Available keys: {list(self.mock_data.keys())}"
            )
            for key in self.mock_data:
                if isinstance(self.mock_data[key], dict):
                    logger.debug(f"{key} structure: {list(self.mock_data[key].keys())}")

        except Exception:
            logger.exception("Failed to load mock data")
            self.mock_data = {}

    def _ensure_shaper_mutable_copy(self) -> None:
        """Deep-copy the traffic shaper fixture so mutations don't leak across tests."""
        if self._mutable_shaper is None:
            self._mutable_shaper = copy.deepcopy(
                self.mock_data.get("traffic_shaper", {})
            )

    def _generate_uuid(self) -> str:
        """Generate a random UUID for new shaper objects."""
        return str(uuid.uuid4())

    async def get_system_status(self) -> dict[str, Any]:
        """Get mock system status."""
        return self.mock_data.get("system_status", {})

    async def get_arp_table(self):
        """Get mock ARP table."""
        data = self.mock_data.get("arp_table", {})
        return data.get("entries", [])

    async def get_ndp_table(self):
        """Get mock NDP table - empty for now."""
        return []

    async def get_interfaces(self):
        """Get mock interfaces."""
        data = self.mock_data.get("interfaces", {})
        return data.get("interfaces", [])

    async def get_firewall_rules(
        self, *, row_count: int = 1000
    ) -> list[dict[str, Any]]:
        """Get mock firewall rules (row_count matches OPNsense client; ignored here)."""
        _ = row_count
        data = self.mock_data.get("firewall_rules", {})
        return data.get("rules", [])

    def _traffic_shaper_mock(self, method: str, endpoint: str) -> dict[str, Any] | None:
        """Return mock traffic shaper payload when endpoint matches, else None."""
        method_u = method.upper()
        shaper_source = (
            self._mutable_shaper
            if self._mutable_shaper is not None
            else self.mock_data.get("traffic_shaper", {})
        )
        if not shaper_source:
            return None

        # --- Read-only endpoints (unchanged from bucket 3c) ---
        resource_map = {
            "get_pipe": ("search_pipes", "pipe"),
            "get_queue": ("search_queues", "queue"),
            "get_rule": ("search_rules", "rule"),
        }
        for path_part, (search_key, resource) in resource_map.items():
            if f"/trafficshaper/settings/{path_part}/" in endpoint:
                uuid_val = endpoint.rsplit("/", 1)[-1]
                for row in shaper_source.get(search_key, {}).get("rows", []):
                    if row.get("uuid") == uuid_val:
                        return {resource: row}

        if endpoint.endswith("/trafficshaper/settings/get") and method_u == "GET":
            return shaper_source.get("settings_get", {"ts": {}})
        if "/trafficshaper/service/statistics" in endpoint:
            return shaper_source.get("statistics", {"status": "ok", "items": []})
        if "/trafficshaper/settings/search_pipes" in endpoint:
            return shaper_source.get("search_pipes", {"rows": [], "rowCount": 0})
        if "/trafficshaper/settings/search_queues" in endpoint:
            return shaper_source.get("search_queues", {"rows": [], "rowCount": 0})
        if "/trafficshaper/settings/search_rules" in endpoint:
            return shaper_source.get("search_rules", {"rows": [], "rowCount": 0})

        # --- Write endpoints (bucket 4c) ---
        if method_u != "POST":
            return None

        # POST /trafficshaper/service/reconfigure
        if "/trafficshaper/service/reconfigure" in endpoint:
            return {"status": "ok"}

        # Route to per-resource handlers
        if "/trafficshaper/settings/" in endpoint:
            for action in ("add_pipe", "set_pipe", "del_pipe", "toggle_pipe"):
                if (
                    f"/trafficshaper/settings/{action}/" in endpoint
                    or endpoint.endswith(f"/trafficshaper/settings/{action}")
                ):
                    return self._handle_pipe_action(action, endpoint)
            for action in ("add_queue", "set_queue", "del_queue", "toggle_queue"):
                if (
                    f"/trafficshaper/settings/{action}/" in endpoint
                    or endpoint.endswith(f"/trafficshaper/settings/{action}")
                ):
                    return self._handle_queue_action(action, endpoint)
            for action in ("add_rule", "set_rule", "del_rule", "toggle_rule"):
                if (
                    f"/trafficshaper/settings/{action}/" in endpoint
                    or endpoint.endswith(f"/trafficshaper/settings/{action}")
                ):
                    return self._handle_rule_action(action, endpoint)

        # POST /trafficshaper/settings/set (global settings subset)
        if endpoint.endswith("/trafficshaper/settings/set"):
            return self._handle_set_global_settings(endpoint)

        return None

    def _handle_pipe_action(self, action: str, endpoint: str) -> dict[str, Any]:
        """Handle pipe CRUD/toggle mutation."""
        self._ensure_shaper_mutable_copy()
        pipes = (
            self._mutable_shaper.setdefault("settings_get", {})
            .setdefault("ts", {})
            .setdefault("pipes", {})
            .setdefault("pipe", {})
        )
        search_pipes = self._mutable_shaper.setdefault("search_pipes", {})
        rows = search_pipes.get("rows", [])

        if action == "add_pipe":
            pipe_uuid = self._generate_uuid()
            new_row: dict[str, str] = {
                "uuid": pipe_uuid,
                "number": "10002",
                "description": "New pipe",
                "enabled": "1",
                "bandwidth": "0",
                "bandwidthMetric": "Mbit",
                "scheduler": "fq_codel",
            }
            pipes[pipe_uuid] = {"_uuid_ref": pipe_uuid}
            rows.append(new_row)
            search_pipes["rowCount"] = len(rows)
            return {"status": "ok", "id": pipe_uuid}

        if action == "set_pipe":
            uuid_val = endpoint.rsplit("/", 1)[-1]
            if uuid_val in pipes:
                row_ref = next((r for r in rows if r.get("uuid") == uuid_val), None)
                if row_ref:
                    row_ref["enabled"] = "1"
                    row_ref["description"] = f"Updated pipe {uuid_val[:8]}"
            return {"status": "ok"}

        if action == "del_pipe":
            uuid_val = endpoint.rsplit("/", 1)[-1]
            if uuid_val in pipes:
                del pipes[uuid_val]
                rows[:] = [r for r in rows if r.get("uuid") != uuid_val]
                search_pipes["rowCount"] = len(rows)
            return {"status": "ok"}

        if action == "toggle_pipe":
            uuid_val = endpoint.rsplit("/", 1)[-1]
            row_ref = next((r for r in rows if r.get("uuid") == uuid_val), None)
            if row_ref:
                current = row_ref.get("enabled", "1")
                row_ref["enabled"] = "0" if current == "1" else "1"
            return {"status": "ok", "enabled": row_ref["enabled"] if row_ref else "1"}

        return {"status": "ok"}

    def _handle_queue_action(self, action: str, endpoint: str) -> dict[str, Any]:
        """Handle queue CRUD/toggle mutation."""
        self._ensure_shaper_mutable_copy()
        queues = (
            self._mutable_shaper.setdefault("settings_get", {})
            .setdefault("ts", {})
            .setdefault("queues", {})
            .setdefault("queue", {})
        )
        search_queues = self._mutable_shaper.setdefault("search_queues", {})
        rows = search_queues.get("rows", [])

        if action == "add_queue":
            queue_uuid = self._generate_uuid()
            new_row: dict[str, str] = {
                "uuid": queue_uuid,
                "description": "New queue",
                "enabled": "1",
                "pipe": "",
                "weight": "100",
            }
            queues[queue_uuid] = {"_uuid_ref": queue_uuid}
            rows.append(new_row)
            search_queues["rowCount"] = len(rows)
            return {"status": "ok", "id": queue_uuid}

        if action == "set_queue":
            uuid_val = endpoint.rsplit("/", 1)[-1]
            if uuid_val in queues:
                row_ref = next((r for r in rows if r.get("uuid") == uuid_val), None)
                if row_ref:
                    row_ref["enabled"] = "1"
                    row_ref["description"] = f"Updated queue {uuid_val[:8]}"
            return {"status": "ok"}

        if action == "del_queue":
            uuid_val = endpoint.rsplit("/", 1)[-1]
            if uuid_val in queues:
                del queues[uuid_val]
                rows[:] = [r for r in rows if r.get("uuid") != uuid_val]
                search_queues["rowCount"] = len(rows)
            return {"status": "ok"}

        if action == "toggle_queue":
            uuid_val = endpoint.rsplit("/", 1)[-1]
            row_ref = next((r for r in rows if r.get("uuid") == uuid_val), None)
            if row_ref:
                current = row_ref.get("enabled", "1")
                row_ref["enabled"] = "0" if current == "1" else "1"
            return {"status": "ok", "enabled": row_ref["enabled"] if row_ref else "1"}

        return {"status": "ok"}

    def _handle_rule_action(self, action: str, endpoint: str) -> dict[str, Any]:
        """Handle rule CRUD/toggle mutation."""
        self._ensure_shaper_mutable_copy()
        rules = (
            self._mutable_shaper.setdefault("settings_get", {})
            .setdefault("ts", {})
            .setdefault("rules", {})
            .setdefault("rule", {})
        )
        search_rules = self._mutable_shaper.setdefault("search_rules", {})
        rows = search_rules.get("rows", [])

        if action == "add_rule":
            rule_uuid = self._generate_uuid()
            new_row: dict[str, str] = {
                "uuid": rule_uuid,
                "description": "New rule",
                "enabled": "1",
                "interface": "wan",
                "direction": "in",
                "proto": "ip",
                "target": "",
            }
            rules[rule_uuid] = {"_uuid_ref": rule_uuid}
            rows.append(new_row)
            search_rules["rowCount"] = len(rows)
            return {"status": "ok", "id": rule_uuid}

        if action == "set_rule":
            uuid_val = endpoint.rsplit("/", 1)[-1]
            if uuid_val in rules:
                row_ref = next((r for r in rows if r.get("uuid") == uuid_val), None)
                if row_ref:
                    row_ref["enabled"] = "1"
                    row_ref["description"] = f"Updated rule {uuid_val[:8]}"
            return {"status": "ok"}

        if action == "del_rule":
            uuid_val = endpoint.rsplit("/", 1)[-1]
            if uuid_val in rules:
                del rules[uuid_val]
                rows[:] = [r for r in rows if r.get("uuid") != uuid_val]
                search_rules["rowCount"] = len(rows)
            return {"status": "ok"}

        if action == "toggle_rule":
            uuid_val = endpoint.rsplit("/", 1)[-1]
            row_ref = next((r for r in rows if r.get("uuid") == uuid_val), None)
            if row_ref:
                current = row_ref.get("enabled", "1")
                row_ref["enabled"] = "0" if current == "1" else "1"
            return {"status": "ok", "enabled": row_ref["enabled"] if row_ref else "1"}

        return {"status": "ok"}

    def _handle_set_global_settings(self, endpoint: str) -> dict[str, Any]:
        """Handle POST /trafficshaper/settings/set for global settings subset."""
        self._ensure_shaper_mutable_copy()
        # Accept any payload and mirror it back as success
        return {
            "status": "ok",
            "message": "Settings saved successfully",
        }

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        **_kwargs: Any,
    ) -> dict[str, Any]:
        """Stub for tools that call the real client's request helper."""
        logger.debug("Mock _make_request: %s %s", method, endpoint)
        shaper_resp = self._traffic_shaper_mock(method, endpoint)
        if shaper_resp is not None:
            return shaper_resp
        return {"total": 0, "rows": []}

    async def get_firewall_logs(self, limit: int = 500) -> list[dict[str, Any]]:
        """Get mock firewall logs."""
        logger.info(f"Mock API keys available: {list(self.mock_data.keys())}")
        data = self.mock_data.get("firewall_logs", {})

        log_keys = list(data.keys()) if data else "None"
        logger.info(f"Mock API firewall_logs data keys: {log_keys}")

        logs = data.get("logs", [])
        logger.info(f"Retrieved {len(logs)} raw logs, limit={limit}")
        return logs[:limit] if limit else logs

    async def get_dhcpv4_leases(self):
        """Get mock DHCPv4 leases."""
        data = self.mock_data.get("dhcp_leases", {})
        return data.get("v4", [])

    async def get_dhcpv6_leases(self):
        """Get mock DHCPv6 leases."""
        data = self.mock_data.get("dhcp_leases", {})
        return data.get("v6", [])

    async def search_arp_table(self, query: str):
        """Search mock ARP table."""
        entries = await self.get_arp_table()
        return [
            entry
            for entry in entries
            if query.lower() in entry.get("ip", "").lower()
            or query.lower() in entry.get("mac", "").lower()
            or query.lower() in entry.get("hostname", "").lower()
        ]

    async def search_ndp_table(self, query: str):
        """Search mock NDP table - empty for now."""
        return []

    async def search_firewall_logs(self, ip: str, row_count: int = 50):
        """Search mock firewall logs for a specific IP."""
        logs = await self.get_firewall_logs()
        filtered = [
            log
            for log in logs
            if ip in log.get("src_ip", "") or ip in log.get("dst_ip", "")
        ]
        return filtered[:row_count]

    async def get_firewall_interface_list(self) -> dict[str, Any]:
        """Get mock firewall interface list."""
        logger.info("Mock API: getting firewall interface list")
        return {
            "interfaces": {
                "lan": "LAN (igb0)",
                "wan": "WAN (igb1)",
                "opt1": "OPT1 (igb2)",
                "opt2": "OPT2 (igb3)",
                "loopback": "Loopback",
                "any": "Any",
            },
            "status": "success",
        }

    async def resolve_host_info(self, query: str) -> dict[str, Any]:
        """Resolve host information from mock ARP/DHCP data."""
        arp_matches = await self.search_arp_table(query)
        ndp_matches = await self.search_ndp_table(query)
        v4_matches = await self.search_dhcpv4_leases(query)
        v6_matches = await self.search_dhcpv6_leases(query)

        result: dict[str, Any] = {
            "input": query,
            "hostname": None,
            "ip": None,
            "mac": None,
            "dhcpv4": v4_matches[0] if v4_matches else None,
            "dhcpv6": v6_matches[0] if v6_matches else None,
            "arp": arp_matches[0] if arp_matches else None,
            "ndp": ndp_matches[0] if ndp_matches else None,
            "dns_forward_ips": [],
            "dns_reverse_names": [],
            "dns_verified": False,
        }

        if arp_matches:
            result["ip"] = arp_matches[0].get("ip")
            result["mac"] = arp_matches[0].get("mac")
            result["hostname"] = arp_matches[0].get("hostname")
        elif v4_matches:
            result["ip"] = v4_matches[0].get("ip") or v4_matches[0].get("address")
            result["mac"] = v4_matches[0].get("mac")
            result["hostname"] = v4_matches[0].get("hostname")

        return result

    async def search_host_overrides(self, search: str = "") -> list[dict[str, Any]]:
        """Return mock DNS host overrides."""
        data = self.mock_data.get("dns_overrides", {})
        rows = data.get("rows", []) if isinstance(data, dict) else []
        if not search:
            return rows
        search_lc = search.lower()
        return [
            row
            for row in rows
            if search_lc in str(row.get("hostname", "")).lower()
            or search_lc in str(row.get("domain", "")).lower()
            or search_lc in str(row.get("server", "")).lower()
            or search_lc in str(row.get("description", "")).lower()
        ]

    async def search_aliases(self, search: str = "") -> list[dict[str, Any]]:
        """Return mock firewall aliases."""
        data = self.mock_data.get("aliases", {})
        rows = data.get("rows", []) if isinstance(data, dict) else []
        if not search:
            return rows
        search_lc = search.lower()
        return [
            row
            for row in rows
            if search_lc in str(row.get("name", "")).lower()
            or search_lc in str(row.get("description", "")).lower()
            or search_lc in str(row.get("content", "")).lower()
        ]

    async def get_lldp_table(self) -> list[dict[str, Any]]:
        """Return mock LLDP neighbors."""
        data = self.mock_data.get("lldp_neighbors", {})
        return data.get("neighbors", []) if isinstance(data, dict) else []

    async def search_dhcpv4_leases(self, query: str) -> list[dict[str, Any]]:
        """Search mock DHCPv4 leases."""
        query_lc = query.lower()
        leases = await self.get_dhcpv4_leases()
        return [
            lease
            for lease in leases
            if query_lc in str(lease.get("hostname", "")).lower()
            or query_lc in str(lease.get("ip", lease.get("address", ""))).lower()
            or query_lc in str(lease.get("mac", "")).lower()
        ]

    async def search_dhcpv6_leases(self, query: str) -> list[dict[str, Any]]:
        """Search mock DHCPv6 leases."""
        query_lc = query.lower()
        leases = await self.get_dhcpv6_leases()
        return [
            lease
            for lease in leases
            if query_lc in str(lease.get("hostname", "")).lower()
            or query_lc in str(lease.get("ip", lease.get("address", ""))).lower()
            or query_lc in str(lease.get("mac", "")).lower()
        ]
