#!/usr/bin/env python3
"""Mock API client for development and testing."""

import json
import logging
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

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        **_kwargs: Any,
    ) -> dict[str, Any]:
        """Stub for tools that call the real client's request helper (empty grid by default)."""
        logger.debug("Mock _make_request: %s %s", method, endpoint)
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
