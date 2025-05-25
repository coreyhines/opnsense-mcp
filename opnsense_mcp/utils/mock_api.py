#!/usr/bin/env python3
"""Mock API client for development and testing"""

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class MockOPNsenseClient:
    """Mock OPNsense API client for development and testing"""

    def __init__(self, config: dict[str, Any]):
        """Initialize the mock client with config"""
        self.config = config
        # Get absolute path to mock data
        workspace_root = Path(__file__).parent.parent.parent
        mock_data_dir = config.get("development", {}).get(
            "mock_data_path", "examples/mock_data"
        )
        self.mock_data_path = workspace_root / mock_data_dir
        self._load_mock_data()

    def _load_mock_data(self):
        """Load all mock data files"""
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

    async def get_system_status(self):
        """Get mock system status"""
        return self.mock_data.get("system_status", {})

    async def get_arp_table(self):
        """Get mock ARP table"""
        data = self.mock_data.get("arp_table", {})
        return data.get("entries", [])

    async def get_ndp_table(self):
        """Get mock NDP table - empty for now"""
        return []

    async def get_interfaces(self):
        """Get mock interfaces"""
        data = self.mock_data.get("interfaces", {})
        return data.get("interfaces", [])

    async def get_firewall_rules(self):
        """Get mock firewall rules"""
        data = self.mock_data.get("firewall_rules", {})
        return data.get("rules", [])

    async def get_firewall_logs(self, limit: int = 500) -> list[dict[str, Any]]:
        """Get mock firewall logs"""
        logger.info(f"Mock API keys available: {list(self.mock_data.keys())}")
        data = self.mock_data.get("firewall_logs", {})

        log_keys = list(data.keys()) if data else "None"
        logger.info(f"Mock API firewall_logs data keys: {log_keys}")

        logs = data.get("logs", [])
        logger.info(f"Retrieved {len(logs)} raw logs, limit={limit}")
        return logs[:limit] if limit else logs

    async def get_dhcpv4_leases(self):
        """Get mock DHCPv4 leases"""
        data = self.mock_data.get("dhcp_leases", {})
        return data.get("v4", [])

    async def get_dhcpv6_leases(self):
        """Get mock DHCPv6 leases"""
        data = self.mock_data.get("dhcp_leases", {})
        return data.get("v6", [])

    async def search_arp_table(self, query: str):
        """Search mock ARP table"""
        entries = await self.get_arp_table()
        return [
            entry
            for entry in entries
            if query.lower() in entry.get("ip", "").lower()
            or query.lower() in entry.get("mac", "").lower()
            or query.lower() in entry.get("hostname", "").lower()
        ]

    async def search_ndp_table(self, query: str):
        """Search mock NDP table - empty for now"""
        return []

    async def search_firewall_logs(self, ip: str, row_count: int = 50):
        """Search mock firewall logs for a specific IP"""
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
