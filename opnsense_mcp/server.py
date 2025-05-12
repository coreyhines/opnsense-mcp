#!/usr/bin/env python3
"""
Final MCP server that handles tools/list method specifically
with real OPNsense API integration for ARP data
"""
import json
import sys
import logging
import ssl
import asyncio
import requests
import os
from typing import Dict, Any, List
from dotenv import load_dotenv
from urllib3.exceptions import InsecureRequestWarning
from opnsense_mcp.tools.lldp import LLDPTool
from opnsense_mcp.tools.dhcp import DHCPTol
from opnsense_mcp.tools.system import SystemTool
from opnsense_mcp.tools.firewall import FirewallTool

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("final_mcp")

# Suppress insecure request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Load environment variables for OPNsense API
home_env = os.path.expanduser("~/.opnsense-env")
project_env = os.path.join(os.path.dirname(__file__), "..", ".opnsense-env")
if os.path.exists(home_env):
    load_dotenv(home_env, override=True)
    logger.info(f"Loaded environment from {home_env}")
else:
    load_dotenv(project_env, override=True)
    logger.info(f"Loaded environment from {project_env}")


class OPNsenseClient:
    def __init__(self):
        # Get API credentials from environment
        self.api_key = os.getenv("OPNSENSE_API_KEY")
        self.api_secret = os.getenv("OPNSENSE_API_SECRET")
        self.api_host = os.getenv("OPNSENSE_API_HOST", "").rstrip("/")

        if not all([self.api_key, self.api_secret, self.api_host]):
            logger.warning("Missing OPNsense API credentials")
            self.is_configured = False
        else:
            self.is_configured = True
            self.setup_ssl()
            self.headers = {"Authorization": f"Basic {self._get_basic_auth()}"}
            logger.info(f"OPNsense API client initialized for {self.api_host}")

    def _get_basic_auth(self) -> str:
        """Create basic auth header from api key and secret"""
        import base64

        auth_str = f"{self.api_key}:{self.api_secret}"
        return base64.b64encode(auth_str.encode()).decode()

    def setup_ssl(self):
        """Configure SSL context for API calls"""
        _create_unverified_https_context = ssl._create_unverified_context
        ssl._create_default_https_context = _create_unverified_https_context

    async def get_arp_table(self) -> List[Dict[str, Any]]:
        """Get ARP table from OPNsense"""
        if not self.is_configured:
            logger.warning(
                "OPNsense API not configured, " "returning dummy ARP " "data"
            )
            return [
                {
                    "ip": "192.168.1.1",
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "intf": "em0",
                }
            ]

        try:
            url = f"{self.api_host}/api/diagnostics/interface/get_arp"
            response = requests.get(url, headers=self.headers, verify=False)
            response.raise_for_status()
            data = response.json()

            # Extract entries from the response
            entries = []

            # Handle different response formats
            if isinstance(data, list):
                # Direct list of entries
                for entry in data:
                    entries.append(
                        {
                            "ip": entry.get("ip", ""),
                            "mac": entry.get("mac", ""),
                            "intf": entry.get("intf", ""),
                            "manufacturer": entry.get("manufacturer", ""),
                        }
                    )
            elif isinstance(data, dict) and "rows" in data:
                # Dict with 'rows' field
                for entry in data.get("rows", []):
                    entries.append(
                        {
                            "ip": entry.get("ip", ""),
                            "mac": entry.get("mac", ""),
                            "intf": entry.get("intf", ""),
                            "manufacturer": entry.get("manufacturer", ""),
                        }
                    )
            else:
                logger.warning(f"Unexpected ARP table format: {data}")

            return entries
        except Exception as e:
            logger.error(f"Failed to get ARP table: {str(e)}")
            return [
                {
                    "ip": "192.168.1.1",
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "intf": "em0",
                }
            ]

    async def get_ndp_table(self) -> List[Dict[str, Any]]:
        """Get NDP table from OPNsense"""
        if not self.is_configured:
            logger.warning("OPNsense API not configured, returning dummy NDP data")
            return [
                {
                    "ip": "fe80::1",
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "intf": "em0",
                }
            ]

        try:
            url = f"{self.api_host}/api/diagnostics/interface/get_ndp"
            response = requests.get(url, headers=self.headers, verify=False)
            response.raise_for_status()
            data = response.json()

            # Extract entries from the response
            entries = []

            # Handle different response formats
            if isinstance(data, list):
                # Direct list of entries
                for entry in data:
                    entries.append(
                        {
                            "ip": entry.get("ip", ""),
                            "mac": entry.get("mac", ""),
                            "intf": entry.get("intf", ""),
                            "manufacturer": entry.get("manufacturer", ""),
                        }
                    )
            elif isinstance(data, dict) and "rows" in data:
                # Dict with 'rows' field
                for entry in data.get("rows", []):
                    entries.append(
                        {
                            "ip": entry.get("ip", ""),
                            "mac": entry.get("mac", ""),
                            "intf": entry.get("intf", ""),
                            "manufacturer": entry.get("manufacturer", ""),
                        }
                    )
            else:
                logger.warning(f"Unexpected NDP table format: {data}")

            return entries
        except Exception as e:
            logger.error(f"Failed to get NDP table: {str(e)}")
            return [
                {
                    "ip": "fe80::1",
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "intf": "em0",
                }
            ]

    async def get_lldp_table(self) -> List[Dict[str, Any]]:
        """Get LLDP neighbor table from OPNsense (lldpd plugin)"""
        if not self.is_configured:
            logger.warning("OPNsense API not configured, " "returning dummy LLDP data")
            return [
                {
                    "intf": "em0",
                    "chassis_id": "00:11:22:33:44:55",
                    "port_id": "1",
                    "system_name": "Dummy Switch-1",
                    "system_description": "Dummy 48-port Gigabit Switch",
                    "port_description": "Uplink Port",
                    "capabilities": "Bridge, Router",
                    "management_address": "192.168.1.2",
                }
            ]
        try:
            url = f"{self.api_host}/api/lldpd/service/neighbor"
            response = requests.get(url, headers=self.headers, verify=False)
            response.raise_for_status()
            data = response.json()
            # Parse the plain text response
            neighbors = []
            text = data.get("response", "")

            # Split by Interface blocks
            for block in text.split("Interface:"):
                block = block.strip()
                if not block or block.startswith("-"):
                    continue
                lines = block.splitlines()
                intf = lines[0].split(",")[0].strip() if lines else ""
                chassis_id = ""
                system_name = ""
                system_description = ""
                management_address = ""
                port_id = ""
                port_description = ""
                capabilities = []
                for line in lines:
                    if "ChassisID:" in line:
                        chassis_id = (
                            line.split("ChassisID:")[-1].strip().replace("mac ", "")
                        )
                    elif "SysName:" in line:
                        system_name = line.split("SysName:")[-1].strip()
                    elif "SysDescr:" in line:
                        system_description = line.split("SysDescr:")[-1].strip()
                    elif "MgmtIP:" in line:
                        management_address = line.split("MgmtIP:")[-1].strip()
                    elif "PortID:" in line:
                        port_id = (
                            line.split("PortID:")[-1].strip().replace("ifname ", "")
                        )
                    elif "PortDescr:" in line:
                        port_description = line.split("PortDescr:")[-1].strip()
                    elif "Capability:" in line and ", on" in line:
                        cap = line.split("Capability:")[-1].split(",")[0].strip()
                        capabilities.append(cap)
                if intf:
                    neighbors.append(
                        {
                            "intf": intf,
                            "chassis_id": chassis_id,
                            "port_id": port_id,
                            "system_name": system_name,
                            "system_description": system_description,
                            "port_description": port_description,
                            "capabilities": ", ".join(capabilities),
                            "management_address": management_address,
                        }
                    )
            return neighbors
        except Exception as e:
            logger.error(f"Failed to get LLDP table: {str(e)}")
            return [
                {
                    "intf": "em0",
                    "chassis_id": "00:11:22:33:44:55",
                    "port_id": "1",
                    "system_name": "Dummy Switch-1",
                    "system_description": "Dummy 48-port Gigabit Switch",
                    "port_description": "Uplink Port",
                    "capabilities": "Bridge, Router",
                    "management_address": "192.168.1.2",
                }
            ]

    async def get_dhcpv4_leases(self) -> list[dict]:
        """Get DHCPv4 lease table from OPNsense"""
        if not self.is_configured:
            logger.warning("OPNsense API not configured, returning dummy DHCP data")
            return [
                {
                    "ip": "192.168.1.100",
                    "mac": "00:11:22:33:44:55",
                    "hostname": "dummy-client",
                    "start": "2025-01-01T00:00:00",
                    "end": "2025-01-01T12:00:00",
                    "online": True,
                    "lease_type": "dynamic",
                    "description": ("Dummy lease entry"),
                }
            ]
        try:
            url = f"{self.api_host}/api/dhcpv4/leases/search_lease"
            response = requests.get(url, headers=self.headers, verify=False)
            response.raise_for_status()
            data = response.json()
            entries = []
            # Handle both list and dict-with-rows formats
            if isinstance(data, list):
                entries = data
            elif isinstance(data, dict) and "rows" in data:
                entries = data["rows"]
            else:
                logger.warning(f"Unexpected DHCP lease format: {data}")
            return entries
        except Exception as e:
            logger.error(f"Failed to get DHCPv4 leases: {str(e)}")
            return [
                {
                    "ip": "192.168.1.100",
                    "mac": "00:11:22:33:44:55",
                    "hostname": "dummy-client",
                    "start": "2025-01-01T00:00:00",
                    "end": "2025-01-01T12:00:00",
                    "online": True,
                    "lease_type": "dynamic",
                    "description": ("Dummy lease entry"),
                }
            ]

    async def get_dhcpv6_leases(self) -> list[dict]:
        """Get DHCPv6 lease table from OPNsense"""
        if not self.is_configured:
            logger.warning(
                "OPNsense API not configured, " "returning dummy DHCPv6 data"
            )
            return [
                {
                    "ip": "2001:db8::100",
                    "mac": "00:11:22:33:44:66",
                    "hostname": "dummy6-client",
                    "start": "2025-01-01T00:00:00",
                    "end": "2025-01-01T12:00:00",
                    "online": True,
                    "lease_type": "dynamic",
                    "description": "Dummy DHCPv6 lease entry",
                }
            ]
        try:
            url = f"{self.api_host}/api/dhcpv6/leases/search_lease"
            response = requests.get(url, headers=self.headers, verify=False)
            response.raise_for_status()
            data = response.json()
            entries = []
            # Handle both list and dict-with-rows formats
            if isinstance(data, list):
                entries = data
            elif isinstance(data, dict) and "rows" in data:
                entries = data["rows"]
            else:
                logger.warning(f"Unexpected DHCPv6 lease format: {data}")
            return entries
        except Exception as e:
            logger.error(f"Failed to get DHCPv6 leases: {str(e)}")
            return [
                {
                    "ip": "2001:db8::100",
                    "mac": "00:11:22:33:44:66",
                    "hostname": "dummy6-client",
                    "start": "2025-01-01T00:00:00",
                    "end": "2025-01-01T12:00:00",
                    "online": True,
                    "lease_type": "dynamic",
                    "description": "Dummy DHCPv6 lease entry",
                }
            ]


class ARPTool:
    """ARP tool implementation that connects to OPNsense API"""

    def __init__(self, client):
        self.client = client

    async def execute(self, filter_value=None) -> Dict[str, Any]:
        """Execute ARP/NDP table lookup with optional IP or MAC filter"""
        try:
            # Get both ARP and NDP tables
            arp_entries = await self.client.get_arp_table()
            ndp_entries = await self.client.get_ndp_table()

            # Apply filter if provided
            if filter_value:
                # Determine if filter_value is a MAC or IP
                is_mac = False
                val = filter_value.lower()
                if (len(val.split(":")) == 6 or len(val.split("-")) == 6) and all(
                    len(x) == 2 for x in val.replace("-", ":").split(":")
                ):
                    is_mac = True
                if is_mac:
                    arp_entries = [
                        entry
                        for entry in arp_entries
                        if val == entry.get("mac", "").lower()
                    ]
                    ndp_entries = [
                        entry
                        for entry in ndp_entries
                        if val == entry.get("mac", "").lower()
                    ]
                else:
                    arp_entries = [
                        entry
                        for entry in arp_entries
                        if filter_value in entry.get("ip", "")
                    ]
                    ndp_entries = [
                        entry
                        for entry in ndp_entries
                        if filter_value in entry.get("ip", "")
                    ]

            return {
                "arp": arp_entries,
                "ndp": ndp_entries,
                "status": "success",
            }
        except Exception as e:
            logger.error(f"Failed to get ARP/NDP tables: {str(e)}")
            # Fallback to dummy data on error
            return self._get_dummy_data(filter_value)

    def _get_dummy_data(self, filter_value=None) -> Dict[str, Any]:
        """Return dummy data for testing"""
        dummy_data = {
            "arp": [
                {
                    "ip": "192.168.1.1",
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "intf": "em0",
                    "manufacturer": "TestCorp",
                },
                {
                    "ip": "10.0.2.1",
                    "mac": "00:11:22:33:44:55",
                    "intf": "em1",
                    "manufacturer": "RouterCorp",
                },
            ],
            "ndp": [
                {
                    "ip": "fe80::1",
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "intf": "em0",
                    "manufacturer": "TestCorp",
                }
            ],
            "status": "success",
        }

        # Apply filter if provided
        if filter_value:
            dummy_data["arp"] = [
                entry for entry in dummy_data["arp"] if filter_value in entry["ip"]
            ]
            dummy_data["ndp"] = [
                entry for entry in dummy_data["ndp"] if filter_value in entry["ip"]
            ]

        return dummy_data


async def main():
    # Initialize OPNsense client
    client = OPNsenseClient()

    # Initialize ARPTool, LLDPTool, DHCPTol, SystemTool, and FirewallTool with client
    arp_tool = ARPTool(client)
    lldp_tool = LLDPTool(client)
    dhcp_tool = DHCPTol(client)
    system_tool = SystemTool(client)
    firewall_tool = FirewallTool(client)

    # ARP tool definition with complete schema
    arp_tool_schema = {
        "id": "arp",
        "name": "arp",
        "description": "Show ARP/NDP table",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {
                    "type": "string",
                    "description": "Filter by IP address",
                },
                "mac": {
                    "type": "string",
                    "description": "Filter by MAC address",
                },
            },
            "required": [],
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "arp": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "ip": {"type": "string"},
                            "mac": {"type": "string"},
                            "intf": {"type": "string"},
                            "manufacturer": {"type": "string"},
                        },
                    },
                },
                "ndp": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "ip": {"type": "string"},
                            "mac": {"type": "string"},
                            "intf": {"type": "string"},
                            "manufacturer": {"type": "string"},
                        },
                    },
                },
                "status": {"type": "string"},
            },
        },
    }

    lldp_tool_schema = {
        "id": "lldp",
        "name": "lldp",
        "description": "Show LLDP neighbor table",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
        "outputSchema": {
            "type": "object",
            "properties": {
                "lldp": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "intf": {"type": "string"},
                            "chassis_id": {"type": "string"},
                            "port_id": {"type": "string"},
                            "system_name": {"type": "string"},
                            "system_description": {"type": "string"},
                            "port_description": {"type": "string"},
                            "capabilities": {"type": "string"},
                            "management_address": {"type": "string"},
                        },
                    },
                },
                "status": {"type": "string"},
            },
        },
    }

    dhcp_tool_schema = {
        "id": "dhcp",
        "name": "dhcp",
        "description": "Show DHCPv4 and DHCPv6 lease tables",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
        "outputSchema": {
            "type": "object",
            "properties": {
                "dhcpv4": {
                    "type": "array",
                    "items": {"type": "object"},
                },
                "dhcpv6": {
                    "type": "array",
                    "items": {"type": "object"},
                },
                "status": {"type": "string"},
            },
        },
    }

    system_tool_schema = {
        "id": "system",
        "name": "system",
        "description": "Show OPNsense system status",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
        "outputSchema": {
            "type": "object",
            "properties": {
                "cpu_usage": {"type": "number"},
                "memory_usage": {"type": "number"},
                "filesystem_usage": {"type": "object"},
                "uptime": {"type": "string"},
                "versions": {"type": "object"},
            },
        },
    }

    firewall_tool_schema = {
        "id": "firewall",
        "name": "firewall",
        "description": "Show OPNsense firewall rules",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
        "outputSchema": {
            "type": "object",
            "properties": {
                "rules": {"type": "array", "items": {"type": "object"}},
                "status": {"type": "string"},
            },
        },
    }

    # Send ready message
    ready = {
        "jsonrpc": "2.0",
        "method": "ready",
        "params": {
            "name": "OPNsense MCP",
            "version": "1.0.0",
            "protocolVersion": "2024-11-05",
        },
    }
    print(json.dumps(ready), flush=True)
    logger.info("Server ready message sent")

    # Process requests
    while True:
        line = sys.stdin.readline().strip()
        if not line:
            logger.info("Empty line received, exiting")
            break

        try:
            logger.info(f"RAW INPUT: {line}")
            message = json.loads(line)

            # Log the full message for debugging
            logger.info(f"RECEIVED: {json.dumps(message, indent=2)}")

            method = message.get("method", "")
            msg_id = message.get("id")

            logger.info(f"Processing method: {method}, id: {msg_id}")

            # HANDLE INITIALIZE
            if method == "initialize":
                response = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "name": "OPNsense MCP",
                        "version": "1.0.0",
                        "protocolVersion": "2024-11-05",
                        "serverInfo": {
                            "name": "OPNsense MCP",
                            "version": "1.0.0",
                        },
                        "capabilities": {
                            "tools": {"enabled": True, "version": "1.0.0"},
                            "prompts": {"enabled": False, "version": "1.0.0"},
                            "resources": {"enabled": True, "version": "1.0.0"},
                            "logging": {"enabled": False, "version": "1.0.0"},
                            "roots": {
                                "listChanged": False,
                                "version": "1.0.0",
                            },
                        },
                    },
                }
                print(json.dumps(response), flush=True)
                logger.info(f"SENT: {json.dumps(response, indent=2)}")

            # HANDLE NOTIFICATIONS (special handling with no result/id)
            elif method.startswith("notifications/"):
                # For notifications, just return empty object with no id/result
                response = {"jsonrpc": "2.0"}
                print(json.dumps(response), flush=True)
                logger.info(f"SENT: {json.dumps(response, indent=2)}")

            # HANDLE TOOLS/LIST (this is what Cursor actually sends)
            elif method == "tools/list":
                response = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "tools": [
                            arp_tool_schema,
                            lldp_tool_schema,
                            dhcp_tool_schema,
                            system_tool_schema,
                            firewall_tool_schema,
                        ]
                    },
                }
                print(json.dumps(response), flush=True)
                logger.info(f"SENT: {json.dumps(response, indent=2)}")
                logger.info("Sent tools list")

            # HANDLE TOOLS/CALL (this is what Cursor actually sends for tool execution)
            elif method == "tools/call":
                tool_name = message.get("params", {}).get("name")
                arguments = message.get("params", {}).get("arguments", {})
                logger.info(f"Execute tool: {tool_name} with arguments: {arguments}")

                if tool_name == "arp":
                    # Accept both 'ip' and 'mac' as arguments
                    filter_value = arguments.get("mac") or arguments.get("ip")

                    # Get real ARP data with optional filter
                    result = await arp_tool.execute(filter_value)

                    # Format the response with content objects as expected by Cursor
                    content = [
                        {"text": "# ARP/NDP Table", "type": "text"},
                        {"text": "", "type": "text"},
                    ]

                    # Add filter info if provided
                    if filter_value:
                        content.append(
                            {
                                "text": f"Filtering by: {filter_value}",
                                "type": "text",
                            }
                        )
                        content.append({"text": "", "type": "text"})

                    # Add ARP entries section title if we have entries
                    if result.get("arp"):
                        content.append({"text": "## IPv4 ARP Entries", "type": "text"})
                        content.append({"text": "", "type": "text"})

                        # Add ARP entries
                        for entry in result.get("arp", []):
                            line = (
                                f"- {entry.get('ip')} at {entry.get('mac')} "
                                f"on {entry.get('intf')}"
                            )
                            if entry.get("manufacturer"):
                                line += f" ({entry.get('manufacturer')})"
                            content.append({"text": line, "type": "text"})
                    else:
                        content.append(
                            {
                                "text": "## No matching IPv4 ARP entries found",
                                "type": "text",
                            }
                        )
                        content.append({"text": "", "type": "text"})

                    # Add NDP entries section title if we have entries
                    content.append({"text": "", "type": "text"})
                    if result.get("ndp"):
                        content.append({"text": "## IPv6 NDP Entries", "type": "text"})
                        content.append({"text": "", "type": "text"})

                        for entry in result.get("ndp", []):
                            line = (
                                f"- {entry.get('ip')} at {entry.get('mac')} "
                                f"on {entry.get('intf')}"
                            )
                            if entry.get("manufacturer"):
                                line += f" ({entry.get('manufacturer')})"
                            content.append({"text": line, "type": "text"})
                    else:
                        content.append(
                            {
                                "text": "## No matching IPv6 NDP entries found",
                                "type": "text",
                            }
                        )
                        content.append({"text": "", "type": "text"})

                    response = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "result": {"content": content},
                    }
                    print(json.dumps(response), flush=True)
                    logger.info(f"SENT: {json.dumps(response, indent=2)}")
                elif tool_name == "lldp":
                    result = await lldp_tool.execute(arguments)
                    content = [
                        {"text": "# LLDP Neighbor Table", "type": "text"},
                        {"text": "", "type": "text"},
                    ]
                    if result.get("lldp"):
                        content.append({"text": "## LLDP Entries", "type": "text"})
                        content.append({"text": "", "type": "text"})
                        for entry in result["lldp"]:
                            line = (
                                f"- {entry.get('intf')} neighbor "
                                f"{entry.get('system_name')} "
                                f"(chassis {entry.get('chassis_id')}, "
                                f"port {entry.get('port_id')})"
                            )
                            if entry.get("system_description"):
                                line += f" - {entry.get('system_description')}"
                            if entry.get("port_description"):
                                line += f" [{entry.get('port_description')}]"
                            if entry.get("capabilities"):
                                line += f" [{entry.get('capabilities')}]"
                            if entry.get("management_address"):
                                line += f" mgmt: {entry.get('management_address')}"
                            content.append({"text": line, "type": "text"})
                    else:
                        content.append(
                            {
                                "text": "## No LLDP entries found",
                                "type": "text",
                            }
                        )
                    response = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "result": {"content": content},
                    }
                    print(json.dumps(response), flush=True)
                    logger.info(f"SENT: {json.dumps(response, indent=2)}")
                elif tool_name == "dhcp":
                    result = await dhcp_tool.execute(arguments)
                    content = [
                        {"text": "# DHCP Lease Tables", "type": "text"},
                        {"text": "", "type": "text"},
                    ]
                    if result.get("dhcpv4"):
                        content.append({"text": "## DHCPv4 Leases", "type": "text"})
                        content.append({"text": "", "type": "text"})
                        for entry in result["dhcpv4"]:
                            line = (
                                f"- {entry.get('ip')} ({entry.get('mac')}) "
                                f"{entry.get('hostname', '')} "
                                f"{entry.get('lease_type', '')} "
                                f"{entry.get('description', '')}"
                            )
                            content.append({"text": line, "type": "text"})
                    else:
                        content.append(
                            {"text": "No DHCPv4 leases found", "type": "text"}
                        )
                    content.append({"text": "", "type": "text"})
                    if result.get("dhcpv6"):
                        content.append({"text": "## DHCPv6 Leases", "type": "text"})
                        content.append({"text": "", "type": "text"})
                        for entry in result["dhcpv6"]:
                            line = (
                                f"- {entry.get('ip')} ({entry.get('mac')}) "
                                f"{entry.get('hostname', '')} "
                                f"{entry.get('lease_type', '')} "
                                f"{entry.get('description', '')}"
                            )
                            content.append({"text": line, "type": "text"})
                    else:
                        content.append(
                            {"text": "No DHCPv6 leases found", "type": "text"}
                        )
                    response = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "result": {"content": content},
                    }
                    print(json.dumps(response), flush=True)
                    logger.info(f"SENT: {json.dumps(response, indent=2)}")
                elif tool_name == "system":
                    result = await system_tool.execute(arguments)
                    content = [
                        {"text": "# OPNsense System Status", "type": "text"},
                        {"text": f"CPU Usage: {result.get('cpu_usage', 0.0)}%", "type": "text"},
                        {"text": f"Memory Usage: {result.get('memory_usage', 0.0)}%", "type": "text"},
                        {"text": f"Uptime: {result.get('uptime', '')}", "type": "text"},
                        {"text": "", "type": "text"},
                        {"text": "## Filesystem Usage", "type": "text"},
                    ]
                    for mount, usage in result.get("filesystem_usage", {}).items():
                        content.append({"text": f"- {mount}: {usage}% used", "type": "text"})
                    content.append({"text": "", "type": "text"})
                    content.append({"text": "## Versions", "type": "text"})
                    for k, v in result.get("versions", {}).items():
                        content.append({"text": f"- {k}: {v}", "type": "text"})
                    response = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "result": {"content": content},
                    }
                    print(json.dumps(response), flush=True)
                    logger.info(f"SENT: {json.dumps(response, indent=2)}")
                elif tool_name == "firewall":
                    result = await firewall_tool.execute(arguments)
                    content = [
                        {"text": "# OPNsense Firewall Rules", "type": "text"},
                        {"text": "", "type": "text"},
                    ]
                    for rule in result.get("rules", []):
                        line = (
                            f"- Rule {rule.get('id')}: {rule.get('description', '')} | "
                            f"Interface: {rule.get('interface', '')} | "
                            f"Action: {rule.get('action', '')} | "
                            f"Enabled: {rule.get('enabled', False)}"
                        )
                        content.append({"text": line, "type": "text"})
                    if not result.get("rules"):
                        content.append({"text": "No firewall rules found.", "type": "text"})
                    response = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "result": {"content": content},
                    }
                    print(json.dumps(response), flush=True)
                    logger.info(f"SENT: {json.dumps(response, indent=2)}")
                else:
                    error = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": -32601,
                            "message": f"Tool not found: {tool_name}",
                        },
                    }
                    print(json.dumps(error), flush=True)
                    logger.info(f"SENT: {json.dumps(error, indent=2)}")

            # DEFAULT FALLBACK
            else:
                response = {"jsonrpc": "2.0", "id": msg_id, "result": {}}
                print(json.dumps(response), flush=True)
                logger.info(f"SENT: {json.dumps(response, indent=2)}")

        except Exception as e:
            logger.error(f"Error: {e}", exc_info=True)
            # Continue processing


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server terminated by keyboard interrupt")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
