#!/usr/bin/env python3
"""
Integration script for new OPNsense API tools with MCP server.
This script sets up the MCP server with all the enhanced API tools
and allows for easy testing of individual components.
"""

import argparse
import asyncio
import logging
import os
import sys

import yaml

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def load_config(config_path):
    """Load configuration from YAML file"""
    try:
        with open(config_path) as f:
            return yaml.safe_load(f)
    except Exception:
        logger.exception("Failed to load config")
        sys.exit(1)


async def run_tool_tests(client, tool_name=None):
    """Run tests for all tools or a specific tool"""
    tools = {
        # Network tools
        "arp": ("ARPTool", "mcp_server.tools.arp_new"),
        "interface": ("InterfaceTool", "mcp_server.tools.interface_new"),
        # Security tools
        "firewall": ("FirewallTool", "mcp_server.tools.firewall_new"),
        "ids": ("IDSTool", "mcp_server.tools.ids_new"),
        # System tools
        "system": ("SystemTool", "mcp_server.tools.system_new"),
        "service": ("ServiceTool", "mcp_server.tools.service_new"),
        # VPN tools
        "vpn": ("VPNTool", "mcp_server.tools.vpn_new"),
        # Certificate management
        "certificate": ("CertificateTool", "mcp_server.tools.certificate_new"),
        # DNS management
        "dns": ("DNSTool", "mcp_server.tools.dns_new"),
        # Traffic shaping
        "traffic": ("TrafficShaperTool", "mcp_server.tools.traffic_new"),
    }

    # If a specific tool was requested, test only that one
    if tool_name:
        if tool_name not in tools:
            logger.error(f"Unknown tool: {tool_name}")
            return False

        tool_class_name, tool_module = tools[tool_name]
        return await test_specific_tool(client, tool_name, tool_class_name, tool_module)

    # Otherwise test all tools
    results = {}
    for name, (tool_class_name, tool_module) in tools.items():
        logger.info(f"Testing {name} tool...")
        result = await test_specific_tool(client, name, tool_class_name, tool_module)
        results[name] = "SUCCESS" if result else "FAILURE"

    # Print summary
    logger.info("\n===== TEST SUMMARY =====")
    for name, status in results.items():
        logger.info(f"{name:15} : {status}")

    return all(status == "SUCCESS" for status in results.values())


async def test_specific_tool(client, tool_name, tool_class_name, tool_module):
    """Test a specific tool"""
    try:
        # Import the tool module
        module = __import__(tool_module, fromlist=[tool_class_name])
        tool_class = getattr(module, tool_class_name)

        # Initialize the tool
        tool = tool_class(client)

        # Run specific test based on the tool type
        if tool_name == "system":
            return await test_system_tool(tool)
        if tool_name == "arp":
            return await test_arp_tool(tool)
        if tool_name == "interface":
            return await test_interface_tool(tool)
        if tool_name == "firewall":
            return await test_firewall_tool(tool)
        if tool_name == "service":
            return await test_service_tool(tool)
        if tool_name == "vpn":
            return await test_vpn_tool(tool)
        if tool_name == "dns":
            return await test_dns_tool(tool)
        if tool_name == "traffic":
            return await test_traffic_tool(tool)
        if tool_name == "ids":
            return await test_ids_tool(tool)
        if tool_name == "certificate":
            return await test_certificate_tool(tool)
        logger.error(f"No test defined for {tool_name}")
        return False

    except Exception:
        logger.exception(f"Error testing {tool_name}")
        return False


async def test_system_tool(tool):
    """Test the system tool"""
    logger.info("Testing system status...")
    status = await tool.execute({"action": "status"})
    logger.info(
        f"System status: CPU: {status.get('cpu_usage')}%, Memory: {status.get('memory_usage')}%"
    )

    logger.info("Testing version info...")
    version = await tool.execute({"action": "version"})
    logger.info(f"OPNsense version: {version.get('version', 'unknown')}")

    return True


async def test_arp_tool(tool):
    """Test the ARP tool"""
    logger.info("Testing ARP table...")
    arp = await tool.execute({"action": "list"})
    logger.info(f"Found {len(arp.get('entries', []))} ARP entries")

    logger.info("Testing NDP table...")
    ndp = await tool.execute({"action": "ndp"})
    logger.info(f"Found {len(ndp.get('entries', []))} NDP entries")

    return True


async def test_interface_tool(tool):
    """Test the interface tool"""
    logger.info("Testing interface list...")
    interfaces = await tool.execute({"action": "list"})
    logger.info(f"Found {len(interfaces.get('interfaces', []))} interfaces")

    # If interfaces are found, test getting details
    if interfaces.get("interfaces"):
        first_if = interfaces["interfaces"][0]
        if_name = first_if.get("name")
        logger.info(f"Testing interface details for {if_name}...")
        details = await tool.execute({"action": "get", "name": if_name})
        logger.info(
            f"Interface {if_name} status: {details.get('interface', {}).get('status', 'unknown')}"
        )

    return True


async def test_firewall_tool(tool):
    """Test the firewall tool"""
    logger.info("Testing firewall rules...")
    rules = await tool.execute({"action": "rules"})
    logger.info(f"Found {len(rules.get('rules', []))} firewall rules")

    logger.info("Testing firewall status...")
    status = await tool.execute({"action": "status"})
    logger.info(f"Firewall status: {status.get('status', 'unknown')}")

    return True


async def test_service_tool(tool):
    """Test the service tool"""
    logger.info("Testing service list...")
    services = await tool.execute({"action": "list"})
    logger.info(f"Found {len(services.get('services', []))} services")

    # If services are found, test getting details
    if services.get("services"):
        first_service = services["services"][0]
        service_id = first_service.get("id")
        logger.info(f"Testing service details for {service_id}...")
        details = await tool.execute({"action": "get", "id": service_id})
        logger.info(
            f"Service status: {details.get('service', {}).get('status', 'unknown')}"
        )

    return True


async def test_vpn_tool(tool):
    """Test the VPN tool"""
    logger.info("Testing OpenVPN instances...")
    openvpn = await tool.execute({"action": "list", "type": "openvpn"})
    logger.info(f"Found {len(openvpn.get('instances', []))} OpenVPN instances")

    logger.info("Testing WireGuard instances...")
    wireguard = await tool.execute({"action": "list", "type": "wireguard"})
    logger.info(f"Found {len(wireguard.get('instances', []))} WireGuard instances")

    return True


async def test_dns_tool(tool):
    """Test the DNS tool"""
    logger.info("Testing DNS resolver config...")
    resolver = await tool.execute({"action": "resolver"})
    logger.info(f"DNS resolver status: {resolver.get('status', 'unknown')}")

    logger.info("Testing DNS records...")
    records = await tool.execute({"action": "records"})
    logger.info(f"Found {len(records.get('records', []))} DNS records")

    return True


async def test_traffic_tool(tool):
    """Test the traffic shaper tool"""
    logger.info("Testing traffic shaper status...")
    status = await tool.execute({"action": "status"})
    logger.info(
        f"Traffic shaper status: {'enabled' if status.get('enabled') else 'disabled'}"
    )

    logger.info("Testing traffic shaper pipes...")
    pipes = await tool.execute({"action": "pipes"})
    logger.info(f"Found {len(pipes.get('pipes', []))} traffic shaper pipes")

    return True


async def test_ids_tool(tool):
    """Test the IDS tool"""
    logger.info("Testing IDS status...")
    status = await tool.execute({"action": "status"})
    logger.info(f"IDS status: {status.get('status', 'unknown')}")

    logger.info("Testing IDS alerts...")
    alerts = await tool.execute({"action": "alerts", "limit": 5})
    logger.info(f"Found {len(alerts.get('alerts', []))} recent IDS alerts")

    return True


async def test_certificate_tool(tool):
    """Test the certificate tool"""
    logger.info("Testing certificate list...")
    certs = await tool.execute({"action": "list"})
    logger.info(f"Found {len(certs.get('certificates', []))} certificates")

    return True


async def main():
    parser = argparse.ArgumentParser(description="OPNsense MCP integration tester")
    parser.add_argument(
        "--config",
        type=str,
        default=os.path.join(os.path.dirname(__file__), "vars/key.yaml"),
        help="Path to config file",
    )
    parser.add_argument(
        "--tool",
        type=str,
        choices=[
            "system",
            "arp",
            "interface",
            "firewall",
            "service",
            "vpn",
            "dns",
            "traffic",
            "ids",
            "certificate",
        ],
        help="Specific tool to test (tests all by default)",
    )
    args = parser.parse_args()

    # Resolve config path
    if not os.path.exists(args.config):
        logger.error(f"Config file not found: {args.config}")
        sys.exit(1)

    # Load config
    config = load_config(args.config)

    # Make sure the config has the expected format
    if not all(k in config for k in ["api_key", "api_secret", "firewall_host"]):
        logger.error(
            "Config file must contain 'api_key', 'api_secret', and 'firewall_host' fields"
        )
        sys.exit(1)

    logger.info(f"Testing OPNsense MCP integration with {config['firewall_host']}")

    # Initialize API client
    from opnsense_mcp.utils.api import OPNsenseClient

    client = OPNsenseClient(config)

    # Run tests
    success = await run_tool_tests(client, args.tool)

    if success:
        logger.info("All tests completed successfully!")
        sys.exit(0)
    else:
        logger.error("Some tests failed. Check the logs for details.")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
