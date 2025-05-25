#!/usr/bin/env python3
"""
OPNsense MCP Integration Tester.

This script provides comprehensive testing for all MCP tools and validates
their integration with the OPNsense API.
"""

import argparse
import asyncio
import importlib
import sys
from pathlib import Path
from typing import Any

import yaml

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from opnsense_mcp.utils.logging import setup_logging

logger = setup_logging()


def load_config(config_path: str) -> dict[str, Any]:
    """Load configuration from YAML file."""
    try:
        with Path(config_path).open() as f:
            config = yaml.safe_load(f)

        # Validate required fields
        required_fields = ["api_key", "api_secret", "firewall_host"]
        missing_fields = [f for f in required_fields if f not in config]
        if missing_fields:
            error_msg = (
                f"Config file missing required fields: "
                f"{missing_fields}. Required: {required_fields}"
            )
            raise ValueError(error_msg)

    except Exception as e:
        logger.exception("Failed to load config")
        raise ValueError(f"Failed to load config: {e}") from None
    else:
        return config


async def run_tool_tests(client, tool_name: str = None) -> bool:
    """Run tests for all tools or a specific tool."""
    tools = {
        # Network tools
        "system": ("SystemTool", "opnsense_mcp.tools.system"),
        "arp": ("ArpTool", "opnsense_mcp.tools.arp"),
        "interface": ("InterfaceTool", "opnsense_mcp.tools.interface"),
        "firewall": ("FirewallTool", "opnsense_mcp.tools.firewall"),
        "service": ("ServiceTool", "opnsense_mcp.tools.service"),
        "vpn": ("VpnTool", "opnsense_mcp.tools.vpn"),
        "dns": ("DnsTool", "opnsense_mcp.tools.dns"),
        "traffic": ("TrafficTool", "opnsense_mcp.tools.traffic"),
        "ids": ("IdsTool", "opnsense_mcp.tools.ids"),
        "certificate": ("CertificateTool", "opnsense_mcp.tools.certificate"),
    }

    if tool_name:
        if tool_name not in tools:
            logger.error(f"Unknown tool: {tool_name}")
            return False

        class_name, module_path = tools[tool_name]
        return await test_specific_tool(client, tool_name, class_name, module_path)

    # Test all tools
    success_count = 0
    total_count = len(tools)

    for tool_name, (class_name, module_path) in tools.items():
        success = await test_specific_tool(client, tool_name, class_name, module_path)
        if success:
            success_count += 1

    logger.info(f"Overall: {success_count}/{total_count} tools passed")
    return success_count == total_count


async def test_specific_tool(
    client, tool_name: str, tool_class_name: str, tool_module: str
) -> bool:
    """Test a specific tool."""
    try:
        # Import the tool module
        module = importlib.import_module(tool_module)
        tool_class = getattr(module, tool_class_name)

        # Initialize the tool
        tool = tool_class(client)

        logger.info(f"\n{'=' * 60}")
        logger.info(f"Testing {tool_name} tool")
        logger.info(f"{'=' * 60}")

        # Run tool-specific tests
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
        logger.exception(f"Failed to test {tool_name} tool")
        return False


async def test_system_tool(tool) -> bool:
    """Test the system tool."""
    logger.info("Testing system status...")
    status = await tool.execute({"action": "status"})
    if not status:
        logger.error("Failed to get system status")
        return False

    logger.info(
        f"System status: CPU: {status.get('cpu_usage')}%, "
        f"Memory: {status.get('memory_usage')}%"
    )
    logger.info(f"OPNsense version: {status.get('versions', {}).get('opnsense')}")
    return True


async def test_arp_tool(tool) -> bool:
    """Test the ARP tool."""
    logger.info("Testing ARP table...")
    arp = await tool.execute({"action": "list"})
    if not arp:
        logger.error("Failed to get ARP table")
        return False

    logger.info(f"Found {len(arp)} ARP entries")

    logger.info("Testing NDP table...")
    ndp = await tool.execute({"action": "ndp"})
    if not ndp:
        logger.error("Failed to get NDP table")
        return False

    logger.info(f"Found {len(ndp)} NDP entries")
    return True


async def test_interface_tool(tool) -> bool:
    """Test the interface tool."""
    logger.info("Testing interface list...")
    interfaces = await tool.execute({"action": "list"})
    if not interfaces:
        logger.error("Failed to get interface list")
        return False

    logger.info(f"Found {len(interfaces.get('interfaces', []))} interfaces")

    # If interfaces are found, test getting details
    if interfaces.get("interfaces"):
        first_interface = list(interfaces["interfaces"].keys())[0]
        details = await tool.execute(
            {"action": "details", "interface": first_interface}
        )
        if details:
            if_name = first_interface
            status = details.get("interface", {}).get("status", "unknown")
            logger.info(f"Interface {if_name} status: {status}")
    return True


async def test_firewall_tool(tool) -> bool:
    """Test the firewall tool."""
    logger.info("Testing firewall rules...")
    rules = await tool.execute({"action": "rules"})
    if not rules:
        logger.error("Failed to get firewall rules")
        return False

    logger.info(f"Found {len(rules)} firewall rules")

    logger.info("Testing firewall status...")
    status = await tool.execute({"action": "status"})
    if status:
        logger.info(f"Firewall status: {status}")
    return True


async def test_service_tool(tool) -> bool:
    """Test the service tool."""
    logger.info("Testing service list...")
    services = await tool.execute({"action": "list"})
    if not services:
        logger.error("Failed to get service list")
        return False

    logger.info(f"Found {len(services.get('services', []))} services")

    # If services are found, test getting details
    if services.get("services"):
        first_service = list(services["services"].keys())[0]
        details = await tool.execute({"action": "details", "service": first_service})
        if details:
            logger.info(f"Service {first_service} details retrieved")
    return True


async def test_vpn_tool(tool) -> bool:
    """Test the VPN tool."""
    logger.info("Testing OpenVPN instances...")
    openvpn = await tool.execute({"action": "list", "type": "openvpn"})
    if openvpn is None:
        logger.error("Failed to get VPN instances")
        return False

    logger.info(f"Found {len(openvpn)} OpenVPN instances")

    logger.info("Testing WireGuard instances...")
    wireguard = await tool.execute({"action": "list", "type": "wireguard"})
    if wireguard is not None:
        logger.info(f"Found {len(wireguard)} WireGuard instances")
    return True


async def test_dns_tool(tool) -> bool:
    """Test the DNS tool."""
    logger.info("Testing DNS resolver config...")
    resolver = await tool.execute({"action": "resolver"})
    if not resolver:
        logger.error("Failed to get DNS resolver config")
        return False

    logger.info("DNS resolver config retrieved")

    logger.info("Testing DNS records...")
    records = await tool.execute({"action": "records"})
    if records:
        logger.info(f"Found {len(records)} DNS records")
    return True


async def test_traffic_tool(tool) -> bool:
    """Test the traffic shaper tool."""
    logger.info("Testing traffic shaper status...")
    status = await tool.execute({"action": "status"})
    if status is None:
        logger.error("Failed to get traffic shaper status")
        return False

    logger.info(f"Traffic shaper status: {status.get('enabled', 'unknown')}")
    return True


async def test_ids_tool(tool) -> bool:
    """Test the IDS tool."""
    logger.info("Testing IDS status...")
    status = await tool.execute({"action": "status"})
    if status is None:
        logger.error("Failed to get IDS status")
        return False

    logger.info(f"IDS status: {status.get('enabled', 'unknown')}")

    logger.info("Testing IDS alerts...")
    alerts = await tool.execute({"action": "alerts", "limit": 5})
    if alerts is not None:
        logger.info(f"Found {len(alerts)} IDS alerts")
    return True


async def test_certificate_tool(tool) -> bool:
    """Test the certificate tool."""
    logger.info("Testing certificate list...")
    certs = await tool.execute({"action": "list"})
    if certs is None:
        logger.error("Failed to get certificate list")
        return False

    logger.info(f"Found {len(certs)} certificates")
    return True


async def main() -> None:
    """Provide entry point for the integration tester."""
    parser = argparse.ArgumentParser(description="OPNsense MCP integration tester")
    parser.add_argument(
        "--config",
        type=str,
        default=str(Path(__file__).parent / "vars" / "key.yaml"),
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
        help="Test only a specific tool",
    )

    args = parser.parse_args()

    # Resolve config path
    if not Path(args.config).exists():
        logger.error(f"Config file not found: {args.config}")
        sys.exit(1)

    try:
        # Load configuration
        config = load_config(args.config)

        # Initialize API client
        from opnsense_mcp.utils.api import OPNsenseClient

        client = OPNsenseClient(
            api_key=config["api_key"],
            api_secret=config["api_secret"],
            firewall_host=config["firewall_host"],
            verify_ssl=config.get("verify_ssl", False),
        )

        # Run tests
        success = await run_tool_tests(client, args.tool)

        if success:
            logger.info("\n✅ All tests passed!")
            sys.exit(0)

        logger.error("\n❌ Some tests failed!")
        sys.exit(1)

    except Exception:
        logger.exception("Integration test failed")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
