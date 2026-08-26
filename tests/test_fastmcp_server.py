"""Tests for the FastMCP-based Streamable HTTP server."""

import pytest


@pytest.mark.asyncio
async def test_fastmcp_server_imports():
    """fastmcp_server module must be importable."""
    from opnsense_mcp.fastmcp_server import build_mcp_server

    assert build_mcp_server is not None


@pytest.mark.asyncio
async def test_fastmcp_server_lists_tools():
    """Server must expose all expected tools."""
    from fastmcp.client import Client

    from opnsense_mcp.fastmcp_server import build_mcp_server

    mcp = build_mcp_server()
    async with Client(mcp) as client:
        tools = await client.list_tools()

    tool_names = {t.name for t in tools}
    expected = {
        "arp",
        "dhcp",
        "dhcp_lease_delete",
        "list_dhcp_subnet_dns",
        "set_dhcp_subnet_dns",
        "move_dhcp_host",
        "list_dhcp_hosts",
        "rm_dhcp_host",
        "mk_dhcp_host",
        "toggle_dhcp_range",
        "lldp",
        "system",
        "fw_rules",
        "mkfw_rule",
        "rmfw_rule",
        "ssh_fw_rule",
        "interface_list",
        "interface_health",
        "packet_capture",
        "dns",
        "mkdns",
        "rmdns",
        "flush_dns",
        "toggle_fw_rule",
        "set_fw_rule",
        "aliases",
        "gateway_status",
        "get_logs",
        "pf_states",
        "pf_statistics",
        "list_shaper_pipes",
        "get_shaper_pipe",
        "list_shaper_queues",
        "get_shaper_queue",
        "list_shaper_rules",
        "get_shaper_rule",
        "get_shaper_settings",
        "shaper_statistics",
        "audit_shaper_config",
        "explain_shaper_config",
    }
    assert expected.issubset(tool_names), f"Missing tools: {expected - tool_names}"


@pytest.mark.asyncio
async def test_fastmcp_server_exposes_every_registered_tool():
    """Counted against the registry, not a literal.

    This asserted `== 55`, so every tool added since needed the number edited
    here too, and the failure said nothing about which tool was missing.
    """
    from fastmcp.client import Client

    from opnsense_mcp.fastmcp_server import SHAPER_TOOL_CLASSES, build_mcp_server
    from opnsense_mcp.utils.registry import TOOL_CLASSES

    mcp = build_mcp_server()
    async with Client(mcp) as client:
        tools = await client.list_tools()

    exposed = {t.name for t in tools}
    expected = {c.name for c in TOOL_CLASSES} | {c.name for c in SHAPER_TOOL_CLASSES}

    assert exposed == expected, (
        f"missing: {sorted(expected - exposed)}\nunexpected: {sorted(exposed - expected)}"
    )


def test_main_argparser_accepts_transport():
    """main.py argparser must accept --transport with streamable-http option."""
    import subprocess
    import sys
    from pathlib import Path

    result = subprocess.run(
        [sys.executable, "main.py", "--help"],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).parent.parent),
    )
    assert "--transport" in result.stdout
    assert "streamable-http" in result.stdout
