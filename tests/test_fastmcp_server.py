"""Tests for the FastMCP-based Streamable HTTP server."""

import pytest


@pytest.mark.asyncio
async def test_fastmcp_server_imports():
    """fastmcp_server module must be importable."""
    from opnsense_mcp.fastmcp_server import build_mcp_server

    assert build_mcp_server is not None


@pytest.mark.asyncio
async def test_fastmcp_server_lists_tools():
    """Every advertised name resolves to something callable.

    The specific names live in utils/tool_groups; asserting them again here
    would just be a second copy to keep in step.
    """
    from fastmcp.client import Client

    from opnsense_mcp.fastmcp_server import build_mcp_server

    mcp = build_mcp_server()
    async with Client(mcp) as client:
        tools = await client.list_tools()

    assert len(tools) > 20
    for tool in tools:
        assert tool.name
        assert tool.description
        assert tool.inputSchema["type"] == "object"


@pytest.mark.asyncio
async def test_fastmcp_server_exposes_every_registered_tool():
    """Counted against the registry, not a literal.

    This asserted `== 55`, so every tool added since needed the number edited
    here too, and the failure said nothing about which tool was missing.
    """
    from fastmcp.client import Client

    from opnsense_mcp.fastmcp_server import build_mcp_server

    mcp = build_mcp_server()
    async with Client(mcp) as client:
        tools = await client.list_tools()

    from opnsense_mcp.utils.tool_groups import GROUPS, UNGROUPED

    exposed = {t.name for t in tools}

    # Operations are grouped by resource, so the exposed names are the group
    # names plus the ones deliberately left on their own.
    assert set(GROUPS) <= exposed, (
        f"groups missing from the server: {sorted(set(GROUPS) - exposed)}"
    )
    assert exposed >= UNGROUPED, (
        f"ungrouped tools missing: {sorted(UNGROUPED - exposed)}"
    )
    assert exposed == set(GROUPS) | UNGROUPED, (
        f"unexpected names: {sorted(exposed - (set(GROUPS) | UNGROUPED))}"
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
