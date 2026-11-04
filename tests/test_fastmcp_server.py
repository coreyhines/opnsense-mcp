"""Tests for the FastMCP-based Streamable HTTP server."""

import pytest


@pytest.mark.asyncio
async def test_fastmcp_server_imports():
    """fastmcp_server module must be importable."""
    from opnsense_mcp.fastmcp_server import build_mcp_server

    assert build_mcp_server is not None


# Deliberately a little above the current count, so ordinary work does not trip
# it, while a regression that fans the surface back out does.
MAX_ADVERTISED_TOOLS = 16


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

    # An upper bound, not a lower one. Keeping the advertised surface small is
    # the goal, and a floor would have to be edited downward every time a group
    # absorbs another, which defeats the purpose of asserting anything.
    assert len(tools) <= MAX_ADVERTISED_TOOLS, (
        f"{len(tools)} tools advertised; consolidate before raising this."
    )
    assert tools, "no tools advertised at all"
    for tool in tools:
        assert tool.name
        assert tool.description
        assert tool.inputSchema["type"] == "object"


def _bare_array_paths(node, path):
    """Yield paths to any ``{\"type\": \"array\"}`` lacking an ``items`` schema."""
    if isinstance(node, dict):
        if node.get("type") == "array" and "items" not in node:
            yield path
        for key, child in node.items():
            yield from _bare_array_paths(child, f"{path}.{key}")
    elif isinstance(node, list):
        for index, child in enumerate(node):
            yield from _bare_array_paths(child, f"{path}[{index}]")


@pytest.mark.asyncio
async def test_fastmcp_server_advertises_items_on_every_array():
    """Strict clients reject arrays with no items schema.
    A Featherless-backed validator refused the whole request while building
    calls for tools that advertised ``\"type\": \"array\"`` with no ``items``,
    so every advertised array needs one, whatever the client's leniency.
    """
    from fastmcp.client import Client

    from opnsense_mcp.fastmcp_server import build_mcp_server

    mcp = build_mcp_server()
    async with Client(mcp) as client:
        tools = await client.list_tools()
    bare = [p for tool in tools for p in _bare_array_paths(tool.inputSchema, tool.name)]
    assert not bare, f"arrays without items schema: {bare}"


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
