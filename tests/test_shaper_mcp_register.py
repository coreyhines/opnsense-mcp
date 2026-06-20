"""Smoke tests for shaper read tool MCP registration (bucket 3b)."""

from __future__ import annotations

import pytest

SHAPER_READ_TOOLS = frozenset(
    {
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
)

SHAPER_WRITE_TOOLS = frozenset(
    {
        "add_shaper_pipe",
        "set_shaper_pipe",
        "toggle_shaper_pipe",
        "delete_shaper_pipe",
        "add_shaper_queue",
        "set_shaper_queue",
        "toggle_shaper_queue",
        "delete_shaper_queue",
        "add_shaper_rule",
        "set_shaper_rule",
        "toggle_shaper_rule",
        "delete_shaper_rule",
        "apply_shaper",
        "restore_shaper_snapshot",
        "apply_shaper_preset",
    }
)


def test_build_mcp_server_imports() -> None:
    """build_mcp_server must import and construct without error."""
    from opnsense_mcp.fastmcp_server import build_mcp_server

    assert build_mcp_server() is not None


@pytest.mark.asyncio
async def test_shaper_read_tools_registered() -> None:
    """All bucket 3a shaper read tools must appear in FastMCP tool list."""
    from fastmcp.client import Client

    from opnsense_mcp.fastmcp_server import build_mcp_server

    mcp = build_mcp_server()
    async with Client(mcp) as client:
        tools = await client.list_tools()

    tool_names = {t.name for t in tools}
    missing = SHAPER_READ_TOOLS - tool_names
    assert not missing, f"Missing shaper read tools: {sorted(missing)}"


@pytest.mark.asyncio
async def test_shaper_write_tools_registered() -> None:
    """All bucket 4i shaper write tools must appear in FastMCP tool list."""
    from fastmcp.client import Client

    from opnsense_mcp.fastmcp_server import build_mcp_server

    mcp = build_mcp_server()
    async with Client(mcp) as client:
        tools = await client.list_tools()

    tool_names = {t.name for t in tools}
    missing = SHAPER_WRITE_TOOLS - tool_names
    assert not missing, f"Missing shaper write tools: {sorted(missing)}"


@pytest.mark.asyncio
async def test_restore_shaper_snapshot_mcp_remove_orphans_param() -> None:
    """FastMCP must expose remove_orphans on restore_shaper_snapshot (BR-fix-a)."""
    from fastmcp.client import Client

    from opnsense_mcp.fastmcp_server import build_mcp_server

    mcp = build_mcp_server()
    async with Client(mcp) as client:
        tools = await client.list_tools()

    restore = next(t for t in tools if t.name == "restore_shaper_snapshot")
    props = (restore.inputSchema or {}).get("properties", {})
    assert "remove_orphans" in props
    assert props["remove_orphans"].get("default") is False
