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
