"""Every shaper operation stays reachable after grouping.

The shaper tools used to be 25 separate names. They are now actions on three
grouped tools, so these assert the operations are still exposed rather than the
names, which is what the tests were protecting all along.
"""

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


def _shaper_actions() -> set[str]:
    """Every underlying shaper tool reachable through the grouped tools."""
    from opnsense_mcp.utils.tool_groups import GROUPS

    reachable: set[str] = set()
    for group_name, (_description, members) in GROUPS.items():
        if group_name.startswith("shaper"):
            reachable.update(members.values())
    return reachable


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
    assert "shaper" in tool_names

    missing = SHAPER_READ_TOOLS - _shaper_actions()
    assert not missing, f"shaper read operations no longer reachable: {sorted(missing)}"


@pytest.mark.asyncio
async def test_shaper_write_tools_registered() -> None:
    """All bucket 4i shaper write tools must appear in FastMCP tool list."""
    from fastmcp.client import Client

    from opnsense_mcp.fastmcp_server import build_mcp_server

    mcp = build_mcp_server()
    async with Client(mcp) as client:
        tools = await client.list_tools()

    tool_names = {t.name for t in tools}
    # Applying and auditing are actions on the one shaper tool now, not
    # separate names; the point of the check is that the operations survived
    # the regrouping, which _shaper_actions() below is what actually verifies.
    assert "shaper" in tool_names

    missing = SHAPER_WRITE_TOOLS - _shaper_actions()
    assert not missing, (
        f"shaper write operations no longer reachable: {sorted(missing)}"
    )


@pytest.mark.asyncio
async def test_restore_shaper_snapshot_mcp_remove_orphans_param() -> None:
    """FastMCP must expose remove_orphans on restore_shaper_snapshot (BR-fix-a)."""
    from fastmcp.client import Client

    from opnsense_mcp.fastmcp_server import build_mcp_server

    mcp = build_mcp_server()
    async with Client(mcp) as client:
        tools = await client.list_tools()

    # restore_shaper_snapshot is the restore_snapshot action on the shaper
    # tool, so the field appears in that group's merged schema.
    shaper = next(t for t in tools if t.name == "shaper")
    props = (shaper.inputSchema or {}).get("properties", {})
    assert "remove_orphans" in props
    assert props["remove_orphans"].get("default") is False
    assert "restore_snapshot" in props["action"]["enum"]
