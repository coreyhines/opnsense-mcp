"""Both servers must expose the same tools, from the same registry.

The old version of this file asserted two shaper names and passed 30 stubbed
positional arguments, so it could not catch drift and could not survive the
registry replacing that signature. It also could not have caught the drift that
actually existed: seven tools were described differently by the two servers,
because each kept its own copy of the surface.

These tests compare the whole set instead.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from opnsense_mcp.server import handle_message
from opnsense_mcp.tools.shaper_pipes import ListShaperPipesTool
from opnsense_mcp.tools.shaper_service import ApplyShaperTool
from opnsense_mcp.utils.mock_api import MockOPNsenseClient
from opnsense_mcp.utils.registry import TOOL_CLASSES, build_tools


def _mock_client() -> MockOPNsenseClient:
    root = Path(__file__).parent.parent
    return MockOPNsenseClient(
        {"development": {"mock_data_path": str(root / "examples" / "mock_data")}}
    )


def _shaper_tools(client: MockOPNsenseClient) -> dict[str, Any]:
    instances = [ListShaperPipesTool(client), ApplyShaperTool(client)]
    return {t.name: t for t in instances}


async def _list_tools(client: MockOPNsenseClient) -> list[dict[str, Any]]:
    response = await handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        tools=build_tools(client),
        shaper_tools=_shaper_tools(client),
    )
    assert response is not None
    return response["result"]["tools"]


@pytest.mark.asyncio
async def test_tools_list_includes_shaper_tools() -> None:
    """Shaper tools are injected rather than registered, so they need checking."""
    names = {t["name"] for t in await _list_tools(_mock_client())}

    assert "list_shaper_pipes" in names
    assert "apply_shaper" in names


@pytest.mark.asyncio
async def test_tools_call_dispatches_shaper_tool() -> None:
    client = _mock_client()

    response = await handle_message(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "list_shaper_pipes", "arguments": {}},
        },
        tools=build_tools(client),
        shaper_tools=_shaper_tools(client),
    )

    assert response is not None
    assert response["result"]["content"][0]["type"] == "text"


@pytest.mark.asyncio
async def test_unknown_tool_still_errors() -> None:
    client = _mock_client()

    response = await handle_message(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "not_a_tool", "arguments": {}},
        },
        tools=build_tools(client),
        shaper_tools=_shaper_tools(client),
    )

    assert response is not None
    assert response["error"]["code"] == -32601


@pytest.mark.asyncio
async def test_stdio_advertises_every_registered_tool() -> None:
    """The registry is the source; nothing in it may go unadvertised."""
    client = _mock_client()
    advertised = {t["name"] for t in await _list_tools(client)}
    registered = set(build_tools(client))

    assert not registered - advertised, (
        f"registered but not advertised: {sorted(registered - advertised)}"
    )


@pytest.mark.asyncio
async def test_stdio_advertises_nothing_extra() -> None:
    """Guards against a name reappearing as a literal alongside the registry."""
    client = _mock_client()
    advertised = {t["name"] for t in await _list_tools(client)}
    expected = set(build_tools(client)) | set(_shaper_tools(client))

    assert not advertised - expected, (
        f"advertised but not registered: {sorted(advertised - expected)}"
    )


def test_fastmcp_covers_the_same_tools() -> None:
    """FastMCP still defines a wrapper per tool.

    Until those wrappers are generated too, this asserts the two surfaces have
    not diverged: every registered tool needs a wrapper of the same name.
    """
    source = (
        Path(__file__).parent.parent / "opnsense_mcp" / "fastmcp_server.py"
    ).read_text()

    missing = [
        cls.name for cls in TOOL_CLASSES if f"async def {cls.name}(" not in source
    ]

    assert not missing, f"registered tools with no FastMCP wrapper: {missing}"
