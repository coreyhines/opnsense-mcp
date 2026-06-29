"""Stdio server (server.py) traffic-shaper tool parity with FastMCP."""

from __future__ import annotations

from pathlib import Path

import pytest

from opnsense_mcp.server import handle_message
from opnsense_mcp.tools.shaper_pipes import ListShaperPipesTool
from opnsense_mcp.tools.shaper_service import ApplyShaperTool
from opnsense_mcp.utils.mock_api import MockOPNsenseClient

# server.py's handle_message takes ~30 positional tool args before the
# keyword-only shaper_tools dict; tools/list and shaper tools/call only read
# shaper_tools and static class attributes, so the rest can be None here.
_TOOL_ARG_COUNT = 30


def _mock_client() -> MockOPNsenseClient:
    root = Path(__file__).parent.parent
    return MockOPNsenseClient(
        {"development": {"mock_data_path": str(root / "examples" / "mock_data")}}
    )


def _shaper_tools(client: MockOPNsenseClient) -> dict[str, object]:
    instances = [ListShaperPipesTool(client), ApplyShaperTool(client)]
    return {t.name: t for t in instances}


@pytest.mark.asyncio
async def test_tools_list_includes_shaper_tools() -> None:
    client = _mock_client()
    shaper_tools = _shaper_tools(client)
    message = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}

    response = await handle_message(
        message, *([None] * _TOOL_ARG_COUNT), shaper_tools=shaper_tools
    )

    names = {t["name"] for t in response["result"]["tools"]}
    assert "list_shaper_pipes" in names
    assert "apply_shaper" in names


@pytest.mark.asyncio
async def test_tools_call_dispatches_shaper_tool() -> None:
    client = _mock_client()
    shaper_tools = _shaper_tools(client)
    message = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "list_shaper_pipes", "arguments": {}},
    }

    response = await handle_message(
        message, *([None] * _TOOL_ARG_COUNT), shaper_tools=shaper_tools
    )

    assert "result" in response
    assert response["result"]["content"][0]["type"] == "text"


@pytest.mark.asyncio
async def test_unknown_tool_still_errors() -> None:
    message = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "does_not_exist", "arguments": {}},
    }

    response = await handle_message(
        message, *([None] * _TOOL_ARG_COUNT), shaper_tools={}
    )

    assert response["error"]["code"] == -32601
