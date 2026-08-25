"""Every advertised tool must actually dispatch.

`server.py`'s dispatch is a long `if tool_name == ...` chain sitting at roughly
38% coverage, and `tools/list` is a separate hand-written block. Nothing tied
the two together, so a tool could be advertised and not wired, or wired and not
advertised, and the suite would stay green.

These tests close that gap before the registry replaces both. The harness binds
tool instances by inspecting `handle_message`'s signature rather than passing 30
positional arguments, so it survives the parameters being reordered, renamed or
replaced by a registry: only the binding helper changes, not the assertions.

Dispatch is asserted, not tool success. Most tools need real arguments and a
real firewall, so a tool-level error is a pass here. What must never happen is
JSON-RPC -32601, which means the name is advertised but unreachable.
"""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any

import pytest

from opnsense_mcp.server import handle_message
from opnsense_mcp.tools.shaper_audit import (
    AuditShaperConfigTool,
    ExplainShaperConfigTool,
)
from opnsense_mcp.tools.shaper_pipes import (
    AddShaperPipeTool,
    DeleteShaperPipeTool,
    GetShaperPipeTool,
    ListShaperPipesTool,
    SetShaperPipeTool,
    ToggleShaperPipeTool,
)
from opnsense_mcp.tools.shaper_service import ApplyShaperTool, ShaperStatisticsTool
from opnsense_mcp.tools.shaper_settings import GetShaperSettingsTool
from opnsense_mcp.utils.mock_api import MockOPNsenseClient

TOOL_NOT_FOUND = -32601


def _mock_client() -> MockOPNsenseClient:
    root = Path(__file__).parent.parent
    return MockOPNsenseClient(
        {"development": {"mock_data_path": str(root / "examples" / "mock_data")}}
    )


def _shaper_tools(client: MockOPNsenseClient) -> dict[str, Any]:
    """A representative slice of the shaper surface.

    The full set is 25 tools; this covers read, write, toggle, delete, apply,
    settings and audit so the dispatch path for each shape is exercised.
    """
    instances = [
        ListShaperPipesTool(client),
        GetShaperPipeTool(client),
        AddShaperPipeTool(client),
        SetShaperPipeTool(client),
        ToggleShaperPipeTool(client),
        DeleteShaperPipeTool(client),
        ApplyShaperTool(client),
        ShaperStatisticsTool(client),
        GetShaperSettingsTool(client),
        AuditShaperConfigTool(client),
        ExplainShaperConfigTool(client),
    ]
    return {t.name: t for t in instances}


def _bind_tools(client: MockOPNsenseClient) -> dict[str, Any]:
    """Build handle_message's tool arguments from its own signature.

    Each parameter is annotated with its tool class, so the class can be read
    off the annotation and instantiated. `PacketCaptureTool` takes no client.
    """
    import opnsense_mcp.server as server_mod

    # server.py uses `from __future__ import annotations`, so signature()
    # yields strings. Resolve them against the module's own namespace.
    hints = inspect.signature(handle_message, eval_str=True).parameters

    bound: dict[str, Any] = {}
    unresolved: list[str] = []
    for pname, param in hints.items():
        if pname in {"message", "shaper_tools"}:
            continue
        cls = param.annotation
        if isinstance(cls, str):
            cls = getattr(server_mod, cls, None)
        if not inspect.isclass(cls):
            unresolved.append(pname)
            continue
        bound[pname] = cls() if cls.__name__ == "PacketCaptureTool" else cls(client)

    assert not unresolved, (
        f"could not resolve tool classes for: {unresolved}. "
        "The harness binds by annotation; update it if the signature changed."
    )
    return bound


async def _advertised_tools() -> list[dict[str, Any]]:
    client = _mock_client()
    response = await handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        **_bind_tools(client),
        shaper_tools=_shaper_tools(client),
    )
    assert response is not None, "tools/list returned nothing"
    return response["result"]["tools"]


def _minimal_arguments(schema: dict[str, Any]) -> dict[str, Any]:
    """Placeholder values for a schema's required fields.

    Values are deliberately inert. The point is to reach the tool, not to make
    it succeed.
    """
    placeholders = {
        "string": "smoke-test",
        "integer": 1,
        "number": 1,
        "boolean": False,
        "array": [],
        "object": {},
    }
    props = schema.get("properties", {}) if isinstance(schema, dict) else {}
    args: dict[str, Any] = {}
    for field in schema.get("required", []) if isinstance(schema, dict) else []:
        spec = props.get(field, {})
        args[field] = placeholders.get(spec.get("type", "string"), "smoke-test")
    return args


@pytest.mark.asyncio
async def test_tools_list_advertises_the_expected_surface() -> None:
    """Guards the harness: an empty or tiny list would make the rest vacuous."""
    tools = await _advertised_tools()

    assert len(tools) > 35
    assert all("name" in t and "inputSchema" in t for t in tools)


@pytest.mark.asyncio
async def test_every_advertised_tool_dispatches() -> None:
    """Advertised and unwired is the failure this catches.

    A tool erroring is fine here. -32601 is not: it means `tools/list` offers a
    name the dispatch chain has no branch for.
    """
    client = _mock_client()
    bound = _bind_tools(client)
    shaper = _shaper_tools(client)

    unreachable = []
    for tool in await _advertised_tools():
        name = tool["name"]
        response = await handle_message(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": name,
                    "arguments": _minimal_arguments(tool.get("inputSchema", {})),
                },
            },
            **bound,
            shaper_tools=shaper,
        )
        if response is None:
            unreachable.append(f"{name}: no response")
        elif response.get("error", {}).get("code") == TOOL_NOT_FOUND:
            unreachable.append(f"{name}: {response['error']['message']}")

    assert not unreachable, "advertised but not dispatchable:\n" + "\n".join(
        unreachable
    )


@pytest.mark.asyncio
async def test_dispatch_returns_mcp_content_shape() -> None:
    """Whatever a tool returns, the envelope must stay MCP-shaped."""
    client = _mock_client()

    response = await handle_message(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "list_shaper_pipes", "arguments": {}},
        },
        **_bind_tools(client),
        shaper_tools=_shaper_tools(client),
    )

    assert response is not None
    content = response["result"]["content"]
    assert isinstance(content, list)
    assert content[0]["type"] == "text"


@pytest.mark.asyncio
async def test_unknown_tool_is_rejected() -> None:
    """The negative case, so the dispatch assertion above means something."""
    client = _mock_client()

    response = await handle_message(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "no_such_tool", "arguments": {}},
        },
        **_bind_tools(client),
        shaper_tools=_shaper_tools(client),
    )

    assert response is not None
    assert response["error"]["code"] == TOOL_NOT_FOUND


# Every tool advertised by server.py now carries class metadata, so tools/list
# and the class-derived snapshot agree. Kept as an explicit empty set so a
# regression names itself instead of silently reopening the gap.
LITERAL_ONLY_TOOLS: frozenset[str] = frozenset()


@pytest.mark.asyncio
async def test_advertised_names_match_the_recorded_surface() -> None:
    """`tools/list` and the class-derived snapshot must not drift apart.

    They differ today in one direction only: nine tools are advertised from
    literals while their classes expose no metadata. That difference is the
    registry's actual work item, so it is asserted exactly rather than waived.
    """
    from tests.tool_surface import load_golden

    advertised = {t["name"] for t in await _advertised_tools()}
    golden = set(load_golden())

    unrecorded = advertised - golden
    assert unrecorded == LITERAL_ONLY_TOOLS, (
        "advertised-but-unrecorded tools changed.\n"
        f"  now:      {sorted(unrecorded)}\n"
        f"  expected: {sorted(LITERAL_ONLY_TOOLS)}\n"
        "Retrofitting a class should remove it from LITERAL_ONLY_TOOLS."
    )


@pytest.mark.asyncio
async def test_recorded_tools_are_advertised() -> None:
    """Anything with class metadata should reach `tools/list`.

    Shaper tools are injected by the caller, so only the slice this harness
    constructs is in scope.
    """
    from tests.tool_surface import load_golden

    advertised = {t["name"] for t in await _advertised_tools()}
    built_shaper = set(_shaper_tools(_mock_client()))
    expected = {
        name for name in load_golden() if "shaper" not in name or name in built_shaper
    }

    assert not expected - advertised, (
        f"recorded but not advertised: {sorted(expected - advertised)}"
    )
