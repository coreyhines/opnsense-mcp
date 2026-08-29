"""The transport surface MCP 2026-07-28 requires.

2026-07-28 removes the initialize/initialized handshake and `Mcp-Session-Id`,
and adds `server/discover` so a client fetches capabilities on demand. Clients
on 2025-11-25 still open with `initialize` through the deprecation window, so
both paths must work and neither may depend on the other having run.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from opnsense_mcp.server import SUPPORTED_PROTOCOL_VERSIONS, handle_message
from opnsense_mcp.utils.registry import build_tools
from opnsense_mcp.utils.tool_groups import build_groups


def _tools() -> dict[str, Any]:
    """The exposed surface, built without a client the same way the server does."""
    return build_groups(build_tools(None))


@pytest.mark.asyncio
async def test_discover_offers_the_2026_version_first() -> None:
    """A client picking the first offered version must land on the new one."""
    reply = await handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "server/discover"}, {}
    )

    versions = reply["result"]["supportedVersions"]
    assert versions[0] == "2026-07-28"
    assert "2025-11-25" in versions


@pytest.mark.asyncio
async def test_discover_reports_the_tools_capability() -> None:
    """Capabilities move from the handshake to discover; they must survive."""
    reply = await handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "server/discover"}, {}
    )

    assert reply["result"]["capabilities"]["tools"] == {"listChanged": False}
    assert reply["result"]["instructions"]


@pytest.mark.asyncio
async def test_tools_work_without_any_handshake() -> None:
    """The point of the change: every request is self-contained.

    No initialize, no discover, no session id. `tools/list` must answer anyway,
    or the server is still carrying a handshake assumption.
    """
    reply = await handle_message(
        {"jsonrpc": "2.0", "id": 7, "method": "tools/list"}, _tools()
    )

    assert reply["id"] == 7
    assert reply["result"]["tools"]


@pytest.mark.asyncio
async def test_initialize_still_answers_for_older_clients() -> None:
    """Removing it would break every client until they migrate."""
    reply = await handle_message(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "initialize",
            "params": {"protocolVersion": "2025-11-25"},
        },
        {},
    )

    assert reply["result"]["protocolVersion"] == "2025-11-25"


@pytest.mark.asyncio
async def test_the_server_holds_no_session_state_between_calls() -> None:
    """Two calls in either order must give the same answer.

    A stateless server can be load-balanced across instances; one that answers
    differently after a handshake cannot.
    """
    first = await handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, _tools()
    )
    await handle_message(
        {"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {}}, _tools()
    )
    second = await handle_message(
        {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}, _tools()
    )

    assert first["result"] == second["result"]


def test_every_tool_schema_is_valid_json_schema_2020_12() -> None:
    """2026-07-28 requires full JSON Schema 2020-12 for tool inputSchema."""
    jsonschema = pytest.importorskip("jsonschema")

    validator = jsonschema.Draft202012Validator
    offenders: list[str] = []
    for name, tool in _tools().items():
        schema = getattr(tool, "input_schema", None)
        if not isinstance(schema, dict):
            offenders.append(f"{name}: no input_schema")
            continue
        try:
            validator.check_schema(schema)
        except jsonschema.exceptions.SchemaError as exc:
            offenders.append(f"{name}: {exc.message}")

    assert not offenders, "invalid 2020-12 schemas: " + "; ".join(offenders)


def test_every_tool_schema_is_json_serialisable() -> None:
    """A schema that cannot be serialised cannot be sent over the wire."""
    for name, tool in _tools().items():
        schema: Any = getattr(tool, "input_schema", None)
        json.dumps(schema), f"{name} schema is not serialisable"


def test_the_supported_versions_are_ordered_newest_first() -> None:
    """Discover offers them in preference order, so the order is the contract."""
    assert list(SUPPORTED_PROTOCOL_VERSIONS) == sorted(
        SUPPORTED_PROTOCOL_VERSIONS, reverse=True
    )


# --- HTTP transport ---------------------------------------------------------

MODERN_META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
}


async def _post(app: Any, method: str, params: dict[str, Any] | None) -> Any:
    """One modern-era JSON-RPC call against the HTTP app, no handshake first."""
    import httpx2 as hx

    body: dict[str, Any] = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    async with hx.AsyncClient(
        transport=hx.ASGITransport(app=app), base_url="http://t", follow_redirects=True
    ) as client:
        return await client.post(
            "/mcp/",
            json=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": method,
            },
        )


@pytest.fixture
def http_app(monkeypatch: pytest.MonkeyPatch) -> Any:
    """The HTTP app with a stubbed client, so no test reaches the firewall."""
    from opnsense_mcp import fastmcp_server

    monkeypatch.setattr(fastmcp_server, "get_opnsense_client", lambda _cfg: None)
    monkeypatch.setattr(fastmcp_server, "load_opnsense_env", lambda: None)
    return fastmcp_server.build_mcp_server().http_app()


@pytest.mark.asyncio
async def test_http_discover_reports_the_2026_version(http_app: Any) -> None:
    """The HTTP transport must speak the new era, not just stdio."""
    async with http_app.router.lifespan_context(http_app):
        reply = await _post(http_app, "server/discover", {"_meta": MODERN_META})

    assert reply.status_code == 200
    assert json.loads(reply.text)["result"]["supportedVersions"] == ["2026-07-28"]


@pytest.mark.asyncio
async def test_http_reports_our_build_version_not_the_sdk_version(
    http_app: Any,
) -> None:
    """Without an explicit version FastMCP reported its own.

    A client could not then tell which build of this server answered.
    """
    from opnsense_mcp.build_info import get_build_info

    async with http_app.router.lifespan_context(http_app):
        reply = await _post(http_app, "server/discover", {"_meta": MODERN_META})

    info = json.loads(reply.text)["result"]["_meta"][
        "io.modelcontextprotocol/serverInfo"
    ]
    assert info["name"] == "opnsense-mcp"
    assert info["version"] == get_build_info()["package_version"]


@pytest.mark.asyncio
async def test_http_tools_list_needs_no_handshake(http_app: Any) -> None:
    """Self-contained requests are the whole point of the new transport."""
    async with http_app.router.lifespan_context(http_app):
        reply = await _post(http_app, "tools/list", {"_meta": MODERN_META})

    assert reply.status_code == 200
    assert json.loads(reply.text)["result"]["tools"]


@pytest.mark.asyncio
async def test_http_rejects_a_request_without_the_meta_envelope(
    http_app: Any,
) -> None:
    """The envelope carries what the handshake used to, so it is required."""
    async with http_app.router.lifespan_context(http_app):
        reply = await _post(http_app, "server/discover", {})

    assert reply.status_code == 400
    assert json.loads(reply.text)["error"]["code"] == -32602
