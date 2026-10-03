"""Startup gates for #99 (mock served as live) and #100 (unchecked secret).

Each test tries to get the server running in the state the issue describes:
blank credentials with no mock flag, and an HTTP listener with no usable
secret or a request with no bearer token.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import main as entry
from opnsense_mcp import fastmcp_server, server
from opnsense_mcp.tools.system import SystemTool
from opnsense_mcp.utils.mock_api import MockOPNsenseClient

SECRET = "s3cret-for-tests-only-0123456789abcdef"  # pragma: allowlist secret
LIVE_CREDS = {
    "OPNSENSE_FIREWALL_HOST": "fw.example.test",
    "OPNSENSE_API_KEY": "k",
    "OPNSENSE_API_SECRET": "s",  # pragma: allowlist secret
}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every test from live creds, a valid secret, and no mock flag.

    server.py loads ~/.env at import, so the developer's real values would
    otherwise leak into these tests.
    """
    for var, value in LIVE_CREDS.items():
        monkeypatch.setenv(var, value)
    monkeypatch.setenv("MCP_SECRET_KEY", SECRET)
    monkeypatch.delenv("OPNSENSE_USE_MOCK", raising=False)
    monkeypatch.setattr(fastmcp_server, "get_opnsense_client", lambda _cfg: None)
    monkeypatch.setattr(fastmcp_server, "load_opnsense_env", lambda: None)


# --- #99: blank credentials ------------------------------------------------


@pytest.mark.parametrize("var", list(LIVE_CREDS))
@pytest.mark.parametrize("blank", ["", "   "])
def test_blank_credential_without_flag_refuses_to_start(
    monkeypatch: pytest.MonkeyPatch, var: str, blank: str
) -> None:
    """Any one blank credential stops startup when mock was not asked for."""
    monkeypatch.setenv(var, blank)
    with pytest.raises(SystemExit):
        server.require_live_credentials_or_mock_flag()


def test_unset_credentials_refuse_the_http_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The container path must not build a server that would serve mock data."""
    for var in LIVE_CREDS:
        monkeypatch.delenv(var)
    with pytest.raises(SystemExit):
        entry.build_http_server()


def test_unset_credentials_refuse_the_stdio_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stdio refuses before reading a single message."""
    for var in LIVE_CREDS:
        monkeypatch.delenv(var)

    def _no_client(_cfg: dict[str, Any]) -> Any:
        raise AssertionError("client built despite blank credentials")

    monkeypatch.setattr(server, "get_opnsense_client", _no_client)
    with pytest.raises(SystemExit):
        server.main()


@pytest.mark.parametrize("flag", ["0", "", "false", "no"])
def test_flag_must_be_affirmative(monkeypatch: pytest.MonkeyPatch, flag: str) -> None:
    """A present but negative flag does not unlock mock."""
    monkeypatch.setenv("OPNSENSE_API_KEY", "")
    monkeypatch.setenv("OPNSENSE_USE_MOCK", flag)
    with pytest.raises(SystemExit):
        server.require_live_credentials_or_mock_flag()


def test_explicit_flag_allows_mock(monkeypatch: pytest.MonkeyPatch) -> None:
    """With the flag the server starts, and the client really is the mock."""
    monkeypatch.setenv("OPNSENSE_API_KEY", "")
    monkeypatch.setenv("OPNSENSE_USE_MOCK", "1")
    server.require_live_credentials_or_mock_flag()
    assert isinstance(server.get_opnsense_client({}), MockOPNsenseClient)


def test_whitespace_credentials_never_build_a_live_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The gate and the client factory agree on what blank means."""
    monkeypatch.setenv("OPNSENSE_API_SECRET", "  ")
    assert isinstance(server.get_opnsense_client({}), MockOPNsenseClient)


@pytest.mark.asyncio
async def test_system_reports_mock_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """A caller can tell fixture output from the firewall's."""
    root = Path(server.__file__).parent.parent
    client = MockOPNsenseClient(
        {"development": {"mock_data_path": str(root / "examples" / "mock_data")}}
    )
    result = await SystemTool(client).execute({})
    assert result["client"] == "mock"


@pytest.mark.asyncio
async def test_system_reports_live_client() -> None:
    """Any non-mock client reports live."""

    class _Live:
        async def get_system_status(self) -> dict[str, Any]:
            return {"hostname": "fw"}

    result = await SystemTool(_Live()).execute({})
    assert result["status"] == "success"
    assert result["client"] == "live"


# --- #100: bearer auth -----------------------------------------------------


@pytest.mark.parametrize(
    "value",
    ["", "   ", "change-me-long-random", "replace_me", "development-secret-key"],
)
def test_http_refuses_unusable_secret(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    """Blank or shipped-placeholder secrets fail closed."""
    monkeypatch.setenv("MCP_SECRET_KEY", value)
    with pytest.raises(SystemExit):
        entry.build_http_server()


def test_http_refuses_unset_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """main.py used to default the secret; nothing may default it now."""
    monkeypatch.delenv("MCP_SECRET_KEY")
    with pytest.raises(SystemExit):
        entry.build_http_server()


async def _discover(app: Any, headers: dict[str, str]) -> Any:
    """POST server/discover to the HTTP app with *headers* added."""
    import httpx2 as hx

    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "server/discover",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        },
    }
    async with (
        app.router.lifespan_context(app),
        hx.AsyncClient(
            transport=hx.ASGITransport(app=app),
            base_url="http://t",
            follow_redirects=True,
        ) as client,
    ):
        return await client.post(
            "/mcp/",
            json=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "server/discover",
                **headers,
            },
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer wrong"},
        {"Authorization": f"Bearer {SECRET}x"},
        {"Authorization": f"Bearer {SECRET[:-1]}"},
        {"Authorization": f"Basic {SECRET}"},
    ],
    ids=["none", "wrong", "suffix", "prefix", "basic"],
)
async def test_http_rejects_requests_without_the_secret(
    headers: dict[str, str],
) -> None:
    """Anything other than the exact bearer secret gets 401 and no tools."""
    reply = await _discover(entry.build_http_server().http_app(), headers)
    assert reply.status_code == 401


@pytest.mark.asyncio
async def test_http_accepts_the_secret() -> None:
    """The control is not a wall: the right token gets through."""
    reply = await _discover(
        entry.build_http_server().http_app(), {"Authorization": f"Bearer {SECRET}"}
    )
    assert reply.status_code == 200
    assert json.loads(reply.text)["result"]["supportedVersions"] == ["2026-07-28"]
