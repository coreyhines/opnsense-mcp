"""Wave 3: a uuid from the model reached the API path unvalidated.

`requests` normalises dot segments client-side, before the request is sent, so
a tool argument containing `../` does not need a cooperative web server — it
simply arrives at a different endpoint:

    POST /api/quagga/bgp/toggleNeighbor/../../../core/firmware/poweroff?x=/1
      -> https://fw/api/core/firmware/poweroff?x=/1

`toggle_bgp_neighbor` takes no confirm token, so that was one tool call to
power off the firewall using the server's stored credentials. Roughly 45 call
sites interpolate a caller-supplied identifier into a path.

The guard is in the client rather than in each tool. Forty-five call sites is
forty-five chances to forget, and a tool added next month would not know to
call a validator it never saw. Refusing the request at the one place every call
passes through cannot be forgotten.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from opnsense_mcp.tools.bgp import ToggleBgpNeighborTool
from opnsense_mcp.utils.api import OPNsenseClient, RequestError


def _client() -> OPNsenseClient:
    config = {"firewall_host": "192.0.2.1", "api_key": "k", "api_secret": "s"}
    with (
        patch.object(OPNsenseClient, "_detect_endpoint", return_value=None),
        patch("opnsense_mcp.utils.api.requests.Session") as sess_cls,
    ):
        sess_cls.side_effect = lambda: MagicMock()
        client = OPNsenseClient(config)
    client.session.request = MagicMock(
        side_effect=AssertionError("a rejected endpoint must never reach the transport")
    )
    client.long_session.request = client.session.request
    return client


TRAVERSALS = [
    "/api/quagga/bgp/toggleNeighbor/../../../core/firmware/poweroff/1",
    "/api/routes/gateway/del_gateway/../../core/firmware/reboot",
    "/api/x/y/z/..%2f..%2fcore/firmware/poweroff",
    "/api/x/y/z/%2e%2e/%2e%2e/core/firmware/poweroff",
    "/api/x/y/../z",
    # Mixed encodings the first version enumerated its way around. requests
    # un-quotes %2e to "." while preparing the URL, so these reach the wire as
    # real dot segments. Enumerating was the mistake; the guard now decodes.
    "/api/quagga/bgp/toggleNeighbor/.%2e/.%2e/.%2e/core/firmware/poweroff/1",
    "/api/quagga/bgp/toggleNeighbor/%2e./%2e./core/firmware/poweroff/1",
    "/api/x/y/..%5c..%5ccore/firmware/poweroff",
    "/api/x/y/%2e%2e%2fcore/firmware/poweroff",
    "/api/x/y/z#/../../core/firmware/poweroff",
]


def test_a_dot_segment_never_reaches_the_transport() -> None:
    """The session mock raises if called, so reaching it fails the test."""
    for endpoint in TRAVERSALS:
        client = _client()
        with pytest.raises(RequestError, match="path"):
            asyncio.run(client._make_request("POST", endpoint))


def test_a_query_string_smuggled_into_the_path_is_refused() -> None:
    """`?x=` let arbitrary parameters be appended to whatever endpoint was hit."""
    client = _client()

    with pytest.raises(RequestError, match="path"):
        asyncio.run(client._make_request("POST", "/api/a/b/c?cmd=1"))


def test_an_ordinary_endpoint_is_untouched() -> None:
    """The guard must not reject the paths the project actually uses."""
    client = _client()
    ok = MagicMock()
    ok.status_code = 200
    ok.json.return_value = {"result": "saved"}
    ok.raise_for_status.return_value = None
    client.session.request = MagicMock(return_value=ok)
    client.long_session.request = client.session.request

    for endpoint in (
        "/api/quagga/bgp/toggleNeighbor/cf441b2a-375d-4ae8-81a3-bf884fc3c329/1",
        "/api/interfaces/loopback_settings/del_item/97816bdd-5018-4458-b73e-31e010bef4dc",
        "/api/firewall/filter/searchRule",
        "/api/interfaces/assignment/get_item/",
    ):
        assert asyncio.run(client._make_request("POST", endpoint)) == {
            "result": "saved"
        }


@pytest.mark.asyncio
async def test_the_tool_reports_the_refusal_rather_than_crashing() -> None:
    """A model passing a traversal should get an error, not a stack trace."""
    client = _client()
    tool = ToggleBgpNeighborTool(client)

    result = await tool.execute(
        {"uuid": "../../../core/firmware/poweroff?x=", "enabled": True}
    )

    assert result["status"] == "error"


def test_the_guard_is_not_confused_by_a_double_slash() -> None:
    """`//` collapses to a host change in some clients; refuse it too."""
    client = _client()

    with pytest.raises(RequestError, match="path"):
        asyncio.run(client._make_request("POST", "//evil.example/api/x"))


# --- sudo -E ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_root_php_call_does_not_inherit_the_environment() -> None:
    """`sudo -E` passes everything the SSH user exports into a root interpreter.

    PHP honours PHPRC, which selects a php.ini, which can set
    auto_prepend_file — arbitrary PHP as root. Only six variables need to
    survive, so they are named explicitly instead.
    """
    from opnsense_mcp.tools.interface_address import SetInterfaceAddressTool

    client = _client()
    ok = MagicMock()
    ok.status_code = 200
    ok.raise_for_status.return_value = None
    ok.json.return_value = {
        "rows": [{"uuid": "opt12", "if": "lo1"}],
        "interface": {"descr": "", "if": {}, "lock": "0"},
    }
    client.session.request = MagicMock(return_value=ok)
    client.long_session.request = client.session.request

    commands: list[str] = []

    class _Ssh:
        def execute_command(self, command: str) -> dict[str, Any]:
            commands.append(command)
            return {
                "stdout": "/tmp/x.aB3",
                "stderr": "",
                "exit_code": 0,
                "success": True,
            }

    tool = SetInterfaceAddressTool(client)
    tool._ssh = _Ssh()
    await tool.execute(
        {"interface": "opt12", "address": "198.51.100.2", "subnet_bits": 32}
    )

    run = next((c for c in commands if "php" in c and "b64decode" not in c), "")
    # Assert the positive shape, not the absence of one spelling: sudo
    # --preserve-env would satisfy `"sudo -E" not in run` and `"env" in run`
    # (inside --preserve-env) while restoring the exact PHPRC path.
    assert "-E" not in run and "preserve-env" not in run
    assert "/usr/bin/env" in run
    for var in ("MCP_IF", "MCP_ADDR", "MCP_BITS", "MCP_FIELD"):
        assert var in run
