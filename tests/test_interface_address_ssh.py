"""Setting an interface address over SSH, because the API cannot.

This is the one place the project reaches past the API to write configuration,
so it carries more argument than code.

Why it is justified: `NetworkInterface.xml` on the 26.7 series defines six
fields — descr, identifier, icon, optgroup, if, lock — and the assignment
controller exposes whatever the model defines. An address posted to `set_item`
comes back `{"result": "saved"}` and is discarded. Verified against the source
and against the firewall.

Why that is a different case from `ssh_fw_rule`, which was removed: there the
API worked and three bugs made it look broken. Here the API genuinely cannot.
An SSH fallback is for what the API cannot do, not for what it appears to do
badly.

The fields exist in master, so this tool has a known expiry. It checks for them
and refuses rather than quietly remaining the path of least resistance on
firmware that no longer needs it.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from opnsense_mcp.tools.interface_address import SetInterfaceAddressTool
from opnsense_mcp.utils.api import OPNsenseClient

ASSIGNED = {
    "rows": [
        {"uuid": "opt12", "descr": "bgp_lo", "if": "lo1", "lock": "1"},
        {"uuid": "wan", "descr": "WAN", "if": "ax1", "lock": "1"},
    ]
}

# What the 26.7 model exposes: no address fields.
MODEL_WITHOUT_ADDRESSING = {
    "interface": {
        "descr": "",
        "identifier": "",
        "icon": "",
        "optgroup": "",
        "if": {},
        "lock": "0",
    }
}

# What master exposes, where this tool must stand down.
MODEL_WITH_ADDRESSING = {
    "interface": dict(
        MODEL_WITHOUT_ADDRESSING["interface"], ipaddr="", subnet="", type4={}
    )
}


def _client() -> OPNsenseClient:
    config = {"firewall_host": "192.0.2.1", "api_key": "k", "api_secret": "s"}
    with (
        patch.object(OPNsenseClient, "_detect_endpoint", return_value=None),
        patch("opnsense_mcp.utils.api.requests.Session") as sess_cls,
    ):
        sess_cls.side_effect = lambda: MagicMock()
        return OPNsenseClient(config)


def _tool(
    api_responses: dict[str, Any] | None = None,
    ssh_results: list[dict[str, Any]] | None = None,
) -> tuple[SetInterfaceAddressTool, list[str]]:
    """Build the tool with the API stubbed and SSH recorded rather than run."""
    client = _client()
    responses = {
        "assignment/search_item": ASSIGNED,
        "assignment/get_item": MODEL_WITHOUT_ADDRESSING,
    }
    responses.update(api_responses or {})

    async def fake(method: str, endpoint: str, **kwargs: Any) -> Any:
        for key, value in responses.items():
            if key in endpoint:
                return value
        return {}

    client._make_request = AsyncMock(side_effect=fake)

    commands: list[str] = []
    # First command is the mktemp+stage, which answers with the remote path.
    results = list(
        ssh_results
        or [
            {"stdout": "/tmp/opnsense-mcp-setaddr.aB3xQ9", "stderr": "", "exit_code": 0}
        ]
    )

    class _Ssh:
        def execute_command(self, command: str) -> dict[str, Any]:
            commands.append(command)
            return (
                results.pop(0)
                if results
                else {"stdout": "", "stderr": "", "exit_code": 0}
            )

    tool = SetInterfaceAddressTool(client)
    tool._ssh = _Ssh()
    return tool, commands


# --- refusals --------------------------------------------------------------


@pytest.mark.asyncio
async def test_it_stands_down_once_the_api_can_do_this() -> None:
    """The addressing fields are in master; this tool must not outlive them."""
    tool, commands = _tool({"assignment/get_item": MODEL_WITH_ADDRESSING})

    result = await tool.execute(
        {"interface": "opt12", "address": "172.16.99.2", "subnet_bits": 32}
    )

    assert result["status"] == "error"
    assert "api" in result["error"].lower()
    assert not commands


@pytest.mark.asyncio
async def test_an_unknown_interface_is_refused_before_any_command_runs() -> None:
    """The identifier is interpolated into a script; it comes from the API's own list."""
    tool, commands = _tool()

    result = await tool.execute(
        {"interface": "opt99", "address": "172.16.99.2", "subnet_bits": 32}
    )

    assert result["status"] == "error"
    assert "opt99" in result["error"]
    assert not commands


@pytest.mark.asyncio
async def test_a_malformed_address_never_reaches_the_shell() -> None:
    """Parsed, not pattern-matched: injection has nowhere to live."""
    for bad in (
        "198.51.100.4; rm -rf /",
        "$(id)",
        "172.16.99.2 && reboot",
        "not-an-ip",
        "",
    ):
        tool, commands = _tool()

        result = await tool.execute(
            {"interface": "opt12", "address": bad, "subnet_bits": 32}
        )

        assert result["status"] == "error", bad
        assert not commands, bad


@pytest.mark.asyncio
async def test_a_prefix_outside_the_family_is_refused() -> None:
    tool, commands = _tool()

    for bits in (33, -1, 129, "thirty-two"):
        result = await tool.execute(
            {"interface": "opt12", "address": "172.16.99.2", "subnet_bits": bits}
        )
        assert result["status"] == "error", bits
        assert not commands, bits


@pytest.mark.asyncio
async def test_an_ipv6_prefix_over_128_is_refused_but_64_is_fine() -> None:
    """The bound differs by family, so it is checked against the parsed address."""
    tool, _ = _tool()
    bad = await tool.execute(
        {"interface": "opt12", "address": "2001:db8::1", "subnet_bits": 129}
    )
    assert bad["status"] == "error"

    tool, commands = _tool(
        ssh_results=[
            {
                "stdout": "/tmp/opnsense-mcp-setaddr.aB3xQ9",
                "stderr": "",
                "exit_code": 0,
            },
            {"stdout": "OK", "stderr": "", "exit_code": 0},
            {
                "stdout": "\tinet6 2001:db8::1/64",
                "stderr": "",
                "exit_code": 0,
            },
            {"stdout": "", "stderr": "", "exit_code": 0},
        ]
    )
    good = await tool.execute(
        {"interface": "opt12", "address": "2001:db8::1", "subnet_bits": 64}
    )
    assert good["status"] == "success"


# --- the write ------------------------------------------------------------


@pytest.mark.asyncio
async def test_success_is_confirmed_by_reading_back_not_by_the_exit_code() -> None:
    """interface_configure threw after applying the address, live.

    So the command completing says nothing. The address has to be observed on
    the interface before this reports success.
    """
    tool, _ = _tool(
        ssh_results=[
            {
                "stdout": "/tmp/opnsense-mcp-setaddr.aB3xQ9",
                "stderr": "",
                "exit_code": 0,
            },
            {"stdout": "", "stderr": "PHP Fatal error: something", "exit_code": 255},
            {
                "stdout": "\tinet 172.16.99.2/32",
                "stderr": "",
                "exit_code": 0,
            },
            {"stdout": "", "stderr": "", "exit_code": 0},
        ]
    )

    result = await tool.execute(
        {"interface": "opt12", "address": "172.16.99.2", "subnet_bits": 32}
    )

    assert result["status"] == "success"
    assert result["verified"] is True


@pytest.mark.asyncio
async def test_a_clean_exit_without_the_address_is_a_failure() -> None:
    """The inverse: exit 0 proves nothing either."""
    tool, _ = _tool(
        ssh_results=[
            {
                "stdout": "/tmp/opnsense-mcp-setaddr.aB3xQ9",
                "stderr": "",
                "exit_code": 0,
            },
            {"stdout": "OK", "stderr": "", "exit_code": 0},
            {"stdout": "\tinet6 fe80::1/64", "stderr": "", "exit_code": 0},
            {"stdout": "", "stderr": "", "exit_code": 0},
        ]
    )

    result = await tool.execute(
        {"interface": "opt12", "address": "172.16.99.2", "subnet_bits": 32}
    )

    assert result["status"] == "error"
    assert "172.16.99.2" in result["error"]


@pytest.mark.asyncio
async def test_the_script_is_removed_even_when_the_write_fails() -> None:
    """A PHP file left in /tmp is litter with the config in it."""
    tool, commands = _tool(
        ssh_results=[
            {
                "stdout": "/tmp/opnsense-mcp-setaddr.aB3xQ9",
                "stderr": "",
                "exit_code": 0,
            },
            {"stdout": "", "stderr": "boom", "exit_code": 1},
            {"stdout": "", "stderr": "", "exit_code": 0},
            {"stdout": "", "stderr": "", "exit_code": 0},
        ]
    )

    await tool.execute(
        {"interface": "opt12", "address": "172.16.99.2", "subnet_bits": 32}
    )

    assert any("rm -f" in c for c in commands)


@pytest.mark.asyncio
async def test_the_values_reach_the_script_as_environment_not_as_source() -> None:
    """Nothing caller-supplied is interpolated into the PHP itself."""
    tool, commands = _tool()

    await tool.execute(
        {"interface": "opt12", "address": "172.16.99.2", "subnet_bits": 32}
    )

    php = next(c for c in commands if "b64decode" in c or "base64" in c)
    assert "172.16.99.2" not in php
    run = next(c for c in commands if "php" in c and "b64decode" not in c)
    assert "172.16.99.2" in run
