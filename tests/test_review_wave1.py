"""Regressions from the three-way adversarial review: things that lied about state.

Every test here reproduces a defect that shipped. The common shape is a tool
reporting a fact about the firewall it never established — the same class as the
savepoint 404 and the toggleRule contract found earlier.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from opnsense_mcp.tools.bgp import BgpStatusTool, RmBgpNeighborTool, SetBgpGlobalTool
from opnsense_mcp.tools.interface_address import SetInterfaceAddressTool
from opnsense_mcp.tools.ipv6_stack import RmLoopbackTool
from opnsense_mcp.utils.api import OPNsenseClient

ASSIGNED = {"rows": [{"uuid": "opt12", "descr": "lo", "if": "lo1", "lock": "1"}]}
MODEL_26_7 = {
    "interface": {
        "descr": "",
        "identifier": "",
        "icon": "",
        "optgroup": "",
        "if": {},
        "lock": "0",
    }
}


def _client(responses: dict[str, Any] | None = None) -> OPNsenseClient:
    config = {"firewall_host": "192.0.2.1", "api_key": "k", "api_secret": "s"}
    with (
        patch.object(OPNsenseClient, "_detect_endpoint", return_value=None),
        patch("opnsense_mcp.utils.api.requests.Session") as sess_cls,
    ):
        sess_cls.side_effect = lambda: MagicMock()
        client = OPNsenseClient(config)

    table = responses or {}

    async def fake(method: str, endpoint: str, **kwargs: Any) -> Any:
        for key, value in table.items():
            if key in endpoint:
                if isinstance(value, Exception):
                    raise value
                return value
        return {}

    client._make_request = AsyncMock(side_effect=fake)
    return client


def _addr_tool(ssh_results: list[dict[str, Any]]) -> SetInterfaceAddressTool:
    client = _client(
        {"assignment/search_item": ASSIGNED, "assignment/get_item": MODEL_26_7}
    )

    class _Ssh:
        def execute_command(self, command: str) -> dict[str, Any]:
            return (
                ssh_results.pop(0)
                if ssh_results
                else {"stdout": "", "stderr": "", "exit_code": 0, "success": True}
            )

    tool = SetInterfaceAddressTool(client)
    tool._ssh = _Ssh()
    return tool


def _staged(*after: dict[str, Any]) -> list[dict[str, Any]]:
    """mktemp, then whatever the caller wants for run / verify / cleanup."""
    return [
        {"stdout": "/tmp/x.aB3", "stderr": "", "exit_code": 0, "success": True},
        *after,
    ]


# --- the read-back that justifies the SSH tool ----------------------------


@pytest.mark.asyncio
async def test_a_longer_address_does_not_satisfy_a_shorter_one() -> None:
    """`198.51.100.1 in "inet 198.51.100.10"` is True. It was a bare substring match.

    So a failed write on an interface already carrying 198.51.100.10 reported
    success for 198.51.100.1 — the one check standing between a root PHP
    write_config() and a false success.
    """
    tool = _addr_tool(
        _staged(
            {
                "stdout": "",
                "stderr": "PHP Fatal error",
                "exit_code": 255,
                "success": False,
            },
            {
                "stdout": "lo1: flags=8049\n\tinet 198.51.100.10/24",
                "stderr": "",
                "exit_code": 0,
                "success": True,
            },
            {"stdout": "", "stderr": "", "exit_code": 0, "success": True},
        )
    )

    result = await tool.execute(
        {"interface": "opt12", "address": "198.51.100.1", "subnet_bits": 32}
    )

    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_the_prefix_is_verified_not_just_the_address() -> None:
    """Asked for /32, got a /24: previously reported success with the /32."""
    tool = _addr_tool(
        _staged(
            {"stdout": "done", "stderr": "", "exit_code": 0, "success": True},
            {
                "stdout": "\tinet 172.16.99.2/24",
                "stderr": "",
                "exit_code": 0,
                "success": True,
            },
            {"stdout": "", "stderr": "", "exit_code": 0, "success": True},
        )
    )

    result = await tool.execute(
        {"interface": "opt12", "address": "172.16.99.2", "subnet_bits": 32}
    )

    assert result["status"] == "error"
    assert "prefix" in result["error"].lower() or "/32" in result["error"]


@pytest.mark.asyncio
async def test_an_exact_match_with_the_right_prefix_still_succeeds() -> None:
    tool = _addr_tool(
        _staged(
            {"stdout": "done", "stderr": "", "exit_code": 0, "success": True},
            {
                "stdout": "\tinet 172.16.99.2/32",
                "stderr": "",
                "exit_code": 0,
                "success": True,
            },
            {"stdout": "", "stderr": "", "exit_code": 0, "success": True},
        )
    )

    result = await tool.execute(
        {"interface": "opt12", "address": "172.16.99.2", "subnet_bits": 32}
    )

    assert result["status"] == "success"
    assert result["verified"] is True


@pytest.mark.asyncio
async def test_a_failed_verification_command_is_not_reported_as_absent() -> None:
    """The SSH client returns success=False on a dropped connection.

    Reading neither `success` nor `exit_code` turned "I could not look" into
    "the address is not there", asserting a fact about the firewall that was
    never observed — after a write that may well have landed.
    """
    tool = _addr_tool(
        _staged(
            {"stdout": "done", "stderr": "", "exit_code": 0, "success": True},
            {
                "stdout": "",
                "stderr": "SSH connection dropped",
                "exit_code": -1,
                "success": False,
            },
            {"stdout": "", "stderr": "", "exit_code": 0, "success": True},
        )
    )

    result = await tool.execute(
        {"interface": "opt12", "address": "172.16.99.2", "subnet_bits": 32}
    )

    assert result["status"] == "unknown"
    assert "could not" in result["error"].lower() or "unverified" in str(result).lower()


@pytest.mark.asyncio
async def test_an_ipv6_scope_id_is_refused() -> None:
    """ipaddress accepts fe80::1%$(reboot); the docstring claimed it would not.

    The value persists in config.xml and is re-applied on every boot, so it is
    not enough that the read-back later fails.
    """
    for bad in ("fe80::1%$(reboot)", "fe80::1%`id`", "fe80::1%a\nb"):
        tool = _addr_tool(_staged())

        result = await tool.execute(
            {"interface": "opt12", "address": bad, "subnet_bits": 128}
        )

        assert result["status"] == "error", bad
        assert "scope" in result["error"].lower(), bad


# --- BGP tools that report state they did not establish -------------------


@pytest.mark.asyncio
async def test_delete_reports_not_found_rather_than_a_deletion() -> None:
    """delBase answers an unknown uuid with {"result": "not found"} at HTTP 200.

    rm_gateway and rm_loopback both check for it; rm_bgp_neighbor did not.
    """
    client = _client({"delNeighbor": {"result": "not found"}})
    tool = RmBgpNeighborTool(client)

    challenge = await tool.execute({"uuid": "nbr-1"})
    result = await tool.execute(
        {"uuid": "nbr-1", "confirm": challenge["confirm_token"]}
    )

    assert result["status"] == "error"
    assert "nbr-1" in result["error"]
    assert result.get("deleted") is not True


@pytest.mark.asyncio
async def test_status_says_it_could_not_read_rather_than_reporting_down() -> None:
    """A read timeout on a loaded firewall became "BGP is down, no sessions"."""
    client = _client(
        {
            "general/get": {
                "general": {
                    "enabled": "1",
                    "daemons": {"bgp": {"value": "bgp", "selected": 1}},
                }
            },
            "bgp/get": {"bgp": {"enabled": "1", "asnumber": "65001"}},
            "searchNeighbor": {"rows": [], "total": 0},
            "service/status": TimeoutError("read timed out"),
            "bgpsummary": TimeoutError("read timed out"),
        }
    )

    result = await BgpStatusTool(client).execute({})

    assert result["running"] is None
    assert result["diagnostics_error"]
    assert "could not" in result["note"].lower()


@pytest.mark.asyncio
async def test_the_as_guard_sees_an_established_peer_in_the_real_shape() -> None:
    """bgpsummary nests peers under response.ipv4Unicast.peers.

    Iterating a dict yields keys, so `any("establish" in str(s))` never fired
    and the AS number could be changed under live sessions.
    """
    client = _client(
        {
            "general/get": {"general": {"enabled": "1", "daemons": {}}},
            "bgp/get": {"bgp": {"enabled": "1", "asnumber": "65001"}},
            "bgpsummary": {
                "response": {
                    "ipv4Unicast": {"peers": {"198.51.100.2": {"state": "Established"}}}
                }
            },
        }
    )

    result = await SetBgpGlobalTool(client).execute({"as_number": "65010"})

    assert result["status"] == "error"
    assert "established" in result["error"].lower()


@pytest.mark.asyncio
async def test_the_as_guard_refuses_when_it_cannot_read_the_sessions() -> None:
    """Failing open on an unreadable summary is the same bug in another coat."""
    client = _client(
        {
            "general/get": {"general": {"enabled": "1", "daemons": {}}},
            "bgp/get": {"bgp": {"enabled": "1", "asnumber": "65001"}},
            "bgpsummary": TimeoutError("read timed out"),
        }
    )

    result = await SetBgpGlobalTool(client).execute({"as_number": "65010"})

    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_disabling_bgp_warns_that_it_stops_other_daemons() -> None:
    """general.enabled=0 stops FRR wholesale, OSPF included.

    Reporting daemons: ["ospf"] afterwards read as "OSPF survived" when it had
    in fact been stopped. FRR is now left running whenever another daemon
    remains selected, so the report and the reality agree.
    """
    client = _client(
        {
            "general/get": {
                "general": {
                    "enabled": "1",
                    "daemons": {
                        "bgp": {"value": "bgp", "selected": 1},
                        "ospf": {"value": "ospf", "selected": 1},
                    },
                }
            },
            "bgp/get": {"bgp": {"enabled": "1", "asnumber": "65001"}},
        }
    )

    result = await SetBgpGlobalTool(client).execute({"enabled": False})

    # FRR stays up for OSPF; only the bgp daemon is deselected.
    assert result["status"] == "success"
    assert result["frr_left_running"] is True
    assert result["daemons"] == ["ospf"]


# --- rm_loopback's opt-in guard -------------------------------------------


@pytest.mark.asyncio
async def test_the_orphan_guard_runs_without_being_asked() -> None:
    """`device` was optional, so omitting it skipped the check entirely.

    That produces the orphaned, lock-protected assignment the tool exists to
    prevent — and the previous test asserted that path returned deleted: True.
    """
    client = _client(
        {
            "assignment/search_item": ASSIGNED,
            "loopback_settings/search_item": {
                "rows": [{"uuid": "lo-uuid", "device": "1"}]
            },
        }
    )
    tool = RmLoopbackTool(client)

    challenge = await tool.execute({"uuid": "lo-uuid"})
    result = await tool.execute(
        {"uuid": "lo-uuid", "confirm": challenge["confirm_token"]}
    )

    assert result["status"] == "error"
    assert "opt12" in result["error"]
