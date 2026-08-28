"""Round-two review: defects in the fixes from round one.

Three adversarial reviewers, run against the merged fix branch. The sharpest
finding was that tests written in the same session as CLAUDE.md's failure-mode
rules broke those very rules — so several of these assert that the *tests* now
hold, not only the code.
"""

from __future__ import annotations

import ipaddress
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from opnsense_mcp.tools.bgp import SetBgpGlobalTool
from opnsense_mcp.tools.interface_address import _has_exact_address
from opnsense_mcp.tools.ipv6_stack import RmLoopbackTool
from opnsense_mcp.utils.api import OPNsenseClient, _reject_unsafe_endpoint


def _client(
    responses: dict[str, Any] | None = None,
) -> tuple[OPNsenseClient, list[str]]:
    config = {"firewall_host": "192.0.2.1", "api_key": "k", "api_secret": "s"}
    with (
        patch.object(OPNsenseClient, "_detect_endpoint", return_value=None),
        patch("opnsense_mcp.utils.api.requests.Session") as sess_cls,
    ):
        sess_cls.side_effect = lambda: MagicMock()
        client = OPNsenseClient(config)
    table = responses or {}
    calls: list[str] = []

    async def fake(method: str, endpoint: str, **kwargs: Any) -> Any:
        calls.append(endpoint)
        for key, value in table.items():
            if key in endpoint:
                if isinstance(value, Exception):
                    raise value
                return value
        return {}

    client._make_request = AsyncMock(side_effect=fake)
    return client, calls


LO_DEVICES = {"rows": [{"uuid": "lo-uuid", "deviceId": "1"}], "total": 1}
ASSIGNED_TO_LO1 = {"rows": [{"uuid": "opt12", "if": "lo1"}], "total": 1}


# --- rm_loopback: a wrong device must not skip the guard ------------------


@pytest.mark.asyncio
async def test_the_orphan_guard_runs_with_no_device_argument() -> None:
    """The guard resolves the device from the uuid, so omitting device does not
    skip it. lo1 is assigned to opt12, so the delete is refused."""
    client, calls = _client(
        {
            "loopback_settings/search_item": LO_DEVICES,
            "assignment/search_item": ASSIGNED_TO_LO1,
        }
    )
    tool = RmLoopbackTool(client)

    challenge = await tool.execute({"uuid": "lo-uuid"})
    result = await tool.execute(
        {"uuid": "lo-uuid", "confirm": challenge["confirm_token"]}
    )

    assert result["status"] == "error"
    assert "opt12" in result["error"]
    assert not [c for c in calls if "del_item" in c]


@pytest.mark.asyncio
async def test_a_matching_device_argument_is_accepted() -> None:
    """The correct device passes the cross-check and the guard still runs."""
    client, calls = _client(
        {
            "loopback_settings/search_item": LO_DEVICES,
            "assignment/search_item": ASSIGNED_TO_LO1,
        }
    )
    tool = RmLoopbackTool(client)

    challenge = await tool.execute({"uuid": "lo-uuid", "device": "lo1"})
    result = await tool.execute(
        {"uuid": "lo-uuid", "device": "lo1", "confirm": challenge["confirm_token"]}
    )

    assert result["status"] == "error"  # refused: opt12 holds it
    assert "opt12" in result["error"]


@pytest.mark.asyncio
async def test_a_mismatched_device_argument_is_reported() -> None:
    """A device that disagrees with the uuid is a caller mistake worth naming."""
    client, _ = _client(
        {
            "loopback_settings/search_item": LO_DEVICES,
            "assignment/search_item": {"rows": [], "total": 0},
        }
    )
    tool = RmLoopbackTool(client)

    challenge = await tool.execute({"uuid": "lo-uuid", "device": "lo9"})
    result = await tool.execute(
        {"uuid": "lo-uuid", "device": "lo9", "confirm": challenge["confirm_token"]}
    )

    assert result["status"] == "error"
    assert "lo1" in result["error"] and "lo9" in result["error"]


@pytest.mark.asyncio
async def test_a_failed_apply_on_delete_keeps_status_success() -> None:
    """rm_loopback ran reconfigure inside the write try, so an apply failure
    reported the delete as failed — the wave 2 defect, unfixed on this path."""
    client, calls = _client(
        {
            "loopback_settings/search_item": LO_DEVICES,
            "assignment/search_item": {"rows": [], "total": 0},
            "reconfigure": {"status": "failed"},
        }
    )
    tool = RmLoopbackTool(client)

    challenge = await tool.execute({"uuid": "lo-uuid"})
    result = await tool.execute(
        {"uuid": "lo-uuid", "confirm": challenge["confirm_token"], "apply": True}
    )

    assert result["status"] == "success"
    assert result["deleted"] is True
    assert result["applied"] is False
    assert any("del_item" in c for c in calls)


# --- the AS guard must read state, not the caller's description -----------


def test_the_as_guard_ignores_a_description_containing_the_word() -> None:
    """A peer described "established 2024" blocked every AS change forever."""
    from opnsense_mcp.tools.bgp import _any_established

    down_with_loaded_desc = {
        "response": {
            "ipv4Unicast": {
                "peers": {
                    "198.51.100.2": {
                        "state": "Active",
                        "desc": "peering established 2024",
                    }
                }
            }
        }
    }
    assert _any_established(down_with_loaded_desc) is False


def test_the_as_guard_still_sees_a_real_established_state() -> None:
    from opnsense_mcp.tools.bgp import _any_established

    up = {
        "response": {
            "ipv4Unicast": {"peers": {"198.51.100.2": {"state": "Established"}}}
        }
    }
    assert _any_established(up) is True


@pytest.mark.asyncio
async def test_an_unstructured_summary_refuses_the_change() -> None:
    """A successful-but-unstructured 200 must fail closed, not open.

    The AS guard treats "no Established peer found" as permission to change the
    AS number. A response it cannot parse — a text/vtysh shape, an error string
    at HTTP 200 — is not evidence of no sessions. A first version of this test
    asserted only that a phrase was absent, which passed while the guard failed
    open; it now asserts the change is refused.
    """
    for shape in (
        {"response": "BGP neighbor 198.51.100.254 state = Established"},
        {"response": "Error: cannot determine if established"},
        "Established",
        {"response": {"unexpected": "shape"}},
    ):
        client, _ = _client(
            {
                "general/get": {"general": {"enabled": "1", "daemons": {}}},
                "bgp/get": {"bgp": {"enabled": "1", "asnumber": "65001"}},
                "bgpsummary": shape,
            }
        )

        result = await SetBgpGlobalTool(client).execute({"as_number": "65010"})

        assert result["status"] == "error", shape


# --- link-local read-back --------------------------------------------------


def test_a_link_local_read_back_carries_a_scope_and_still_matches() -> None:
    """ifconfig always prints a scope on link-local; the token failed to parse
    and a successful write was reported as absent."""
    observed = "\tinet6 fe80::1%lo0/64 scopeid 0x7"
    assert _has_exact_address(observed, ipaddress.ip_address("fe80::1"), 64) is True


# --- the traversal guard, decoded ----------------------------------------


def test_mixed_encodings_of_a_dot_segment_are_refused() -> None:
    """requests un-quotes %2e to '.', so .%2e reached the wire as '..'."""
    from opnsense_mcp.utils.api import RequestError

    for bad in (".%2e/.%2e/core/x", "%2e./core/x", "%252e%252e/core/x", "..%5ccore/x"):
        with pytest.raises(RequestError):
            _reject_unsafe_endpoint(f"/api/a/{bad}")


def test_an_empty_trailing_segment_is_allowed() -> None:
    """get_item/ ends in an empty segment, which is not a dot segment."""
    _reject_unsafe_endpoint("/api/interfaces/assignment/get_item/")


def test_the_doc_drift_test_catches_a_fully_removed_verb_family() -> None:
    """Round 2 derived the verb set from surviving tools, so a name whose whole
    verb family was removed — ssh_fw_rule, the exact motivating case — could no
    longer be caught. The check must not depend on the stale name's verb still
    being in use."""
    import re
    import sys

    sys.path.insert(0, "tests")
    from test_review_wave4 import _NOT_TOOLS, _exposed_names

    known = _exposed_names()
    candidates = re.compile(r"`([a-z][a-z0-9]+(?:_[a-z0-9]+)+)`")

    # A removed tool's name, in a doc, must be flagged.
    doc_text = "See `ssh_fw_rule` for the SSH path."
    flagged = [
        n
        for n in candidates.findall(doc_text)
        if n not in known and n not in _NOT_TOOLS
    ]
    assert "ssh_fw_rule" in flagged
