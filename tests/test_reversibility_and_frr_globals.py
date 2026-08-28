"""Deletes that were missing, and the FRR switches that were UI-only.

Two separate gaps found the same way. An audit of every create tool against its
delete counterpart turned up `mk_loopback`, `mk_gateway` and `mk_snapshot` with
no way to undo them, which is how a stale uuid ended up being deleted with a
raw request instead of a tool.

The FRR globals are the other half: `bgp_status` could read the three switches
that gate a session but nothing could write them, so standing up BGP stopped
being drivable exactly where it got interesting.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from opnsense_mcp.tools.bgp import SetBgpGlobalTool
from opnsense_mcp.tools.ipv6_stack import MkLoopbackTool, RmLoopbackTool
from opnsense_mcp.tools.routing_stack import RmGatewayTool
from opnsense_mcp.utils.api import OPNsenseClient

LOOPBACK_UUID = "lo-1234"
GATEWAY_UUID = "gw-1234"

GENERAL_OFF = {
    "general": {
        "enabled": "0",
        "daemons": {
            "bfd": {"value": "bfd", "selected": 0},
            "bgp": {"value": "bgp", "selected": 0},
            "static": {"value": "static", "selected": 1},
        },
        "profile": {
            "traditional": {"value": "traditional", "selected": 1},
            "datacenter": {"value": "datacenter", "selected": 0},
        },
    }
}

BGP_OFF = {
    "bgp": {"enabled": "0", "asnumber": "65551", "routerid": "", "graceful": "0"}
}


def _client() -> OPNsenseClient:
    config = {"firewall_host": "192.0.2.1", "api_key": "k", "api_secret": "s"}
    with (
        patch.object(OPNsenseClient, "_detect_endpoint", return_value=None),
        patch("opnsense_mcp.utils.api.requests.Session") as sess_cls,
    ):
        sess_cls.side_effect = lambda: MagicMock()
        return OPNsenseClient(config)


def _stub(client: OPNsenseClient, responses: dict[str, Any]) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    async def fake(method: str, endpoint: str, **kwargs: Any) -> Any:
        calls.append({"endpoint": endpoint, "json": kwargs.get("json")})
        for key, value in responses.items():
            if key in endpoint:
                return value() if callable(value) else value
        return {"result": "saved"}

    client._make_request = AsyncMock(side_effect=fake)
    return calls


# --- the missing deletes ---------------------------------------------------


@pytest.mark.asyncio
async def test_rm_loopback_confirms_before_deleting() -> None:
    client = _client()
    calls = _stub(client, {})

    result = await RmLoopbackTool(client).execute({"uuid": LOOPBACK_UUID})

    assert result["status"] == "confirmation_required"
    assert not [c for c in calls if "del_item" in c["endpoint"]]


@pytest.mark.asyncio
async def test_rm_loopback_deletes_once_confirmed() -> None:
    """The device resolves and nothing is assigned to it, so the delete runs.

    This previously passed no `device` and asserted success, which encoded the
    opt-in guard as intended behaviour. The guard now always runs, so the
    fixtures have to describe an unassigned device.
    """
    client = _client()
    calls = _stub(
        client,
        {
            "loopback_settings/search_item": {
                "rows": [{"uuid": LOOPBACK_UUID, "deviceId": "9"}]
            },
            "assignment/search_item": {"rows": []},
        },
    )

    challenge = await RmLoopbackTool(client).execute({"uuid": LOOPBACK_UUID})
    result = await RmLoopbackTool(client).execute(
        {"uuid": LOOPBACK_UUID, "confirm": challenge["confirm_token"]}
    )

    assert result["deleted"] is True
    assert [c for c in calls if "del_item" in c["endpoint"]]


@pytest.mark.asyncio
async def test_rm_gateway_confirms_before_deleting() -> None:
    """A gateway can be the default route; removing one is not a small edit."""
    client = _client()
    calls = _stub(client, {})

    result = await RmGatewayTool(client).execute({"uuid": GATEWAY_UUID})

    assert result["status"] == "confirmation_required"
    assert not [c for c in calls if "del_gateway" in c["endpoint"]]


@pytest.mark.asyncio
async def test_rm_gateway_deletes_once_confirmed() -> None:
    client = _client()
    calls = _stub(client, {})

    challenge = await RmGatewayTool(client).execute({"uuid": GATEWAY_UUID})
    result = await RmGatewayTool(client).execute(
        {"uuid": GATEWAY_UUID, "confirm": challenge["confirm_token"]}
    )

    assert result["deleted"] is True
    assert [c for c in calls if "del_gateway" in c["endpoint"]]


# --- FRR globals -----------------------------------------------------------


@pytest.mark.asyncio
async def test_enabling_bgp_sets_all_three_switches() -> None:
    """FRR, the daemon selection and the BGP section each gate a session.

    Setting one and not the others leaves a configuration that looks enabled
    and peers with nobody, which is the failure bgp_status exists to explain.
    """
    client = _client()
    calls = _stub(client, {"general/get": GENERAL_OFF, "bgp/get": BGP_OFF})

    result = await SetBgpGlobalTool(client).execute(
        {"enabled": True, "as_number": "65001", "router_id": "172.16.99.2"}
    )

    assert result["status"] == "success"
    general = next(c for c in calls if "general/set" in c["endpoint"])["json"][
        "general"
    ]
    bgp = next(c for c in calls if "bgp/set" in c["endpoint"])["json"]["bgp"]
    assert general["enabled"] == "1"
    assert "bgp" in general["daemons"].split(",")
    assert bgp["enabled"] == "1"
    assert bgp["asnumber"] == "65001"
    assert bgp["routerid"] == "172.16.99.2"


@pytest.mark.asyncio
async def test_enabling_keeps_daemons_that_were_already_selected() -> None:
    """Writing the enum replaces it, so a naive write drops the others."""
    client = _client()
    calls = _stub(client, {"general/get": GENERAL_OFF, "bgp/get": BGP_OFF})

    await SetBgpGlobalTool(client).execute({"enabled": True, "as_number": "65001"})

    general = next(c for c in calls if "general/set" in c["endpoint"])["json"][
        "general"
    ]
    assert set(general["daemons"].split(",")) == {"static", "bgp"}


@pytest.mark.asyncio
async def test_disabling_leaves_the_other_daemons_alone() -> None:
    client = _client()
    on = {
        "general": {
            "enabled": "1",
            "daemons": {
                "bgp": {"value": "bgp", "selected": 1},
                "static": {"value": "static", "selected": 1},
            },
        }
    }
    calls = _stub(client, {"general/get": on, "bgp/get": BGP_OFF})

    await SetBgpGlobalTool(client).execute({"enabled": False})

    general = next(c for c in calls if "general/set" in c["endpoint"])["json"][
        "general"
    ]
    assert general["daemons"] == "static"


@pytest.mark.asyncio
async def test_an_as_number_is_required_to_enable() -> None:
    """65551 is the shipped default and is outside the 2-byte private range."""
    client = _client()
    _stub(client, {"general/get": GENERAL_OFF, "bgp/get": BGP_OFF})

    result = await SetBgpGlobalTool(client).execute({"enabled": True})

    assert result["status"] == "error"
    assert "as_number" in result["error"]


@pytest.mark.asyncio
async def test_an_existing_as_number_does_not_have_to_be_restated() -> None:
    client = _client()
    configured = {"bgp": {"enabled": "0", "asnumber": "65001", "routerid": ""}}
    calls = _stub(client, {"general/get": GENERAL_OFF, "bgp/get": configured})

    result = await SetBgpGlobalTool(client).execute({"enabled": True})

    assert result["status"] == "success"
    bgp = next(c for c in calls if "bgp/set" in c["endpoint"])["json"]["bgp"]
    assert bgp["asnumber"] == "65001"


@pytest.mark.asyncio
async def test_changing_the_as_number_is_refused_while_peers_are_up() -> None:
    """The AS number is in every OPEN message, so changing it resets each peer."""
    client = _client()
    _stub(
        client,
        {
            "general/get": GENERAL_OFF,
            "bgp/get": {"bgp": {"enabled": "1", "asnumber": "65001"}},
            "bgpsummary": {
                "response": [{"peer": "198.51.100.254", "state": "Established"}]
            },
        },
    )

    result = await SetBgpGlobalTool(client).execute({"as_number": "65010"})

    assert result["status"] == "error"
    assert "established" in result["error"].lower()


@pytest.mark.asyncio
async def test_nothing_to_change_is_an_error_not_a_silent_write() -> None:
    client = _client()
    _stub(client, {"general/get": GENERAL_OFF, "bgp/get": BGP_OFF})

    result = await SetBgpGlobalTool(client).execute({})

    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_globals_do_not_apply_by_default() -> None:
    """Reconfiguring restarts FRR, which drops every established session."""
    client = _client()
    calls = _stub(client, {"general/get": GENERAL_OFF, "bgp/get": BGP_OFF})

    await SetBgpGlobalTool(client).execute({"enabled": True, "as_number": "65001"})

    assert not [c for c in calls if "reconfigure" in c["endpoint"]]


# --- loopback lifecycle ----------------------------------------------------


ASSIGNED_ROWS = {
    "rows": [
        {"uuid": "opt12", "descr": "probe_lo", "if": "lo1", "lock": "1"},
        {"uuid": "wan", "descr": "WAN", "if": "ax1", "lock": "1"},
    ]
}


@pytest.mark.asyncio
async def test_creating_a_loopback_says_it_is_inert_until_reconfigured() -> None:
    """A created device does not exist on the system, or in the assignable list.

    Until loopback_settings/reconfigure runs, assigning it fails with
    "Option [] not in list", which reads as though the device were never made.
    """
    client = _client()
    _stub(client, {})

    result = await MkLoopbackTool(client).execute({"description": "test"})

    assert result["status"] == "success"
    assert "reconfigure" in result["note"].lower() or "apply" in result["note"].lower()


@pytest.mark.asyncio
async def test_creating_with_apply_instantiates_it() -> None:
    client = _client()
    calls = _stub(client, {})

    await MkLoopbackTool(client).execute({"description": "test", "apply": True})

    assert [c for c in calls if "loopback_settings/reconfigure" in c["endpoint"]]


@pytest.mark.asyncio
async def test_deleting_an_assigned_loopback_is_refused_with_the_reason() -> None:
    """The API's own error is "Interface locked, unset lock first before removal".

    Deleting the device while an interface still points at it leaves an
    assignment referring to nothing, which is what happened on the live box.
    """
    client = _client()
    calls = _stub(
        client,
        {
            "loopback_settings/search_item": {
                "rows": [{"uuid": "lo-uuid", "deviceId": "1"}]
            },
            "assignment/search_item": ASSIGNED_ROWS,
        },
    )

    challenge = await RmLoopbackTool(client).execute({"uuid": "lo-uuid"})
    result = await RmLoopbackTool(client).execute(
        {"uuid": "lo-uuid", "confirm": challenge["confirm_token"]}
    )

    assert result["status"] == "error"
    assert "opt12" in result["error"]
    assert not [c for c in calls if "loopback_settings/del_item" in c["endpoint"]]


@pytest.mark.asyncio
async def test_deleting_an_unassigned_loopback_proceeds() -> None:
    client = _client()
    calls = _stub(
        client,
        {
            "loopback_settings/search_item": {
                "rows": [{"uuid": "lo-uuid", "deviceId": "9"}]
            },
            "assignment/search_item": {"rows": []},
        },
    )

    challenge = await RmLoopbackTool(client).execute({"uuid": "lo-uuid"})
    result = await RmLoopbackTool(client).execute(
        {"uuid": "lo-uuid", "confirm": challenge["confirm_token"]}
    )

    assert result["deleted"] is True
    assert [c for c in calls if "loopback_settings/del_item" in c["endpoint"]]


@pytest.mark.asyncio
async def test_a_loopback_created_with_an_address_says_exactly_what_to_set() -> None:
    """Addressing has no API, so the tool hands over the values instead.

    "do it in the UI" is not an instruction. The caller already knows the
    address it wanted; echoing it back with the page and the field names is the
    difference between a dead end and a two-minute step.
    """
    client = _client()
    _stub(client, {})

    result = await MkLoopbackTool(client).execute(
        {
            "description": "bgp",
            "planned_address": "172.16.99.2",
            "planned_subnet_bits": 32,
        }
    )

    manual = result["manual_step"]
    assert manual["address"] == "172.16.99.2"
    assert manual["subnet_bits"] == 32
    assert "Interfaces" in manual["where"]
    assert "172.16.99.2/32" in manual["instruction"]


@pytest.mark.asyncio
async def test_the_address_is_never_posted_since_the_model_would_swallow_it() -> None:
    """set_item accepts ipaddr and returns saved while changing nothing."""
    client = _client()
    calls = _stub(client, {})

    await MkLoopbackTool(client).execute(
        {
            "description": "bgp",
            "planned_address": "172.16.99.2",
            "planned_subnet_bits": 32,
        }
    )

    posted = json.dumps([c.get("json") for c in calls])
    assert "172.16.99.2" not in posted


@pytest.mark.asyncio
async def test_an_address_without_a_prefix_is_refused() -> None:
    """A loopback with the wrong prefix advertises a subnet it does not own."""
    client = _client()
    _stub(client, {})

    result = await MkLoopbackTool(client).execute(
        {"description": "bgp", "planned_address": "172.16.99.2"}
    )

    assert result["status"] == "error"
    assert "planned_subnet_bits" in result["error"]


@pytest.mark.asyncio
async def test_no_address_means_no_manual_step() -> None:
    client = _client()
    _stub(client, {})

    result = await MkLoopbackTool(client).execute({"description": "bgp"})

    assert "manual_step" not in result
