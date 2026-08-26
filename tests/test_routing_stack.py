"""VLAN devices, gateways and static routes.

The three objects a routed transit needs: a tagged device, a next hop, and a
prefix pointed at it.

The polarity trap this wave has to survive: routes carry `enabled`, gateways
carry `disabled`. Two objects in the same wave with opposite senses, confirmed
from the firmware models (`Routes/Route.xml`, `Routing/Gateways.xml`). The
published docs also describe route toggling with a `$disabled` argument, which
this build contradicts.

Because of that, enable and disable are done by reading the object and writing
the field back, not by calling a toggle endpoint whose argument sense is
ambiguous. The state asked for is the state written.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from opnsense_mcp.tools.routing_stack import (
    ListGatewaysTool,
    ListRoutesTool,
    ListVlansTool,
    MkGatewayTool,
    MkRouteTool,
    MkVlanTool,
    RmRouteTool,
    RmVlanTool,
    ToggleGatewayTool,
    ToggleRouteTool,
)
from opnsense_mcp.utils.api import OPNsenseClient

VLAN_UUID = "vlan-1111"
GW_UUID = "gw-2222"
ROUTE_UUID = "rt-3333"

VLAN_ROWS = {
    "rows": [
        {
            "uuid": VLAN_UUID,
            "if": "ax0",
            "tag": "2",
            "pcp": "0",
            "descr": "wired",
            "vlanif": "ax0_vlan2 [VLAN2wired]",
        }
    ],
    "total": 1,
}

GW_ROWS = {
    "rows": [
        {
            "uuid": GW_UUID,
            "name": "TRANSIT_INTERNAL",
            "interface": "opt2",
            "gateway": "172.31.0.2",
            "ipprotocol": "inet",
            "disabled": "0",
            "fargw": "1",
            "monitor_disable": "1",
            "descr": "fabric transit",
            # search_gateway mixes live status into the same row
            "status": "none",
            "stddev": "0.1",
            "current_latencyhigh": "500",
        }
    ],
    "total": 1,
}

ROUTE_ROWS = {
    "rows": [
        {
            "uuid": ROUTE_UUID,
            "network": "172.20.2.0/24",
            "gateway": "TRANSIT_INTERNAL",
            "descr": "wired via fabric",
            "enabled": "1",
        }
    ],
    "total": 1,
}

GET_GW = {
    "gateway_item": {
        "name": "TRANSIT_INTERNAL",
        "interface": {"opt2": {"selected": 1, "value": "VLAN2"}},
        "gateway": "172.31.0.2",
        "ipprotocol": {"inet": {"selected": 1, "value": "IPv4"}},
        "disabled": "0",
        "fargw": "1",
        "monitor_disable": "1",
        "priority": "255",
        "weight": "1",
        "descr": "fabric transit",
    }
}

GET_ROUTE = {
    "route": {
        "network": "172.20.2.0/24",
        "gateway": {"TRANSIT_INTERNAL": {"selected": 1, "value": "TRANSIT"}},
        "descr": "wired via fabric",
        "enabled": "1",
    }
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
                return value
        return {"result": "saved", "uuid": "new-uuid"}

    client._make_request = AsyncMock(side_effect=fake)
    return calls


# --- VLAN ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mk_vlan_uses_parent_and_tag() -> None:
    client = _client()
    calls = _stub(client, {"search_item": {"rows": [], "total": 0}})

    result = await MkVlanTool(client).execute(
        {"parent": "ax0", "tag": 900, "description": "INTERNAL transit"}
    )

    assert result["status"] == "success"
    payload = next(c for c in calls if "add_item" in c["endpoint"])["json"]["vlan"]
    assert payload["if"] == "ax0"
    assert payload["tag"] == "900"
    assert "vlanif" not in payload


@pytest.mark.asyncio
async def test_mk_vlan_reuses_an_existing_device() -> None:
    """Never delete and recreate: the device may already carry an assignment."""
    client = _client()
    calls = _stub(client, {"search_item": VLAN_ROWS})

    result = await MkVlanTool(client).execute({"parent": "ax0", "tag": 2})

    assert result["created"] is False
    assert result["uuid"] == VLAN_UUID
    assert not [c for c in calls if "add_item" in c["endpoint"]]


@pytest.mark.asyncio
async def test_rm_vlan_refuses_while_assigned() -> None:
    """Deleting an assigned device takes the interface with it."""
    client = _client()
    _stub(
        client,
        {
            "search_item": VLAN_ROWS,
            "overview/export": [{"device": "ax0_vlan2", "identifier": "opt2"}],
        },
    )
    tool = RmVlanTool(client)

    first = await tool.execute({"uuid": VLAN_UUID})
    result = await tool.execute(
        {"uuid": VLAN_UUID, "confirm": first.get("confirm_token", "x")}
    )

    assert result["status"] == "error"
    assert "assigned" in result["error"]


@pytest.mark.asyncio
async def test_list_vlans_projects_fields() -> None:
    client = _client()
    _stub(client, {"search_item": VLAN_ROWS})

    result = await ListVlansTool(client).execute({})

    assert result["vlans"][0]["parent"] == "ax0"
    assert result["vlans"][0]["tag"] == "2"


# --- gateways --------------------------------------------------------------


@pytest.mark.asyncio
async def test_mk_gateway_writes_disabled_not_enabled() -> None:
    """The gateway model has no `enabled` field."""
    client = _client()
    calls = _stub(client, {"search_gateway": {"rows": [], "total": 0}})

    await MkGatewayTool(client).execute(
        {
            "name": "TRANSIT_INTERNAL",
            "interface": "opt2",
            "gateway": "172.31.0.2",
            "far_gateway": True,
            "monitor_disable": True,
        }
    )

    payload = next(c for c in calls if "add_gateway" in c["endpoint"])["json"][
        "gateway_item"
    ]
    assert payload["disabled"] == "0"
    assert "enabled" not in payload
    assert payload["fargw"] == "1"
    assert payload["monitor_disable"] == "1"


@pytest.mark.asyncio
async def test_mk_gateway_is_idempotent_on_interface_and_address() -> None:
    client = _client()
    calls = _stub(client, {"search_gateway": GW_ROWS})

    result = await MkGatewayTool(client).execute(
        {"name": "OTHER", "interface": "opt2", "gateway": "172.31.0.2"}
    )

    assert result["created"] is False
    assert not [c for c in calls if "add_gateway" in c["endpoint"]]


@pytest.mark.asyncio
async def test_list_gateways_separates_config_from_status() -> None:
    """One row carries both; a caller reading it as config gets 44 fields."""
    client = _client()
    _stub(client, {"search_gateway": GW_ROWS})

    result = await ListGatewaysTool(client).execute({})

    gw = result["gateways"][0]
    assert gw["gateway"] == "172.31.0.2"
    assert gw["disabled"] == "0"
    assert "current_latencyhigh" not in gw
    assert "stddev" not in gw


@pytest.mark.asyncio
async def test_toggle_gateway_disables_by_writing_disabled_true() -> None:
    """enabled=False must become disabled=1, not disabled=0."""
    client = _client()
    calls = _stub(client, {"get_gateway": GET_GW, "search_gateway": GW_ROWS})

    result = await ToggleGatewayTool(client).execute(
        {"uuid": GW_UUID, "enabled": False}
    )

    assert result["status"] == "success"
    payload = next(c for c in calls if "set_gateway" in c["endpoint"])["json"][
        "gateway_item"
    ]
    assert payload["disabled"] == "1"


@pytest.mark.asyncio
async def test_toggle_gateway_enables_by_writing_disabled_false() -> None:
    client = _client()
    calls = _stub(client, {"get_gateway": GET_GW, "search_gateway": GW_ROWS})

    await ToggleGatewayTool(client).execute({"uuid": GW_UUID, "enabled": True})

    payload = next(c for c in calls if "set_gateway" in c["endpoint"])["json"][
        "gateway_item"
    ]
    assert payload["disabled"] == "0"


@pytest.mark.asyncio
async def test_toggle_gateway_preserves_other_fields() -> None:
    client = _client()
    calls = _stub(client, {"get_gateway": GET_GW, "search_gateway": GW_ROWS})

    await ToggleGatewayTool(client).execute({"uuid": GW_UUID, "enabled": False})

    payload = next(c for c in calls if "set_gateway" in c["endpoint"])["json"][
        "gateway_item"
    ]
    assert payload["fargw"] == "1"
    assert payload["monitor_disable"] == "1"
    assert payload["gateway"] == "172.31.0.2"


# --- routes ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_mk_route_writes_enabled_not_disabled() -> None:
    """The route model has no `disabled` field; the docs are wrong about this."""
    client = _client()
    calls = _stub(client, {"searchroute": {"rows": [], "total": 0}})

    await MkRouteTool(client).execute(
        {"network": "172.20.2.0/24", "gateway": "TRANSIT_INTERNAL"}
    )

    payload = next(c for c in calls if "addroute" in c["endpoint"])["json"]["route"]
    assert payload["enabled"] == "1"
    assert "disabled" not in payload


@pytest.mark.asyncio
async def test_toggle_route_disables_by_writing_enabled_false() -> None:
    """Opposite sense to the gateway, on purpose."""
    client = _client()
    calls = _stub(client, {"getroute": GET_ROUTE, "searchroute": ROUTE_ROWS})

    await ToggleRouteTool(client).execute({"uuid": ROUTE_UUID, "enabled": False})

    payload = next(c for c in calls if "setroute" in c["endpoint"])["json"]["route"]
    assert payload["enabled"] == "0"
    assert "disabled" not in payload


@pytest.mark.asyncio
async def test_mk_route_is_idempotent_on_network_and_gateway() -> None:
    client = _client()
    calls = _stub(client, {"searchroute": ROUTE_ROWS})

    result = await MkRouteTool(client).execute(
        {"network": "172.20.2.0/24", "gateway": "TRANSIT_INTERNAL"}
    )

    assert result["created"] is False
    assert not [c for c in calls if "addroute" in c["endpoint"]]


@pytest.mark.asyncio
async def test_mk_route_rejects_a_malformed_network() -> None:
    client = _client()
    _stub(client, {"searchroute": {"rows": [], "total": 0}})

    result = await MkRouteTool(client).execute(
        {"network": "not-a-network", "gateway": "TRANSIT_INTERNAL"}
    )

    assert result["status"] == "error"
    assert "network" in result["error"]


@pytest.mark.asyncio
async def test_route_delete_needs_confirmation() -> None:
    client = _client()
    _stub(client, {"searchroute": ROUTE_ROWS})

    result = await RmRouteTool(client).execute({"uuid": ROUTE_UUID})

    assert result["status"] == "confirmation_required"


@pytest.mark.asyncio
async def test_list_routes_projects_fields() -> None:
    client = _client()
    _stub(client, {"searchroute": ROUTE_ROWS})

    result = await ListRoutesTool(client).execute({})

    assert result["routes"][0]["network"] == "172.20.2.0/24"
    assert result["routes"][0]["enabled"] == "1"


# --- staging ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_routing_writes_stage_by_default() -> None:
    """Reconfiguring routes mid-change can drop the path being worked over."""
    client = _client()
    calls = _stub(client, {"searchroute": {"rows": [], "total": 0}})

    await MkRouteTool(client).execute(
        {"network": "172.20.2.0/24", "gateway": "TRANSIT_INTERNAL"}
    )

    assert not [c for c in calls if "reconfigure" in c["endpoint"]]
