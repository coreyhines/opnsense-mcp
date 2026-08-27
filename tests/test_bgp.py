"""FRR BGP: reading state, and managing neighbours.

FRR is installed on the target firewall but switched off: `general.enabled` and
`bgp.enabled` are both "0" and no daemons are selected. That is the state these
tools have to be useful in, because the operator needs to see what is there
before turning anything on, and "off" has to read as a clear answer rather than
as an error.

The one field worth staring at is `enabled` on a neighbour, which the API
defaults to "1". Creating a peer therefore means "start trying to establish a
session with it", which is a live network action rather than a staged change.
These tools default it off and make the caller ask for it.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from opnsense_mcp.tools.bgp import (
    BgpStatusTool,
    ListBgpNeighborsTool,
    MkBgpNeighborTool,
    RmBgpNeighborTool,
    ToggleBgpNeighborTool,
)
from opnsense_mcp.utils.api import OPNsenseClient

NEIGHBOR_UUID = "nbr-1234"

BGP_OFF = {
    "bgp": {
        "enabled": "0",
        "asnumber": "65551",
        "routerid": "",
        "networkimportcheck": "1",
    }
}

GENERAL_OFF = {
    "general": {
        "enabled": "0",
        "daemons": {
            "bfd": {"value": "bfd", "selected": 0},
            "bgp": {"value": "bgp", "selected": 0},
            "ospf": {"value": "ospf", "selected": 0},
        },
    }
}

GENERAL_ON = {
    "general": {
        "enabled": "1",
        "daemons": {
            "bfd": {"value": "bfd", "selected": 0},
            "bgp": {"value": "bgp", "selected": 1},
            "ospf": {"value": "ospf", "selected": 0},
        },
    }
}

NEIGHBOR_ROWS = {
    "rows": [
        {
            "uuid": NEIGHBOR_UUID,
            "enabled": "1",
            "address": "198.51.100.2",
            "remoteas": "65002",
            "remote_as_mode": "",
            "description": "border leaf",
            "updatesource": "lo0",
            "multihop": "1",
            "bfd": "1",
            "password": "hunter2",
        }
    ],
    "total": 1,
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
        return {"result": "saved", "uuid": "new-uuid"}

    client._make_request = AsyncMock(side_effect=fake)
    return calls


# --- status ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_status_reports_off_as_a_result_not_an_error() -> None:
    """FRR being installed and idle is the normal starting state."""
    client = _client()
    _stub(
        client,
        {
            "general/get": GENERAL_OFF,
            "bgp/get": BGP_OFF,
            "searchNeighbor": {"rows": [], "total": 0},
            "bgpsummary": {"response": []},
            "service/status": {"status": "disabled"},
        },
    )

    result = await BgpStatusTool(client).execute({})

    assert result["status"] == "success"
    assert result["frr_enabled"] is False
    assert result["bgp_enabled"] is False
    assert result["running"] is False
    assert result["neighbor_count"] == 0


@pytest.mark.asyncio
async def test_status_reports_the_as_number_and_router_id() -> None:
    client = _client()
    _stub(
        client,
        {
            "general/get": GENERAL_ON,
            "bgp/get": {
                "bgp": {"enabled": "1", "asnumber": "65001", "routerid": "198.51.100.1"}
            },
            "searchNeighbor": NEIGHBOR_ROWS,
            "bgpsummary": {"response": []},
            "service/status": {"status": "running"},
        },
    )

    result = await BgpStatusTool(client).execute({})

    assert result["as_number"] == "65001"
    assert result["router_id"] == "198.51.100.1"
    assert result["running"] is True
    assert result["neighbor_count"] == 1


@pytest.mark.asyncio
async def test_status_says_when_the_bgp_daemon_is_not_selected() -> None:
    """FRR can be enabled with bgp unselected, which looks like BGP is on."""
    client = _client()
    _stub(
        client,
        {
            "general/get": {
                "general": {
                    "enabled": "1",
                    "daemons": {"bgp": {"value": "bgp", "selected": 0}},
                }
            },
            "bgp/get": {"bgp": {"enabled": "1", "asnumber": "65001"}},
            "searchNeighbor": {"rows": [], "total": 0},
            "bgpsummary": {"response": []},
            "service/status": {"status": "running"},
        },
    )

    result = await BgpStatusTool(client).execute({})

    assert result["bgp_daemon_selected"] is False
    assert "daemon" in result["note"].lower()


# --- neighbours ------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_neighbors_never_returns_the_password() -> None:
    """The model stores the MD5 secret in clear, and listing is a read anyone does."""
    client = _client()
    _stub(client, {"searchNeighbor": NEIGHBOR_ROWS})

    result = await ListBgpNeighborsTool(client).execute({})

    row = result["neighbors"][0]
    assert row["address"] == "198.51.100.2"
    assert "password" not in row
    assert row["password_set"] is True


@pytest.mark.asyncio
async def test_list_neighbors_reports_no_password_as_such() -> None:
    client = _client()
    rows = {"rows": [dict(NEIGHBOR_ROWS["rows"][0], password="")], "total": 1}
    _stub(client, {"searchNeighbor": rows})

    result = await ListBgpNeighborsTool(client).execute({})

    assert result["neighbors"][0]["password_set"] is False


@pytest.mark.asyncio
async def test_create_neighbor_is_staged_disabled_by_default() -> None:
    """The API default is enabled=1, which starts a session attempt at once."""
    client = _client()
    calls = _stub(client, {"searchNeighbor": {"rows": [], "total": 0}})

    result = await MkBgpNeighborTool(client).execute(
        {"address": "198.51.100.9", "remote_as": "65009"}
    )

    assert result["status"] == "success"
    payload = next(c for c in calls if "addNeighbor" in c["endpoint"])["json"][
        "neighbor"
    ]
    assert payload["enabled"] == "0"
    assert payload["address"] == "198.51.100.9"
    assert payload["remoteas"] == "65009"


@pytest.mark.asyncio
async def test_create_neighbor_can_be_enabled_explicitly() -> None:
    client = _client()
    calls = _stub(client, {"searchNeighbor": {"rows": [], "total": 0}})

    await MkBgpNeighborTool(client).execute(
        {"address": "198.51.100.9", "remote_as": "65009", "enabled": True}
    )

    payload = next(c for c in calls if "addNeighbor" in c["endpoint"])["json"][
        "neighbor"
    ]
    assert payload["enabled"] == "1"


@pytest.mark.asyncio
async def test_create_neighbor_requires_an_as_or_a_mode() -> None:
    """A peer with neither is accepted by the model and never establishes."""
    client = _client()
    _stub(client, {"searchNeighbor": {"rows": [], "total": 0}})

    result = await MkBgpNeighborTool(client).execute({"address": "198.51.100.9"})

    assert result["status"] == "error"
    assert "remote_as" in result["error"]


@pytest.mark.asyncio
async def test_create_neighbor_refuses_an_as_and_a_mode_together() -> None:
    """internal and external derive the AS; giving both says two things at once."""
    client = _client()
    _stub(client, {"searchNeighbor": {"rows": [], "total": 0}})

    result = await MkBgpNeighborTool(client).execute(
        {"address": "198.51.100.9", "remote_as": "65009", "remote_as_mode": "external"}
    )

    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_create_neighbor_accepts_a_mode_alone() -> None:
    client = _client()
    calls = _stub(client, {"searchNeighbor": {"rows": [], "total": 0}})

    await MkBgpNeighborTool(client).execute(
        {"address": "198.51.100.9", "remote_as_mode": "external"}
    )

    payload = next(c for c in calls if "addNeighbor" in c["endpoint"])["json"][
        "neighbor"
    ]
    assert payload["remote_as_mode"] == "external"
    assert payload["remoteas"] == ""


@pytest.mark.asyncio
async def test_create_neighbor_is_idempotent_on_address() -> None:
    """One peer address, one neighbour; a duplicate is a configuration error."""
    client = _client()
    calls = _stub(client, {"searchNeighbor": NEIGHBOR_ROWS})

    result = await MkBgpNeighborTool(client).execute(
        {"address": "198.51.100.2", "remote_as": "65002"}
    )

    assert result["created"] is False
    assert result["uuid"] == NEIGHBOR_UUID
    assert not [c for c in calls if "addNeighbor" in c["endpoint"]]


@pytest.mark.asyncio
async def test_toggle_takes_an_explicit_state() -> None:
    client = _client()
    calls = _stub(client, {"searchNeighbor": NEIGHBOR_ROWS})

    await ToggleBgpNeighborTool(client).execute(
        {"uuid": NEIGHBOR_UUID, "enabled": False}
    )

    toggle = next(c for c in calls if "toggleNeighbor" in c["endpoint"])
    assert toggle["endpoint"].endswith("/0")


@pytest.mark.asyncio
async def test_delete_neighbor_needs_confirmation() -> None:
    client = _client()
    calls = _stub(client, {"searchNeighbor": NEIGHBOR_ROWS})

    result = await RmBgpNeighborTool(client).execute({"uuid": NEIGHBOR_UUID})

    assert result["status"] == "confirmation_required"
    assert not [c for c in calls if "delNeighbor" in c["endpoint"]]


@pytest.mark.asyncio
async def test_writes_do_not_apply_by_default() -> None:
    """Applying restarts FRR, which drops every established session."""
    client = _client()
    calls = _stub(client, {"searchNeighbor": {"rows": [], "total": 0}})

    await MkBgpNeighborTool(client).execute(
        {"address": "198.51.100.9", "remote_as": "65009"}
    )

    assert not [c for c in calls if "reconfigure" in c["endpoint"]]
