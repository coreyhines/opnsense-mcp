"""Outbound source NAT, and reachability from the firewall's point of view.

Source NAT is what lets a routed prefix reach the internet once it is no longer
a directly connected network on the firewall. The mode matters as much as the
rules: `automatic` generates them from connected networks, `hybrid` keeps those
and adds yours, `advanced` replaces them entirely.

`fw_ping` answers a question no existing tool could: is the next hop reachable
*from the firewall*, rather than from wherever the MCP server happens to run.
The API models it as a job, so the tool submits, polls and cleans up.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from opnsense_mcp.tools.nat_outbound import (
    FwPingTool,
    ListNatOutboundTool,
    MkNatOutboundTool,
    NatOutboundModeTool,
    RmNatOutboundTool,
    ToggleNatOutboundTool,
)
from opnsense_mcp.utils.api import OPNsenseClient

NAT_UUID = "nat-1234"

NAT_ROWS = {
    "rows": [
        {
            "uuid": NAT_UUID,
            "interface": "wan",
            "source_net": "FABRIC_INTERNAL",
            "destination_net": "any",
            "target": "",
            "staticnatport": "0",
            "enabled": "1",
            "description": "fabric out",
            "alias_meta_source_net": "internal prefixes",
            "category_colors": [],
        }
    ],
    "total": 1,
}

MODE_HYBRID = {
    "filter": {
        "general": {
            "snat_mode": {
                "automatic": {"value": "Automatic", "selected": 0},
                "hybrid": {"value": "Hybrid", "selected": 1},
                "advanced": {"value": "Manual", "selected": 0},
                "disabled": {"value": "Disabled", "selected": 0},
            }
        }
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
                return value() if callable(value) else value
        return {"result": "saved", "uuid": "new-uuid"}

    client._make_request = AsyncMock(side_effect=fake)
    return calls


# --- mode ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mode_reports_the_selected_value() -> None:
    client = _client()
    _stub(client, {"source_nat/get": MODE_HYBRID})

    result = await NatOutboundModeTool(client).execute({"action_mode": "get"})

    assert result["mode"] == "hybrid"


@pytest.mark.asyncio
async def test_mode_refuses_advanced() -> None:
    """Manual generation drops the implicit rules for management and VPN nets."""
    client = _client()
    _stub(client, {"source_nat/get": MODE_HYBRID})

    result = await NatOutboundModeTool(client).execute(
        {"action_mode": "set", "mode": "advanced"}
    )

    assert result["status"] == "error"
    assert "hybrid" in result["error"]


@pytest.mark.asyncio
async def test_mode_refuses_disabled() -> None:
    client = _client()
    _stub(client, {"source_nat/get": MODE_HYBRID})

    result = await NatOutboundModeTool(client).execute(
        {"action_mode": "set", "mode": "disabled"}
    )

    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_mode_allows_hybrid() -> None:
    client = _client()
    calls = _stub(client, {"source_nat/get": MODE_HYBRID})

    result = await NatOutboundModeTool(client).execute(
        {"action_mode": "set", "mode": "hybrid"}
    )

    assert result["status"] == "success"
    assert [c for c in calls if "source_nat/set" in c["endpoint"]]


# --- rules -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_projects_and_drops_display_metadata() -> None:
    client = _client()
    _stub(client, {"search_rule": NAT_ROWS})

    result = await ListNatOutboundTool(client).execute({})

    rule = result["rules"][0]
    assert rule["source_net"] == "FABRIC_INTERNAL"
    assert "alias_meta_source_net" not in rule
    assert "category_colors" not in rule


@pytest.mark.asyncio
async def test_create_defaults_to_interface_address_translation() -> None:
    """An empty target means the interface address, which is what a border wants."""
    client = _client()
    calls = _stub(client, {"search_rule": {"rows": [], "total": 0}})

    result = await MkNatOutboundTool(client).execute(
        {"interface": "wan", "source_net": "FABRIC_INTERNAL"}
    )

    assert result["status"] == "success"
    payload = next(c for c in calls if "add_rule" in c["endpoint"])["json"]["rule"]
    assert payload["interface"] == "wan"
    assert payload["source_net"] == "FABRIC_INTERNAL"
    assert payload["target"] == ""
    assert payload["staticnatport"] == "0"


@pytest.mark.asyncio
async def test_create_is_idempotent_on_interface_and_source() -> None:
    client = _client()
    calls = _stub(client, {"search_rule": NAT_ROWS})

    result = await MkNatOutboundTool(client).execute(
        {"interface": "wan", "source_net": "FABRIC_INTERNAL"}
    )

    assert result["created"] is False
    assert not [c for c in calls if "add_rule" in c["endpoint"]]


@pytest.mark.asyncio
async def test_create_requires_a_source() -> None:
    """A rule with no source would translate everything leaving the interface."""
    client = _client()
    _stub(client, {"search_rule": {"rows": [], "total": 0}})

    result = await MkNatOutboundTool(client).execute({"interface": "wan"})

    assert result["status"] == "error"
    assert "source_net" in result["error"]


@pytest.mark.asyncio
async def test_toggle_takes_an_explicit_state() -> None:
    client = _client()
    calls = _stub(client, {"search_rule": NAT_ROWS})

    await ToggleNatOutboundTool(client).execute({"uuid": NAT_UUID, "enabled": False})

    toggle = next(c for c in calls if "toggle_rule" in c["endpoint"])
    assert toggle["endpoint"].endswith("/0")


@pytest.mark.asyncio
async def test_delete_needs_confirmation() -> None:
    client = _client()
    calls = _stub(client, {"search_rule": NAT_ROWS})

    result = await RmNatOutboundTool(client).execute({"uuid": NAT_UUID})

    assert result["status"] == "confirmation_required"
    assert not [c for c in calls if "del_rule" in c["endpoint"]]


@pytest.mark.asyncio
async def test_nat_writes_stage_by_default() -> None:
    client = _client()
    calls = _stub(client, {"search_rule": {"rows": [], "total": 0}})

    await MkNatOutboundTool(client).execute(
        {"interface": "wan", "source_net": "FABRIC_INTERNAL"}
    )

    assert not [c for c in calls if "apply" in c["endpoint"]]


# --- ping ------------------------------------------------------------------
#
# The job runs until it is stopped: `status` stays "running" for as long as the
# process lives, and the row carries live counters rather than command output.
# So the tool waits for `count` packets, stops, reads the final row, removes.


def _ping_rows(sent: int, received: int, status: str = "running") -> dict[str, Any]:
    loss = f"{(sent - received) / sent * 100:.1f}%" if sent else "0.0%"
    return {
        "rows": [
            {
                "id": "job-1",
                "hostname": "172.31.0.2",
                "status": status,
                "send": sent,
                "received": received,
                "loss": loss,
                "min": 0.4,
                "avg": 0.5,
                "max": 0.6,
                "last_error": None,
            }
        ]
    }


@pytest.mark.asyncio
async def test_ping_waits_for_the_requested_packets_then_stops() -> None:
    """`count` is how many packets to wait for; nothing in the model bounds the run."""
    client = _client()
    sent = {"n": 0}

    def jobs() -> dict[str, Any]:
        sent["n"] += 1
        return _ping_rows(sent["n"], sent["n"])

    calls = _stub(client, {"ping/set": {"uuid": "job-1"}, "searchJobs": jobs})

    result = await FwPingTool(client).execute({"target": "172.31.0.2", "count": 3})

    assert result["status"] == "success"
    assert result["transmitted"] >= 3
    assert result["received"] >= 3
    assert result["loss"] == "0.0%"
    assert [c for c in calls if "ping/stop" in c["endpoint"]]
    assert [c for c in calls if "ping/remove" in c["endpoint"]]


@pytest.mark.asyncio
async def test_ping_polls_on_the_id_key() -> None:
    """searchJobs rows are keyed `id`; matching on `uuid` finds nothing."""
    client = _client()
    _stub(
        client, {"ping/set": {"uuid": "job-1"}, "searchJobs": lambda: _ping_rows(3, 3)}
    )

    result = await FwPingTool(client).execute({"target": "172.31.0.2", "count": 1})

    assert result["transmitted"] == 3


@pytest.mark.asyncio
async def test_ping_reports_an_unreachable_target_as_loss_not_an_error() -> None:
    """The job succeeds; the packets are what failed. The caller needs both."""
    client = _client()
    _stub(
        client,
        {"ping/set": {"uuid": "job-1"}, "searchJobs": lambda: _ping_rows(3, 0)},
    )

    result = await FwPingTool(client).execute({"target": "172.31.0.2", "count": 1})

    assert result["status"] == "success"
    assert result["reachable"] is False
    assert result["loss"] == "100.0%"


@pytest.mark.asyncio
async def test_ping_payload_matches_the_model() -> None:
    """The model nests under `settings`, and the family keys are ip and ip6."""
    client = _client()
    calls = _stub(
        client,
        {"ping/set": {"uuid": "job-1"}, "searchJobs": lambda: _ping_rows(3, 3)},
    )

    await FwPingTool(client).execute(
        {"target": "2001:db8::1", "family": "inet6", "count": 1}
    )

    payload = next(c for c in calls if "ping/set" in c["endpoint"])["json"]
    assert payload["ping"]["settings"]["hostname"] == "2001:db8::1"
    assert payload["ping"]["settings"]["fam"] == "ip6"


@pytest.mark.asyncio
async def test_ping_requires_a_target() -> None:
    client = _client()

    result = await FwPingTool(client).execute({})

    assert result["status"] == "error"
    assert "target" in result["error"]


@pytest.mark.asyncio
async def test_ping_stops_and_removes_the_job_even_when_it_fails() -> None:
    """A running job left behind pings forever."""
    client = _client()
    calls: list[dict[str, Any]] = []

    async def fake(method: str, endpoint: str, **kwargs: Any) -> Any:
        calls.append({"endpoint": endpoint})
        if "ping/set" in endpoint:
            return {"uuid": "job-1"}
        if "searchJobs" in endpoint:
            raise RuntimeError("poll failed")
        return {"status": "ok"}

    client._make_request = AsyncMock(side_effect=fake)

    result = await FwPingTool(client).execute({"target": "172.31.0.2"})

    assert result["status"] == "error"
    assert [c for c in calls if "ping/stop" in c["endpoint"]]
    assert [c for c in calls if "ping/remove" in c["endpoint"]]
