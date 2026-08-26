"""NPTv6, virtual IP and loopback tools.

These are the objects a ULA conversion needs: a stable fd00::/8 prefix on the
LAN interfaces (VIP), a 1:1 prefix translation to the delegated GUA on WAN
(NPT), and optionally a loopback to hold the delegated prefix once the LAN
stops carrying it.

Field names come from the firmware's own model, `Filter.xml` under `<npt>` and
`Interfaces/Vip.xml`, not from documentation:

    npt: interface, source_net, destination_net, trackif, enabled, log
    vip: interface, mode, subnet, subnet_bits, descr, password, vhid

`source_net` is the internal prefix and `destination_net` the external one. The
spec had guessed `internal_prefix` and `external_prefix`, which do not exist.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from opnsense_mcp.tools.ipv6_stack import (
    ListLoopbackTool,
    ListNptRulesTool,
    ListVipTool,
    MkLoopbackTool,
    MkNptRuleTool,
    MkVipTool,
    RmNptRuleTool,
    RmVipTool,
    ToggleNptRuleTool,
)
from opnsense_mcp.utils.api import OPNsenseClient

NPT_UUID = "11111111-2222-3333-4444-555555555555"
VIP_UUID = "66666666-7777-8888-9999-000000000000"

# One rule per VLAN /64, which is what the ULA layout needs.
NPT_ROWS = {
    "rows": [
        {
            "uuid": NPT_UUID,
            "interface": "wan",
            "source_net": "fd0b:b022:1e5:2::/64",
            "destination_net": "",
            "trackif": "lan",
            "enabled": "1",
            "description": "wired VLAN",
        }
    ],
    "total": 1,
}

VIP_ROWS = {
    "rows": [
        {
            "uuid": VIP_UUID,
            "interface": "lan",
            "mode": "ipalias",
            "subnet": "fd0b:b022:1e5:2::1",
            "subnet_bits": "64",
            "descr": "ULA gateway",
            "password": "carp-secret",
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
                return value
        return {"result": "saved", "uuid": "new-uuid"}

    client._make_request = AsyncMock(side_effect=fake)
    return calls


# --- NPT: the validations that stop a broken v6 layout ----------------------


@pytest.mark.asyncio
async def test_npt_rejects_no_external_and_no_track() -> None:
    """Without either, the rule cannot know the delegated prefix.

    The forum guidance is explicit that this breaks WAN IPv6 listeners,
    WireGuard among them.
    """
    client = _client()
    _stub(client, {"search_rule": {"rows": [], "total": 0}})

    result = await MkNptRuleTool(client).execute(
        {"interface": "wan", "source_net": "fd0b:b022:1e5:2::/64"}
    )

    assert result["status"] == "error"
    assert "trackif" in result["error"]


@pytest.mark.asyncio
async def test_npt_rejects_a_prefix_shorter_than_64() -> None:
    """One /48 or /60 rule cannot express this layout.

    The VLAN ids place some prefixes outside any single /60, so the mapping is
    one rule per /64. A short prefix silently covers the wrong ranges.
    """
    client = _client()
    _stub(client, {"search_rule": {"rows": [], "total": 0}})

    result = await MkNptRuleTool(client).execute(
        {"interface": "wan", "source_net": "fd0b:b022:1e5::/48", "trackif": "lan"}
    )

    assert result["status"] == "error"
    assert "/64" in result["error"]


@pytest.mark.asyncio
async def test_npt_rejects_a_second_rule_onto_the_same_external_prefix() -> None:
    """Many internal /64 onto one external /64 is outbound-only and breaks inbound."""
    client = _client()
    _stub(
        client,
        {
            "search_rule": {
                "rows": [
                    {
                        "uuid": NPT_UUID,
                        "source_net": "fd0b:b022:1e5:2::/64",
                        "destination_net": "2001:db8:1e5:b502::/64",
                        "trackif": "",
                    }
                ],
                "total": 1,
            }
        },
    )

    result = await MkNptRuleTool(client).execute(
        {
            "interface": "wan",
            "source_net": "fd0b:b022:1e5:10::/64",
            "destination_net": "2001:db8:1e5:b502::/64",
        }
    )

    assert result["status"] == "error"
    assert "already maps" in result["error"]


@pytest.mark.asyncio
async def test_npt_rejects_a_non_ipv6_prefix() -> None:
    client = _client()
    _stub(client, {"search_rule": {"rows": [], "total": 0}})

    result = await MkNptRuleTool(client).execute(
        {"interface": "wan", "source_net": "172.20.2.0/24", "trackif": "lan"}
    )

    assert result["status"] == "error"
    assert "IPv6" in result["error"]


@pytest.mark.asyncio
async def test_npt_creates_with_the_real_field_names() -> None:
    """source_net and destination_net, not internal_prefix/external_prefix."""
    client = _client()
    calls = _stub(client, {"search_rule": {"rows": [], "total": 0}})

    result = await MkNptRuleTool(client).execute(
        {
            "interface": "wan",
            "source_net": "fd0b:b022:1e5:2::/64",
            "trackif": "lan",
            "description": "wired VLAN",
        }
    )

    assert result["status"] == "success"
    payload = next(c for c in calls if "add_rule" in c["endpoint"])["json"]["rule"]
    assert payload["source_net"] == "fd0b:b022:1e5:2::/64"
    assert payload["trackif"] == "lan"
    assert payload["interface"] == "wan"
    assert "internal_prefix" not in payload


@pytest.mark.asyncio
async def test_npt_is_idempotent_on_interface_and_source() -> None:
    client = _client()
    calls = _stub(client, {"search_rule": NPT_ROWS})

    result = await MkNptRuleTool(client).execute(
        {"interface": "wan", "source_net": "fd0b:b022:1e5:2::/64", "trackif": "lan"}
    )

    assert result["created"] is False
    assert result["uuid"] == NPT_UUID
    assert not [c for c in calls if "add_rule" in c["endpoint"]]


@pytest.mark.asyncio
async def test_npt_stages_without_applying_by_default() -> None:
    """Dataplane writes stage; apply_ula loads them."""
    client = _client()
    calls = _stub(client, {"search_rule": {"rows": [], "total": 0}})

    await MkNptRuleTool(client).execute(
        {"interface": "wan", "source_net": "fd0b:b022:1e5:2::/64", "trackif": "lan"}
    )

    assert not [c for c in calls if "apply" in c["endpoint"]]


@pytest.mark.asyncio
async def test_npt_toggle_takes_an_explicit_state() -> None:
    client = _client()
    calls = _stub(client, {"search_rule": NPT_ROWS})

    await ToggleNptRuleTool(client).execute({"uuid": NPT_UUID, "enabled": False})

    toggle = next(c for c in calls if "toggle_rule" in c["endpoint"])
    assert toggle["endpoint"].endswith("/0")


@pytest.mark.asyncio
async def test_npt_delete_needs_confirmation() -> None:
    client = _client()
    calls = _stub(client, {"search_rule": NPT_ROWS})
    tool = RmNptRuleTool(client)

    first = await tool.execute({"uuid": NPT_UUID})
    assert first["status"] == "confirmation_required"
    assert not [c for c in calls if "del_rule" in c["endpoint"]]

    second = await tool.execute({"uuid": NPT_UUID, "confirm": first["confirm_token"]})
    assert second["status"] == "success"


@pytest.mark.asyncio
async def test_npt_list_projects_useful_fields() -> None:
    client = _client()
    _stub(client, {"search_rule": NPT_ROWS})

    result = await ListNptRulesTool(client).execute({})

    assert result["count"] == 1
    assert result["rules"][0]["source_net"] == "fd0b:b022:1e5:2::/64"


# --- VIP -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_vip_defaults_to_ipalias_never_carp() -> None:
    """A CARP VIP with a stray vhid would fight the other node on a shared segment."""
    client = _client()
    calls = _stub(client, {"search_item": {"rows": [], "total": 0}})

    await MkVipTool(client).execute(
        {"interface": "lan", "subnet": "fd0b:b022:1e5:2::1", "subnet_bits": 64}
    )

    payload = next(c for c in calls if "add_item" in c["endpoint"])["json"]["vip"]
    assert payload["mode"] == "ipalias"
    assert payload.get("vhid", "") == ""


@pytest.mark.asyncio
async def test_vip_carp_requires_a_vhid() -> None:
    client = _client()
    _stub(client, {"search_item": {"rows": [], "total": 0}})

    result = await MkVipTool(client).execute(
        {
            "interface": "lan",
            "subnet": "fd0b:b022:1e5:2::1",
            "subnet_bits": 64,
            "mode": "carp",
        }
    )

    assert result["status"] == "error"
    assert "vhid" in result["error"]


@pytest.mark.asyncio
async def test_vip_is_idempotent_on_interface_and_subnet() -> None:
    client = _client()
    calls = _stub(client, {"search_item": VIP_ROWS})

    result = await MkVipTool(client).execute(
        {"interface": "lan", "subnet": "fd0b:b022:1e5:2::1", "subnet_bits": 64}
    )

    assert result["created"] is False
    assert not [c for c in calls if "add_item" in c["endpoint"]]


@pytest.mark.asyncio
async def test_vip_results_never_carry_the_carp_password() -> None:
    client = _client()
    _stub(client, {"search_item": VIP_ROWS})

    result = await ListVipTool(client).execute({})

    assert "carp-secret" not in str(result)


@pytest.mark.asyncio
async def test_vip_delete_needs_confirmation() -> None:
    client = _client()
    _stub(client, {"search_item": VIP_ROWS})
    tool = RmVipTool(client)

    first = await tool.execute({"uuid": VIP_UUID})

    assert first["status"] == "confirmation_required"


# --- loopback --------------------------------------------------------------


@pytest.mark.asyncio
async def test_loopback_create_is_device_only() -> None:
    """Creating the device does not assign or address it; that stays manual."""
    client = _client()
    _stub(client, {"search_item": {"rows": [], "total": 0}})

    result = await MkLoopbackTool(client).execute({"description": "PD holder"})

    assert result["status"] == "success"
    assert "assign" in result["note"].lower()


@pytest.mark.asyncio
async def test_loopback_list_returns_rows() -> None:
    client = _client()
    _stub(
        client,
        {"search_item": {"rows": [{"uuid": "lo-1", "description": "PD"}], "total": 1}},
    )

    result = await ListLoopbackTool(client).execute({})

    assert result["count"] == 1
