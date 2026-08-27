"""DHCP ranges, DHCP options, and firewall interface groups.

The router option is the capability this adds. A routed subnet gets its default
gateway from DHCP option 3, and until now nothing here could set one, so moving
a subnet behind a router meant editing it in the UI.

Two shapes worth knowing, both confirmed against the live API rather than
guessed:

- `constructor` on a range is the IPv6 prefix-from-interface field. It looks
  like a relay setting and is not one.
- Options scope by `interface` or by `tag`, never both, and the v4 and v6
  option numbers are separate enums. Option 3 is `router` in v4 and
  `option_ia_na` in v6, so writing a v4 option number into `option6` produces a
  valid request that means something else entirely.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from opnsense_mcp.tools.dhcp_ranges import (
    ListDhcpOptionsTool,
    ListDhcpRangesTool,
    MkDhcpRangeTool,
    RmDhcpOptionTool,
    RmDhcpRangeTool,
    SetDhcpRangeTool,
    SetDhcpRouterOptionTool,
)
from opnsense_mcp.tools.fw_groups import ListFwGroupsTool, SetFwGroupTool
from opnsense_mcp.utils.api import OPNsenseClient

RANGE_UUID = "range-1234"
GROUP_UUID = "2873531a-bf3b-42c6-9b90-676e193edd67"

RANGE_ROWS = {
    "rows": [
        {
            "uuid": RANGE_UUID,
            "interface": "opt3",
            "%interface": "VLAN3workshop",
            "start_addr": "172.20.3.100",
            "end_addr": "172.20.3.200",
            "subnet_mask": "255.255.255.0",
            "constructor": "",
            "mode": "",
            "prefix_len": "",
            "lease_time": "7200",
            "domain": "lab.frobozz.example",
            "set_tag": "",
            "description": "lab range",
        }
    ],
    "total": 1,
}

OPTION_ROWS = {
    "rows": [
        {
            "uuid": "opt-1",
            "type": "set",
            "option": "3",
            "%option": "router [3]",
            "option6": "",
            "interface": "opt3",
            "tag": "",
            "set_tag": "",
            "value": "172.20.3.1",
            "force": "0",
            "description": "",
        },
        {
            "uuid": "opt-2",
            "type": "set",
            "option": "6",
            "option6": "",
            "interface": "opt3",
            "tag": "",
            "set_tag": "",
            "value": "172.20.3.53",
            "force": "0",
            "description": "dns",
        },
    ],
    "total": 2,
}

GROUP_ROWS = {
    "rows": [
        {
            "uuid": GROUP_UUID,
            "ifname": "workshopNets",
            "members": "opt3,opt4",
            "%members": "VLAN3workshop,VLAN5studio",
            "nogroup": "0",
            "sequence": "0",
            "descr": "lab networks",
        },
        # Built-in groups are keyed by name rather than a uuid and cannot be
        # edited through this API.
        {
            "uuid": "openvpn",
            "ifname": "openvpn",
            "members": "",
            "nogroup": "",
            "sequence": "10",
            "descr": "",
        },
    ],
    "total": 2,
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


# --- ranges ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_ranges_drops_display_labels() -> None:
    client = _client()
    _stub(client, {"search_range": RANGE_ROWS})

    result = await ListDhcpRangesTool(client).execute({})

    row = result["ranges"][0]
    assert row["start_addr"] == "172.20.3.100"
    assert "%interface" not in row
    assert row["interface_label"] == "VLAN3workshop"


@pytest.mark.asyncio
async def test_create_range_requires_the_bounds() -> None:
    """A range with one end open is not a range."""
    client = _client()
    _stub(client, {"search_range": {"rows": [], "total": 0}})

    result = await MkDhcpRangeTool(client).execute(
        {"interface": "opt3", "start_addr": "172.20.3.100"}
    )

    assert result["status"] == "error"
    assert "end_addr" in result["error"]


@pytest.mark.asyncio
async def test_create_range_is_idempotent_on_interface_and_start() -> None:
    client = _client()
    calls = _stub(client, {"search_range": RANGE_ROWS})

    result = await MkDhcpRangeTool(client).execute(
        {
            "interface": "opt3",
            "start_addr": "172.20.3.100",
            "end_addr": "172.20.3.200",
        }
    )

    assert result["created"] is False
    assert not [c for c in calls if "add_range" in c["endpoint"]]


@pytest.mark.asyncio
async def test_update_range_preserves_fields_it_was_not_given() -> None:
    """A partial POST to an MVC model blanks every field it omits.

    This is the same defect that made set_fw_rule widen rules to any/any, so
    the update path reads the record and merges rather than posting a partial.
    """
    client = _client()
    calls = _stub(
        client,
        {
            "get_range": {"range": dict(RANGE_ROWS["rows"][0])},
            "search_range": RANGE_ROWS,
        },
    )

    await SetDhcpRangeTool(client).execute({"uuid": RANGE_UUID, "lease_time": "3600"})

    payload = next(c for c in calls if "set_range" in c["endpoint"])["json"]["range"]
    assert payload["lease_time"] == "3600"
    assert payload["start_addr"] == "172.20.3.100"
    assert payload["end_addr"] == "172.20.3.200"
    assert payload["domain"] == "lab.frobozz.example"


@pytest.mark.asyncio
async def test_delete_range_needs_confirmation() -> None:
    client = _client()
    calls = _stub(client, {"search_range": RANGE_ROWS})

    result = await RmDhcpRangeTool(client).execute({"uuid": RANGE_UUID})

    assert result["status"] == "confirmation_required"
    assert not [c for c in calls if "del_range" in c["endpoint"]]


# --- the router option -----------------------------------------------------


@pytest.mark.asyncio
async def test_router_option_creates_an_option_3_scoped_to_the_interface() -> None:
    client = _client()
    calls = _stub(client, {"search_option": {"rows": [], "total": 0}})

    result = await SetDhcpRouterOptionTool(client).execute(
        {"interface": "opt3", "router": "172.20.3.1"}
    )

    assert result["status"] == "success"
    payload = next(c for c in calls if "add_option" in c["endpoint"])["json"]["option"]
    assert payload["option"] == "3"
    assert payload["type"] == "set"
    assert payload["interface"] == "opt3"
    assert payload["value"] == "172.20.3.1"
    # v4 and v6 option numbers are different enums; 3 means option_ia_na in v6.
    assert payload["option6"] == ""


@pytest.mark.asyncio
async def test_router_option_updates_the_existing_row_rather_than_adding_a_second() -> (
    None
):
    """Two option 3 rows on one interface is a configuration nobody wants."""
    client = _client()
    calls = _stub(client, {"search_option": OPTION_ROWS})

    result = await SetDhcpRouterOptionTool(client).execute(
        {"interface": "opt3", "router": "172.20.3.254"}
    )

    assert result["status"] == "success"
    assert not [c for c in calls if "add_option" in c["endpoint"]]
    update = next(c for c in calls if "set_option" in c["endpoint"])
    assert update["endpoint"].endswith("opt-1")
    assert update["json"]["option"]["value"] == "172.20.3.254"


@pytest.mark.asyncio
async def test_router_option_ignores_option_6_rows_on_the_same_interface() -> None:
    """Matching on interface alone would overwrite the DNS option."""
    client = _client()
    calls = _stub(
        client,
        {"search_option": {"rows": [OPTION_ROWS["rows"][1]], "total": 1}},
    )

    await SetDhcpRouterOptionTool(client).execute(
        {"interface": "opt3", "router": "172.20.3.1"}
    )

    assert [c for c in calls if "add_option" in c["endpoint"]]
    assert not [c for c in calls if "set_option" in c["endpoint"]]


@pytest.mark.asyncio
async def test_router_option_requires_a_scope() -> None:
    """An unscoped option 3 becomes the gateway for every served subnet."""
    client = _client()
    _stub(client, {"search_option": {"rows": [], "total": 0}})

    result = await SetDhcpRouterOptionTool(client).execute({"router": "172.20.3.1"})

    assert result["status"] == "error"
    assert "interface" in result["error"] or "tag" in result["error"]


@pytest.mark.asyncio
async def test_list_options_labels_the_option_number() -> None:
    client = _client()
    _stub(client, {"search_option": OPTION_ROWS})

    result = await ListDhcpOptionsTool(client).execute({})

    assert result["options"][0]["option"] == "3"
    assert result["options"][0]["label"] == "router [3]"


@pytest.mark.asyncio
async def test_delete_option_needs_confirmation() -> None:
    """Removing option 3 silently strips a subnet's default gateway."""
    client = _client()
    calls = _stub(client, {"search_option": OPTION_ROWS})

    result = await RmDhcpOptionTool(client).execute({"uuid": "opt-1"})

    assert result["status"] == "confirmation_required"
    assert not [c for c in calls if "del_option" in c["endpoint"]]


@pytest.mark.asyncio
async def test_delete_option_removes_it_once_confirmed() -> None:
    client = _client()
    calls = _stub(client, {"search_option": OPTION_ROWS})

    challenge = await RmDhcpOptionTool(client).execute({"uuid": "opt-1"})
    result = await RmDhcpOptionTool(client).execute(
        {"uuid": "opt-1", "confirm": challenge["confirm_token"]}
    )

    assert result["deleted"] is True
    assert [c for c in calls if "del_option" in c["endpoint"]]


# --- interface groups ------------------------------------------------------


@pytest.mark.asyncio
async def test_list_groups_marks_the_built_in_ones_as_not_editable() -> None:
    """openvpn, enc0 and wireguard are keyed by name and rejected on write."""
    client = _client()
    _stub(client, {"search_item": GROUP_ROWS})

    result = await ListFwGroupsTool(client).execute({})

    by_name = {g["ifname"]: g for g in result["groups"]}
    assert by_name["workshopNets"]["editable"] is True
    assert by_name["openvpn"]["editable"] is False


@pytest.mark.asyncio
async def test_group_members_are_returned_as_a_list() -> None:
    client = _client()
    _stub(client, {"search_item": GROUP_ROWS})

    result = await ListFwGroupsTool(client).execute({})

    labs = next(g for g in result["groups"] if g["ifname"] == "workshopNets")
    assert labs["members"] == ["opt3", "opt4"]


@pytest.mark.asyncio
async def test_set_group_replaces_membership_with_a_comma_joined_list() -> None:
    client = _client()
    calls = _stub(
        client,
        {
            "get_item": {"group": dict(GROUP_ROWS["rows"][0])},
            "search_item": GROUP_ROWS,
        },
    )

    result = await SetFwGroupTool(client).execute(
        {"uuid": GROUP_UUID, "members": ["opt3", "opt4", "opt7"]}
    )

    assert result["status"] == "success"
    payload = next(c for c in calls if "set_item" in c["endpoint"])["json"]["group"]
    assert payload["members"] == "opt3,opt4,opt7"
    assert payload["ifname"] == "workshopNets"


@pytest.mark.asyncio
async def test_set_group_refuses_a_built_in_group() -> None:
    """The API accepts the write and drops it, which reads as success."""
    client = _client()
    calls = _stub(client, {"search_item": GROUP_ROWS})

    result = await SetFwGroupTool(client).execute(
        {"uuid": "openvpn", "members": ["opt3"]}
    )

    assert result["status"] == "error"
    assert not [c for c in calls if "set_item" in c["endpoint"]]


@pytest.mark.asyncio
async def test_set_group_preserves_description_and_sequence() -> None:
    client = _client()
    calls = _stub(
        client,
        {
            "get_item": {"group": dict(GROUP_ROWS["rows"][0])},
            "search_item": GROUP_ROWS,
        },
    )

    await SetFwGroupTool(client).execute({"uuid": GROUP_UUID, "members": ["opt3"]})

    payload = next(c for c in calls if "set_item" in c["endpoint"])["json"]["group"]
    assert payload["descr"] == "lab networks"
    assert payload["sequence"] == "0"
