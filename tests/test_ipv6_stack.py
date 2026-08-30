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
    REASON_TRACKIF_DOES_NOT_TRANSLATE,
    ListLoopbackTool,
    ListNptRulesTool,
    ListVipTool,
    MkLoopbackTool,
    MkNptRuleTool,
    MkVipTool,
    ReconcileNptTool,
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
async def test_npt_rejects_no_external_prefix() -> None:
    """Without one the rule cannot know the delegated prefix."""
    client = _client()
    calls = _stub(client, {"search_rule": {"rows": [], "total": 0}})

    result = await MkNptRuleTool(client).execute(
        {"interface": "wan", "source_net": "fd0b:b022:1e5:2::/64"}
    )

    assert result["status"] == "error"
    assert result["reason"] == REASON_TRACKIF_DOES_NOT_TRANSLATE
    assert not [c for c in calls if "add_rule" in c["endpoint"]]


@pytest.mark.asyncio
async def test_npt_refuses_trackif_as_the_external_side() -> None:
    """trackif alone stores fine and translates nothing.

    On 26.7.3 a rule with only `trackif` is accepted by add_rule, comes back
    from search_rule with the field populated, and survives a filter reload --
    and pf still holds no mapping for it. Nine such rules black-holed every
    ULA VLAN's egress: a WAN capture showed the ULA source leaving
    untranslated. Nothing in the rule's own read-back reveals this, so the
    tool has to refuse the shape rather than report it.
    """
    client = _client()
    calls = _stub(client, {"search_rule": {"rows": [], "total": 0}})

    result = await MkNptRuleTool(client).execute(
        {
            "interface": "wan",
            "source_net": "fd0b:b022:1e5:2::/64",
            "trackif": "lan",
        }
    )

    assert result["status"] == "error"
    assert result["reason"] == REASON_TRACKIF_DOES_NOT_TRANSLATE
    assert not [c for c in calls if "add_rule" in c["endpoint"]]


@pytest.mark.asyncio
async def test_npt_list_marks_a_rule_that_cannot_translate() -> None:
    """An enabled rule is not necessarily a translating one.

    NPT_ROWS holds the shape that caused the outage: enabled, trackif set,
    destination_net empty. Listing must say so rather than echo the fields.
    """
    client = _client()
    _stub(client, {"search_rule": NPT_ROWS})

    result = await ListNptRulesTool(client).execute({})

    rule = result["rules"][0]
    assert rule["enabled"] == "1"
    assert rule["translating"] is False
    assert rule["reason"] == REASON_TRACKIF_DOES_NOT_TRANSLATE
    assert "warning" in result


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
            "destination_net": "2001:db8:2::/64",
            "description": "wired VLAN",
        }
    )

    assert result["status"] == "success"
    payload = next(c for c in calls if "add_rule" in c["endpoint"])["json"]["rule"]
    assert payload["source_net"] == "fd0b:b022:1e5:2::/64"
    assert payload["destination_net"] == "2001:db8:2::/64"
    assert payload["interface"] == "wan"
    assert "internal_prefix" not in payload


@pytest.mark.asyncio
async def test_npt_is_idempotent_on_interface_and_source() -> None:
    client = _client()
    calls = _stub(client, {"search_rule": NPT_ROWS})

    result = await MkNptRuleTool(client).execute(
        {
            "interface": "wan",
            "source_net": "fd0b:b022:1e5:2::/64",
            "destination_net": "2001:db8:2::/64",
        }
    )

    assert result["created"] is False
    assert result["uuid"] == NPT_UUID
    assert not [c for c in calls if "add_rule" in c["endpoint"]]


@pytest.mark.asyncio
async def test_npt_stages_without_applying_by_default() -> None:
    """Dataplane writes stage; apply_ula loads them."""
    client = _client()
    calls = _stub(client, {"search_rule": {"rows": [], "total": 0}})

    result = await MkNptRuleTool(client).execute(
        {
            "interface": "wan",
            "source_net": "fd0b:b022:1e5:2::/64",
            "destination_net": "2001:db8:2::/64",
        }
    )

    # The write must land, or "no apply call" is satisfied by a refusal.
    assert result["created"] is True
    assert [c for c in calls if "add_rule" in c["endpoint"]]
    assert not [c for c in calls if "apply" in c["endpoint"]]


@pytest.mark.asyncio
async def test_npt_apply_status_failed_keeps_successful_write_visible() -> None:
    client = _client()
    _stub(
        client,
        {
            "search_rule": {"rows": [], "total": 0},
            "filter/apply": {"status": "failed", "message": "pf reload refused"},
        },
    )

    result = await MkNptRuleTool(client).execute(
        {
            "interface": "wan",
            "source_net": "fd0b:b022:1e5:2::/64",
            "destination_net": "2001:db8:2::/64",
            "apply": True,
        }
    )

    assert result["status"] == "success"
    assert result["created"] is True
    assert result["applied"] is False
    assert "apply_error" in result


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


@pytest.mark.asyncio
async def test_vip_refuses_unparseable_subnet_before_any_request() -> None:
    """Garbage in `subnet` must not reach the VIP API (D3)."""
    client = _client()
    calls = _stub(client, {"search_item": {"rows": [], "total": 0}})

    result = await MkVipTool(client).execute(
        {"interface": "lan", "subnet": "not-an-address", "subnet_bits": 64}
    )

    assert result["status"] == "error"
    assert "error" in result
    assert calls == []


@pytest.mark.asyncio
async def test_vip_refuses_subnet_bits_outside_address_family() -> None:
    """IPv6 /129 and IPv4 /64 are both impossible; neither may issue a request."""
    client = _client()
    calls = _stub(client, {"search_item": {"rows": [], "total": 0}})

    v6 = await MkVipTool(client).execute(
        {"interface": "lan", "subnet": "fd0b:b022:1e5:2::1", "subnet_bits": 129}
    )
    v4 = await MkVipTool(client).execute(
        {"interface": "lan", "subnet": "192.0.2.1", "subnet_bits": 64}
    )

    assert v6["status"] == "error"
    assert v4["status"] == "error"
    assert calls == []


@pytest.mark.asyncio
async def test_vip_accepts_valid_ipv4_and_ipv6_addresses() -> None:
    """Family-aware bounds still allow a real /64 ULA and a real /24 IPv4 alias."""
    client = _client()
    calls = _stub(client, {"search_item": {"rows": [], "total": 0}})

    v6 = await MkVipTool(client).execute(
        {"interface": "lan", "subnet": "fd0b:b022:1e5:2::1", "subnet_bits": 64}
    )
    v4 = await MkVipTool(client).execute(
        {"interface": "lan", "subnet": "192.0.2.1", "subnet_bits": 24}
    )

    assert v6["status"] == "success"
    assert v4["status"] == "success"
    assert len([c for c in calls if "add_item" in c["endpoint"]]) == 2


@pytest.mark.asyncio
async def test_vip_apply_status_failed_keeps_successful_write_visible() -> None:
    client = _client()
    _stub(
        client,
        {
            "search_item": {"rows": [], "total": 0},
            "reconfigure": {
                "status": "failed",
                "message": "interface reconfigure refused",
            },
        },
    )

    result = await MkVipTool(client).execute(
        {
            "interface": "lan",
            "subnet": "fd0b:b022:1e5:2::1",
            "subnet_bits": 64,
            "apply": True,
        }
    )

    assert result["status"] == "success"
    assert result["created"] is True
    assert result["applied"] is False
    assert "apply_error" in result


# --- loopback --------------------------------------------------------------


@pytest.mark.asyncio
async def test_loopback_create_is_device_only() -> None:
    """Creating the device does not assign or address it; that stays manual."""
    client = _client()
    calls = _stub(client, {"search_item": {"rows": [], "total": 0}})

    result = await MkLoopbackTool(client).execute({"description": "PD holder"})

    assert result["status"] == "success"
    assert result.get("unsupported") is not True
    assert any("add_item" in call["endpoint"] for call in calls)
    assert "assign" in result["note"].lower()


@pytest.mark.asyncio
async def test_loopback_planned_static_address_behavior_is_unchanged() -> None:
    """The existing planned-address path still creates and returns its manual step."""
    client = _client()
    calls = _stub(client, {})

    result = await MkLoopbackTool(client).execute(
        {
            "description": "Static holder",
            "planned_address": "2001:db8::1",
            "planned_subnet_bits": 128,
        }
    )

    assert result["status"] == "success"
    assert result.get("unsupported") is not True
    assert result["manual_step"]["address"] == "2001:db8::1"
    assert result["manual_step"]["subnet_bits"] == 128
    assert any("add_item" in call["endpoint"] for call in calls)


@pytest.mark.asyncio
async def test_loopback_refuses_track_interface_addressing_with_manual_steps() -> None:
    """A PD holder cannot be partially created when its addressing is unavailable."""
    client = _client()
    calls = _stub(client, {})

    result = await MkLoopbackTool(client).execute(
        {
            "description": "PD holder",
            "ipaddrv6": "track6",
            "track6-interface": "wan",
            "track6-prefix-id": 9,
        }
    )

    assert result["status"] == "success"
    assert result["unsupported"] is True
    assert result["created"] is False
    assert result["reason"]["code"] == "per_interface_ipv6_addressing_api_unavailable"
    assert result["reason"]["availability"] == "UI or config.xml edit only"
    assert result["requested"] == {
        "ipaddrv6": "track6",
        "track6-interface": "wan",
        "track6-prefix-id": 9,
    }
    assert result["manual_steps"]
    assert calls == []


@pytest.mark.asyncio
async def test_loopback_schema_declares_track6_refusal_fields() -> None:
    """The track6 refusal is unreachable over MCP unless these keys are advertised (D4)."""
    props = MkLoopbackTool.input_schema["properties"]

    for field in ("ipaddrv6", "track6-interface", "track6-prefix-id"):
        assert field in props
        assert field not in (MkLoopbackTool.input_schema.get("required") or [])


@pytest.mark.asyncio
async def test_loopback_list_returns_rows() -> None:
    client = _client()
    _stub(
        client,
        {"search_item": {"rows": [{"uuid": "lo-1", "description": "PD"}], "total": 1}},
    )

    result = await ListLoopbackTool(client).execute({})

    assert result["count"] == 1


# --- NPT reconcile: drift between the rule and the live delegation ----------


def _iface(identifier: str, addresses: list[str], device: str = "") -> dict[str, Any]:
    """One /api/interfaces/overview/export row, trimmed to what reconcile reads."""
    return {
        "device": device or identifier,
        "identifier": identifier,
        "description": f"{identifier} description",
        "ipv6": [{"ipaddr": a} for a in addresses],
    }


# The delegation moved from b501 to c001; the interface has already re-derived,
# and the rule still names the old block.
DRIFTED_IFACES = [
    _iface(
        "opt13",
        [
            "fd0b:b022:1e5:10::1/64",
            "2001:db8:1e5:c001::1/64",
            "fe80::1/64",
        ],
        device="vlan01",
    )
]
DRIFTED_RULE = {
    "rows": [
        {
            "uuid": NPT_UUID,
            "interface": "wan",
            "source_net": "fd0b:b022:1e5:10::/64",
            "destination_net": "2001:db8:1e5:b501::/64",
            "trackif": "",
            "enabled": "1",
            "description": "ULA VLAN10 Podman",
        }
    ],
    "total": 1,
}


@pytest.mark.asyncio
async def test_reconcile_npt_reports_a_prefix_that_has_drifted() -> None:
    """A new delegation leaves every literal external prefix stale.

    The rule still translates, onto a block the upstream no longer routes, so
    egress fails while the rule reads as correct. Drift has to come from the
    interface, which is the only thing that tracks the delegation.
    """
    client = _client()
    calls = _stub(
        client,
        {"search_rule": DRIFTED_RULE, "overview/export": DRIFTED_IFACES},
    )

    result = await ReconcileNptTool(client).execute({})

    assert result["counts"] == {"current": 0, "drifted": 1, "unresolved": 0}
    row = result["results"][0]
    assert row["outcome"] == "drifted"
    assert row["destination_net"] == "2001:db8:1e5:b501::/64"
    assert row["expected"] == "2001:db8:1e5:c001::/64"
    assert row["interface"] == "opt13"
    assert result["rewritten"] == 0
    assert not [c for c in calls if "set_rule" in c["endpoint"]]


@pytest.mark.asyncio
async def test_reconcile_npt_says_current_when_the_rule_still_matches() -> None:
    client = _client()
    matching = {
        "rows": [
            dict(DRIFTED_RULE["rows"][0], destination_net="2001:db8:1e5:c001::/64")
        ],
        "total": 1,
    }
    calls = _stub(client, {"search_rule": matching, "overview/export": DRIFTED_IFACES})

    result = await ReconcileNptTool(client).execute({})

    assert result["counts"]["drifted"] == 0
    assert result["results"][0]["outcome"] == "current"
    assert not [c for c in calls if "set_rule" in c["endpoint"]]


@pytest.mark.asyncio
async def test_reconcile_npt_re_reads_instead_of_trusting_the_write() -> None:
    """set_rule returning ok is not evidence the rule moved."""
    client = _client()
    calls: list[dict[str, Any]] = []
    searches = {"n": 0}

    async def fake(method: str, endpoint: str, **kwargs: Any) -> Any:
        calls.append({"endpoint": endpoint, "json": kwargs.get("json")})
        if "overview/export" in endpoint:
            return DRIFTED_IFACES
        if "search_rule" in endpoint:
            searches["n"] += 1
            if searches["n"] == 1:
                return DRIFTED_RULE
            return {
                "rows": [
                    dict(
                        DRIFTED_RULE["rows"][0],
                        destination_net="2001:db8:1e5:c001::/64",
                    )
                ],
                "total": 1,
            }
        return {"result": "saved"}

    client._make_request = AsyncMock(side_effect=fake)

    result = await ReconcileNptTool(client).execute({"dry_run": False})

    assert result["rewritten"] == 1
    assert result["verified"] is True
    written = next(c for c in calls if "set_rule" in c["endpoint"])["json"]["rule"]
    assert written["destination_net"] == "2001:db8:1e5:c001::/64"
    assert written["source_net"] == "fd0b:b022:1e5:10::/64"


@pytest.mark.asyncio
async def test_reconcile_npt_leaves_a_rule_whose_interface_it_cannot_find() -> None:
    """Guessing is worse than reporting: the rule keeps working as configured."""
    client = _client()
    calls = _stub(
        client,
        {
            "search_rule": DRIFTED_RULE,
            "overview/export": [_iface("opt2", ["fd0b:b022:1e5:2::1/64"])],
        },
    )

    result = await ReconcileNptTool(client).execute({"dry_run": False})

    assert result["results"][0]["outcome"] == "no_interface"
    assert result["counts"]["unresolved"] == 1
    assert result["rewritten"] == 0
    assert not [c for c in calls if "set_rule" in c["endpoint"]]


@pytest.mark.asyncio
async def test_reconcile_npt_never_writes_an_empty_external_prefix() -> None:
    """An interface that has lost its delegation must not blank the rule.

    Writing "" here would turn a stale-but-translating rule into the exact
    silent no-op this whole guard exists to prevent.
    """
    client = _client()
    calls = _stub(
        client,
        {
            "search_rule": DRIFTED_RULE,
            "overview/export": [_iface("opt13", ["fd0b:b022:1e5:10::1/64"])],
        },
    )

    result = await ReconcileNptTool(client).execute({"dry_run": False})

    assert result["results"][0]["outcome"] == "no_delegated_prefix"
    assert result["rewritten"] == 0
    assert not [c for c in calls if "set_rule" in c["endpoint"]]


@pytest.mark.asyncio
async def test_reconcile_npt_reports_unverified_when_the_re_read_disagrees() -> None:
    """set_rule can return ok and leave the rule where it was.

    Without this case the re-read is untestable: a run where the write really
    landed reports verified=True whether the code checked or just said so.
    """
    client = _client()

    async def fake(method: str, endpoint: str, **kwargs: Any) -> Any:
        if "overview/export" in endpoint:
            return DRIFTED_IFACES
        if "search_rule" in endpoint:
            # Unchanged before and after: the write did not take.
            return DRIFTED_RULE
        return {"result": "saved"}

    client._make_request = AsyncMock(side_effect=fake)

    result = await ReconcileNptTool(client).execute({"dry_run": False})

    assert result["rewritten"] == 1
    assert result["verified"] is False
