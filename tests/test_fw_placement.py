"""fw_rule create/update: sequence, log, shadow warnings and empty aliases (#123).

Row keys follow a 26.7.7 searchRule capture: `sort_order` and `prio_group` are
what pf orders by, and a rule on several interfaces sorts as floating
(200000). Addresses are documentation ranges.
"""

from __future__ import annotations

from typing import Any

import pytest

from opnsense_mcp.tools.apply_fw_changes import ApplyFwChangesTool
from opnsense_mcp.tools.mkfw_rule import MkfwRuleTool
from opnsense_mcp.tools.set_fw_rule import SetFwRuleTool
from opnsense_mcp.utils.api import _firewall_rule_inner_for_add_api
from opnsense_mcp.utils.fw_placement import check_placement

OURS = "34299fd6-b472-41fd-ba0a-0a239deaae96"
FLOATING_TRUSTED = "7eba7aad-cad1-48d7-83ba-24abb39bac19"
IFACE_PASS_ANY = "1d56a10a-d74e-4525-a758-eb8295d17aeb"


def _row(uuid: str, prio: int, seq: int, **fields: Any) -> dict[str, Any]:
    row = {
        "uuid": uuid,
        "enabled": "1",
        "quick": "1",
        "action": "pass",
        "interface": "",
        "interfacenot": "0",
        "direction": "in",
        "ipprotocol": "inet46",
        "protocol": "any",
        "source_net": "any",
        "source_not": "0",
        "source_port": "",
        "destination_net": "any",
        "destination_not": "0",
        "destination_port": "",
        "description": "",
        "sequence": str(seq),
        "prio_group": str(prio),
        "sort_order": f"{prio}.{seq:07d}",
    }
    row.update(fields)
    return row


def _block_rule(seq: int, **fields: Any) -> dict[str, Any]:
    """The agent-fence #4 block rule: three interfaces, so floating."""
    base = {
        "action": "block",
        "interface": "opt2,opt5,opt9",
        "destination_net": "mcp_fenced_backends",
        "description": "agent-fence #4 block",
    }
    base.update(fields)
    return _row(OURS, 200000, seq, **base)


def _trusted_pass(seq: int, **fields: Any) -> dict[str, Any]:
    base = {
        "interface": "",
        "source_net": "trustedNets",
        "destination_net": "trustedNets",
    }
    base.update(fields)
    return _row(FLOATING_TRUSTED, 200000, seq, **base)


def _iface_pass_any(seq: int = 261) -> dict[str, Any]:
    return _row(IFACE_PASS_ANY, 400000, seq, interface="opt9")


class FakeClient:
    """Serves searchRule, groups, aliases and pf tables; records every call."""

    def __init__(
        self,
        rows: list[dict[str, Any]],
        *,
        tables: dict[str, list[str]] | None = None,
        aliases: list[dict[str, Any]] | None = None,
        groups: list[dict[str, Any]] | None = None,
    ) -> None:
        self.rows = rows
        self.tables = (
            tables
            if tables is not None
            else {
                "__trustedNets_network": ["192.0.2.0/24", "198.51.100.0/24"],
                "mcp_fenced_backends": ["192.0.2.39"],
            }
        )
        self.aliases = (
            aliases
            if aliases is not None
            else [{"name": "mcp_fenced_backends", "type": "host", "current_items": "1"}]
        )
        self.groups = (
            groups
            if groups is not None
            else [{"ifname": "trustedNets", "members": "opt2,opt5,opt9"}]
        )
        self.calls: list[tuple[str, str]] = []
        self.added: list[dict[str, Any]] = []
        self.updated: list[tuple[str, dict[str, Any]]] = []
        self.applied = 0

    async def search_firewall_rules(self, *, row_count: int = 1000) -> dict[str, Any]:
        return {"rows": self.rows, "total": len(self.rows)}

    async def search_aliases(self, search: str = "") -> list[dict[str, Any]]:
        return self.aliases

    async def _make_request(
        self, method: str, endpoint: str, **_kwargs: Any
    ) -> dict[str, Any]:
        self.calls.append((method, endpoint))
        if endpoint == "/api/firewall/group/search_item":
            return {"rows": self.groups}
        prefix = "/api/firewall/alias_util/list/"
        if endpoint.startswith(prefix):
            name = endpoint[len(prefix) :]
            return {"rows": [{"ip": ip} for ip in self.tables.get(name, [])]}
        if endpoint.endswith("/reconfigure"):
            return {"status": "ok"}
        raise AssertionError(f"unexpected request {method} {endpoint}")

    async def add_firewall_rule(self, rule: dict[str, Any]) -> dict[str, Any]:
        self.added.append(rule)
        return {"uuid": OURS, "result": "success"}

    async def update_firewall_rule(
        self, uuid: str, rule: dict[str, Any]
    ) -> dict[str, Any]:
        self.updated.append((uuid, rule))
        return {"uuid": uuid, "result": "success"}

    async def apply_firewall_changes(self) -> dict[str, Any]:
        self.calls.append(("POST", "/api/firewall/filter/apply"))
        self.applied += 1
        return {"status": "ok"}


def _ids(placement: dict[str, Any]) -> list[str]:
    return [entry["id"] for entry in placement["shadowed_by"]]


# --- the incident ---------------------------------------------------------


@pytest.mark.asyncio
async def test_the_agent_fence_block_is_reported_shadowed_by_the_floating_pass() -> (
    None
):
    """Seq 100 behind a floating trustedNets pass at seq 1: what really happened."""
    client = FakeClient([_trusted_pass(1), _block_rule(100), _iface_pass_any()])

    placement = await check_placement(client, OURS)

    assert placement["ran"] is True
    assert placement["shadowed"] is True
    assert _ids(placement) == [FLOATING_TRUSTED]
    entry = placement["shadowed_by"][0]
    assert entry["certainty"] == "definite"
    assert entry["sequence"] == 1
    assert entry["action"] == "pass"


@pytest.mark.asyncio
async def test_the_fix_that_worked_reports_no_shadow() -> None:
    """Ours at 2, the floating pass moved to 5."""
    client = FakeClient([_block_rule(2), _trusted_pass(5), _iface_pass_any()])

    placement = await check_placement(client, OURS)

    assert placement["ran"] is True
    assert placement["shadowed"] is False
    assert placement["shadowed_by"] == []
    assert placement["sequence"] == 2


@pytest.mark.asyncio
async def test_an_interface_rule_with_a_lower_sequence_does_not_shadow_a_floating_one() -> (
    None
):
    """Sequence alone says 261 < 1379; priority group says floating runs first.

    Ordering by sequence across groups would report this, and it is wrong.
    """
    client = FakeClient([_block_rule(1379), _iface_pass_any(261)])

    placement = await check_placement(client, OURS)

    assert placement["shadowed"] is False


@pytest.mark.asyncio
async def test_a_floating_rule_shadows_an_interface_rule_whatever_the_sequence() -> (
    None
):
    ours = _row(OURS, 400000, 1, interface="opt9", action="block")
    client = FakeClient([ours, _trusted_pass(900)])

    placement = await check_placement(client, OURS)

    assert _ids(placement) == [FLOATING_TRUSTED]


# --- what does not shadow -------------------------------------------------


@pytest.mark.asyncio
async def test_disjoint_destinations_do_not_shadow() -> None:
    client = FakeClient(
        [_trusted_pass(1), _block_rule(100)],
        tables={
            "__trustedNets_network": ["198.51.100.0/24"],
            "mcp_fenced_backends": ["192.0.2.39"],
        },
    )

    placement = await check_placement(client, OURS)

    assert placement["shadowed"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fields",
    [{"quick": "0"}, {"enabled": "0"}],
    ids=["not-quick", "disabled"],
)
async def test_only_enabled_quick_rules_shadow(fields: dict[str, Any]) -> None:
    client = FakeClient([_trusted_pass(1, **fields), _block_rule(100)])

    placement = await check_placement(client, OURS)

    assert placement["shadowed"] is False


@pytest.mark.asyncio
async def test_disjoint_interfaces_do_not_shadow_but_a_group_member_does() -> None:
    ours = _row(OURS, 400000, 50, interface="opt9", action="block")
    other_iface = _row("a" * 36, 400000, 10, interface="opt3")
    via_group = _row("b" * 36, 300000, 10, interface="trustedNets")
    client = FakeClient([other_iface, via_group, ours])

    placement = await check_placement(client, OURS)

    assert _ids(placement) == ["b" * 36]


@pytest.mark.asyncio
async def test_disjoint_address_families_do_not_shadow() -> None:
    client = FakeClient(
        [_trusted_pass(1, ipprotocol="inet6"), _block_rule(100, ipprotocol="inet")]
    )

    placement = await check_placement(client, OURS)

    assert placement["shadowed"] is False


@pytest.mark.asyncio
async def test_disjoint_ports_do_not_shadow_and_overlapping_ranges_do() -> None:
    ours = _block_rule(100, protocol="TCP", destination_port="443")
    ssh = _row("c" * 36, 200000, 1, protocol="TCP", destination_port="22")
    https_range = _row("d" * 36, 200000, 2, protocol="TCP", destination_port="400:500")
    client = FakeClient([ssh, https_range, ours])

    placement = await check_placement(client, OURS)

    assert _ids(placement) == ["d" * 36]


# --- best effort -----------------------------------------------------------


@pytest.mark.asyncio
async def test_an_unresolvable_net_is_possible_not_dropped() -> None:
    client = FakeClient([_trusted_pass(1, destination_net="(self)"), _block_rule(100)])

    placement = await check_placement(client, OURS)

    entry = placement["shadowed_by"][0]
    assert entry["certainty"] == "possible"
    assert entry["unresolved"] == ["destination_net"]
    # `(self)` is not a table name, so it is never sent to alias_util.
    assert not any("(self)" in endpoint for _, endpoint in client.calls)


@pytest.mark.asyncio
async def test_an_equal_sort_order_is_flagged_as_a_tie() -> None:
    client = FakeClient([_trusted_pass(100), _block_rule(100)])

    placement = await check_placement(client, OURS)

    assert placement["shadowed_by"][0]["tie"] is True


@pytest.mark.asyncio
async def test_a_failed_reread_is_reported_as_not_run() -> None:
    class Broken(FakeClient):
        async def search_firewall_rules(
            self, *, row_count: int = 1000
        ) -> dict[str, Any]:
            raise RuntimeError("searchRule timed out")

    placement = await check_placement(Broken([]), OURS)

    assert placement["ran"] is False
    assert "searchRule timed out" in placement["error"]


@pytest.mark.asyncio
async def test_a_rule_missing_from_the_reread_is_reported_as_not_run() -> None:
    placement = await check_placement(FakeClient([_trusted_pass(1)]), OURS)

    assert placement["ran"] is False


# --- empty aliases ---------------------------------------------------------


@pytest.mark.asyncio
async def test_a_referenced_alias_with_no_loaded_entries_is_reported() -> None:
    """`alias create apply=false` leaves current_items 0; the rule is a no-op."""
    client = FakeClient(
        [_block_rule(2)],
        tables={},
        aliases=[{"name": "mcp_fenced_backends", "type": "host", "current_items": "0"}],
    )

    placement = await check_placement(client, OURS)

    assert placement["empty_aliases"] == [
        {"field": "destination_net", "name": "mcp_fenced_backends", "type": "host"}
    ]


@pytest.mark.asyncio
async def test_a_loaded_alias_is_not_reported_empty() -> None:
    placement = await check_placement(FakeClient([_block_rule(2)]), OURS)

    assert placement["empty_aliases"] == []


# --- create / update -------------------------------------------------------


def test_add_payload_carries_sequence_and_log() -> None:
    inner = _firewall_rule_inner_for_add_api(
        {"description": "x", "sequence": 2, "log": True}
    )

    assert inner["sequence"] == 2
    assert inner["log"] == "1"


@pytest.mark.asyncio
async def test_create_sends_sequence_and_log_and_reports_the_shadow() -> None:
    client = FakeClient([_trusted_pass(1), _block_rule(100)])

    result = await MkfwRuleTool(client).execute(
        {
            "description": "agent-fence #4 block",
            "interface": "opt2,opt5,opt9",
            "action": "block",
            "destination_net": "mcp_fenced_backends",
            "sequence": 100,
            "log": True,
        }
    )

    assert result["status"] == "success"
    assert client.added[0]["sequence"] == 100
    assert client.added[0]["log"] is True
    assert result["placement"]["shadowed"] is True
    assert result["placement"]["shadowed_by"][0]["id"] == FLOATING_TRUSTED
    assert len(result["warnings"]) == 1


@pytest.mark.asyncio
async def test_create_rejects_a_negative_sequence_before_writing() -> None:
    client = FakeClient([])

    result = await MkfwRuleTool(client).execute({"description": "x", "sequence": -1})

    assert result["status"] == "error"
    assert client.added == []


@pytest.mark.asyncio
async def test_create_without_sequence_or_log_keeps_the_old_payload_shape() -> None:
    client = FakeClient([_block_rule(1379)])

    await MkfwRuleTool(client).execute({"description": "x"})

    inner = _firewall_rule_inner_for_add_api(client.added[0])
    assert "sequence" not in inner
    assert inner["log"] == "0"


@pytest.mark.asyncio
async def test_update_sends_sequence_and_reports_placement() -> None:
    client = FakeClient([_block_rule(2), _trusted_pass(5)])

    result = await SetFwRuleTool(client).execute({"rule_uuid": OURS, "sequence": 2})

    assert client.updated == [(OURS, {"sequence": 2})]
    assert result["placement"]["ran"] is True
    assert result["placement"]["shadowed"] is False
    assert "warnings" not in result


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", [0, -3, True, "2"])
async def test_update_refuses_a_sequence_that_is_not_a_positive_int(bad: Any) -> None:
    client = FakeClient([_block_rule(2)])

    result = await SetFwRuleTool(client).execute({"rule_uuid": OURS, "sequence": bad})

    assert result["status"] == "error"
    assert client.updated == []


# --- apply loads aliases ---------------------------------------------------


@pytest.mark.asyncio
async def test_apply_reloads_aliases_before_the_filter() -> None:
    client = FakeClient([])

    result = await ApplyFwChangesTool(client).execute({})

    assert result["status"] == "success"
    assert result["applied"] is True
    assert result["aliases_applied"] is True
    assert client.calls == [
        ("POST", "/api/firewall/alias/reconfigure"),
        ("POST", "/api/firewall/filter/apply"),
    ]


@pytest.mark.asyncio
async def test_a_refused_alias_reload_is_an_error_even_when_the_filter_loads() -> None:
    class AliasRefused(FakeClient):
        async def _make_request(
            self, method: str, endpoint: str, **kwargs: Any
        ) -> dict[str, Any]:
            if endpoint == "/api/firewall/alias/reconfigure":
                self.calls.append((method, endpoint))
                return {"status": "failed"}
            return await super()._make_request(method, endpoint, **kwargs)

    client = AliasRefused([])

    result = await ApplyFwChangesTool(client).execute({})

    assert result["status"] == "error"
    assert result["aliases_applied"] is False
    assert result["applied"] is True
    assert client.applied == 1
