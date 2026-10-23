"""fw_rules must return the rules the firewall reported (#113).

The deployed server answered `fw_rules()` with `rules: []`, `total: 0`,
`total_all: 204` and `status: success`. Its FastMCP wrapper passed every
omitted filter as an explicit `None`, and the enabled filter ran on key
presence (`if "enabled" in params`), so `rule["enabled"] == None` dropped all
204 parsed rows. `total_all` was the parsed count, so it looked healthy.

These tests drive the tool with the captured `searchRule` response, through
both the flat tool and the grouped `fw_rule` entry point, and assert on the
rows that come back rather than on message text.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest

from opnsense_mcp.tools.fw_rules import FwRulesTool
from opnsense_mcp.utils.grouped_tool import GroupedTool
from opnsense_mcp.utils.tool_groups import FIELD_ALIASES

FIXTURE = (
    pathlib.Path(__file__).parent
    / "fixtures"
    / "opnsense-26.7.3"
    / "filter_searchrule_rows.json"
)

LAN_PASS = "9b1c0a2e-1111-4a00-8000-000000000001"
WAN_BLOCK_TCP = "9b1c0a2e-1111-4a00-8000-000000000002"
OPT3_REJECT_DISABLED = "9b1c0a2e-1111-4a00-8000-000000000003"
ALL_UUIDS = {LAN_PASS, WAN_BLOCK_TCP, OPT3_REJECT_DISABLED}

# What the hand-written FastMCP wrapper sent for `fw_rules()` with no arguments.
FASTMCP_NULLS = {"interface": None, "action": None, "enabled": None, "protocol": None}


def _captured() -> dict[str, Any]:
    """The recorded searchRule response, whole."""
    return json.loads(FIXTURE.read_text())


class _SearchRuleClient:
    """Answers searchRule with a fixed response and nothing else."""

    def __init__(self, response: dict[str, Any]) -> None:
        """Hold the response to return."""
        self.response = response

    async def search_firewall_rules(self, *, row_count: int = 1000) -> dict[str, Any]:
        """Return the stored searchRule response."""
        _ = row_count
        return self.response

    async def _make_request(self, method: str, endpoint: str, **_: Any) -> Any:
        """Interface group/alias lookups find nothing."""
        return {}


def _flat(response: dict[str, Any] | None = None) -> FwRulesTool:
    return FwRulesTool(_SearchRuleClient(response or _captured()))


def _grouped(response: dict[str, Any] | None = None) -> GroupedTool:
    return GroupedTool(
        name="fw_rule",
        description="test",
        members={"list": _flat(response)},
        field_aliases=FIELD_ALIASES,
    )


def _uuids(result: dict[str, Any]) -> set[str]:
    return {rule["id"] for rule in result["rules"]}


async def test_explicit_null_filters_return_every_captured_rule() -> None:
    """The exact call the deployed server received for `fw_rules()`."""
    result = await _flat().execute(dict(FASTMCP_NULLS))

    assert result["status"] == "success"
    assert _uuids(result) == ALL_UUIDS
    assert result["total"] == result["total_all"] == len(_captured()["rows"])


async def test_grouped_list_with_no_filters_returns_every_captured_rule() -> None:
    result = await _grouped().execute({"action": "list"})

    assert result["status"] == "success"
    assert _uuids(result) == ALL_UUIDS


async def test_grouped_list_with_explicit_nulls_returns_every_captured_rule() -> None:
    params = {"action": "list", "rule_action": None, "interface": None}
    params |= {"protocol": None, "enabled": None}

    result = await _grouped().execute(params)

    assert result["status"] == "success"
    assert _uuids(result) == ALL_UUIDS


async def test_zero_rows_when_the_firewall_reports_rules_is_an_error() -> None:
    """`status: success` with no rows and a non-zero total is a silent failure."""
    result = await _flat({"rows": [], "total": 204, "rowCount": 0}).execute(
        dict(FASTMCP_NULLS)
    )

    assert result["status"] == "error"
    assert result["rules"] == []
    assert result["total_reported"] == 204


async def test_an_empty_ruleset_is_still_success() -> None:
    result = await _flat({"rows": [], "total": 0, "rowCount": 0}).execute({})

    assert result["status"] == "success"
    assert result["total_all"] == 0


async def test_fewer_rows_than_reported_is_flagged_as_truncated() -> None:
    response = _captured() | {"total": 1500}

    result = await _flat(response).execute({})

    assert result["status"] == "success"
    assert result["truncated"] is True
    assert result["total_reported"] == 1500
    assert result["total_all"] == len(response["rows"])


async def test_a_complete_read_is_not_flagged_as_truncated() -> None:
    result = await _flat().execute({})

    assert result["truncated"] is False
    assert result["total_reported"] == result["total_all"]


FILTER_CASES = [
    ({"interface": "wan"}, {WAN_BLOCK_TCP}),
    ({"interface": "opt3"}, {OPT3_REJECT_DISABLED}),
    ({"action": "block"}, {WAN_BLOCK_TCP}),
    ({"action": "PASS"}, {LAN_PASS}),
    ({"protocol": "tcp"}, {WAN_BLOCK_TCP}),
    ({"protocol": "any"}, {LAN_PASS, OPT3_REJECT_DISABLED}),
    ({"enabled": True}, {LAN_PASS, WAN_BLOCK_TCP}),
    ({"enabled": False}, {OPT3_REJECT_DISABLED}),
    ({"enabled": "false"}, {OPT3_REJECT_DISABLED}),
    ({"enabled": "1"}, {LAN_PASS, WAN_BLOCK_TCP}),
]


@pytest.mark.parametrize(("filters", "expected"), FILTER_CASES)
async def test_each_filter_selects_the_right_captured_rules(
    filters: dict[str, Any], expected: set[str]
) -> None:
    params = dict(FASTMCP_NULLS) | filters

    result = await _flat().execute(params)

    assert result["status"] == "success"
    assert _uuids(result) == expected
    assert result["total_all"] == len(ALL_UUIDS)


@pytest.mark.parametrize(("filters", "expected"), FILTER_CASES)
async def test_each_filter_works_through_the_grouped_entry_point(
    filters: dict[str, Any], expected: set[str]
) -> None:
    params = {("rule_action" if k == "action" else k): v for k, v in filters.items()}

    result = await _grouped().execute({"action": "list", **params})

    assert result["status"] == "success"
    assert _uuids(result) == expected


async def test_an_unparseable_enabled_filter_is_refused_not_applied() -> None:
    """A value that is neither true nor false must not silently empty the list."""
    result = await _flat().execute({"enabled": "maybe"})

    assert result["status"] == "error"
    assert result["rules"] == []
