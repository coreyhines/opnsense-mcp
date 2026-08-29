"""Normalizers must be exercised against the shapes the API really returns.

Issue #24, the systemic finding behind #14 and #18: `uv run pytest tests/`
passed 1337/1337 while `fw_rule list` reported every rule as any->any and the
DHCP subnet selector could not match anything. Both normalizers were fed
hand-written fixtures using key names OPNsense does not emit, so each was
tested against the shape it already expected.

The specific blind spot was that no test asserted a normalized value was ever
non-empty:

    $ grep -rn 'source"\\]\\["net' tests/*.py
    (no matches)

A normalizer returning "" for every rule's source and destination passed the
whole suite. These tests assert on values, not on the presence of keys.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "opnsense-26.7.3"


def _rows(name: str) -> list[dict[str, Any]]:
    """Rows from a captured API response fixture."""
    return json.loads((FIXTURES / name).read_text())["rows"]


def _fixture(name: str) -> dict[str, Any]:
    """A captured API response fixture."""
    return json.loads((FIXTURES / name).read_text())


# --- searchRule ------------------------------------------------------------


def test_every_captured_rule_normalizes_to_a_non_empty_source_and_destination() -> None:
    """The assertion whose absence let #14 ship."""
    from opnsense_mcp.tools.fw_rules import _map_search_rule_row

    mapped = [_map_search_rule_row(row) for row in _rows("filter_searchrule_rows.json")]

    assert mapped, "fixture carries no rows"
    for rule in mapped:
        assert rule["source"]["net"], f"empty source net for {rule['description']!r}"
        assert rule["destination"]["net"], (
            f"empty destination net for {rule['description']!r}"
        )


def test_captured_rules_round_trip_their_values_not_just_their_keys() -> None:
    """Values must equal what the firewall stored, not merely be present."""
    from opnsense_mcp.tools.fw_rules import _map_search_rule_row

    by_uuid = {
        row["uuid"]: (row, _map_search_rule_row(row))
        for row in _rows("filter_searchrule_rows.json")
    }

    for row, mapped in by_uuid.values():
        assert mapped["source"]["net"] == row["source_net"]
        assert mapped["destination"]["net"] == row["destination_net"]
        assert mapped["destination"]["port"] == row["destination_port"]
        assert mapped["action"] == row["action"]


def test_the_captured_rules_cover_more_than_one_action() -> None:
    """A fixture of only `pass` rules cannot catch an action defect."""
    actions = {row["action"] for row in _rows("filter_searchrule_rows.json")}

    assert {"pass", "block"} <= actions


# --- dnsmasq search_range --------------------------------------------------


@pytest.mark.asyncio
async def test_every_captured_range_resolves_by_its_own_subnet() -> None:
    """The assertion whose absence let #18 ship."""
    from opnsense_mcp.utils.dhcp_scope import resolve_scope_from_selectors

    rows = _rows("dnsmasq_search_range_rows.json")

    async def make_request(method: str, endpoint: str, **kwargs: Any) -> Any:
        if "interfaces/overview" in endpoint:
            return {}
        return {"rows": rows}

    assert rows, "fixture carries no rows"
    for row in rows:
        subnet = f"{row['start_addr'].rsplit('.', 1)[0]}.0/{row['prefix_len']}"
        scope = await resolve_scope_from_selectors(
            make_request,
            subnet=subnet,
            interface=None,
            range_search_endpoint="/api/dnsmasq/settings/search_range",
        )
        assert scope.interface == row["interface"]
        assert scope.subnet == subnet


def test_captured_v6_range_normalizes_to_a_non_empty_constructor() -> None:
    """The prefix-from-interface selector must survive range normalization."""
    from opnsense_mcp.tools.dhcp_ranges import _RANGE_FIELDS, _project

    captured = _fixture("dnsmasq_v6_range_responses.json")
    row = captured["search_range"]["rows"][0]
    node = captured["get_range"]["range"]
    mapped = _project(row, _RANGE_FIELDS)

    selected = [key for key, option in node["constructor"].items() if option["selected"]]
    assert selected == ["opt13"]
    assert mapped["constructor"] == row["constructor"] == selected[0]


@pytest.mark.xfail(
    strict=True,
    reason="Bucket B1 will add the dnsmasq range RA fields to the normalizer",
)
def test_captured_v6_range_normalizes_ra_mode_value() -> None:
    """The selected RA mode must not disappear from the normalized range."""
    from opnsense_mcp.tools.dhcp_ranges import _RANGE_FIELDS, _project

    captured = _fixture("dnsmasq_v6_range_responses.json")
    row = captured["search_range"]["rows"][0]
    node = captured["get_range"]["range"]
    mapped = _project(row, _RANGE_FIELDS)

    selected = [key for key, option in node["ra_mode"].items() if option["selected"]]
    assert selected == ["slaac"]
    assert mapped.get("ra_mode") == row["ra_mode"] == selected[0]


# --- the mock cannot drift back to a shape the API never emits -------------


def test_the_captured_rule_rows_carry_no_key_the_normalizer_ignores() -> None:
    """A fixture key nothing reads is a fixture that documents nothing.

    Both defects came from a fixture that used a key the API does not emit.
    The mirror of that check: every key the normalizer reads must appear in
    the captured rows, so a rename upstream shows up here rather than as
    empty values on the firewall.
    """
    from opnsense_mcp.tools import fw_rules

    source = pathlib.Path(fw_rules.__file__).read_text()
    read_keys = {
        key
        for key in (
            "source_net",
            "destination_net",
            "source_port",
            "destination_port",
            "action",
            "interface",
            "sequence",
            "uuid",
        )
        if f'"{key}"' in source
    }
    captured = set().union(*(set(row) for row in _rows("filter_searchrule_rows.json")))

    missing = sorted(read_keys - captured)
    assert not missing, (
        "fw_rules reads keys the captured response does not contain, so the "
        "fixture cannot prove the normalizer works: " + ", ".join(missing)
    )
