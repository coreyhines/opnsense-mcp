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

    selected = [
        key for key, option in node["constructor"].items() if option["selected"]
    ]
    assert selected == ["opt13"]
    assert mapped["constructor"] == row["constructor"] == selected[0]


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


def test_the_captured_wireguard_rows_carry_every_key_the_tool_reads() -> None:
    """The mirror check, for the WireGuard read path.

    Every key `wireguard.py` reads off a response must appear in one of the
    captured responses, so a rename upstream — or a key guessed rather than
    observed — fails here instead of turning into an always-empty column on
    the firewall. The read keys are swept out of the source rather than
    listed, so a newly-read key is checked on arrival; what is listed instead
    is the far smaller set of keys this module puts into dicts it builds
    itself, and the three keys nothing in the repository captures.
    """
    import re

    from opnsense_mcp.tools import wireguard

    source = pathlib.Path(wireguard.__file__).read_text()

    def _keys(value: Any, depth: int = 3) -> set[str]:
        """Keys of a row and of the nested shapes the tool reaches into.

        Three levels deep, because a `get*` node map is
        `field -> option key -> {value, selected}` and `selected` is the flag
        membership is carried by.
        """
        if depth == 0:
            return set()
        if isinstance(value, dict):
            return set(value).union(*(_keys(v, depth - 1) for v in value.values()))
        if isinstance(value, list):
            return set().union(*(_keys(v, depth - 1) for v in value), set())
        return set()

    captured: set[str] = set()
    for name in (
        "wg_searchserver_rows.json",
        "wg_searchclient_rows.json",
        "wg_service_show_rows.json",
        "wg_interfaces_info_wg0.json",
    ):
        for row in _rows(name):
            captured |= _keys(row)
    captured |= _keys(_fixture("wg_getserver_dangling.json")["server"])
    # The captured wg0 device has no interface assignment — its `config` holds
    # `if`, `descr`, `enable`, `lock`, `spoofmac`, `identifier` and nothing
    # else — so the assignment keys are pinned by the other captured
    # interfaces_info in the repository, which does carry one.
    assigned = json.loads(
        (
            pathlib.Path(__file__).parent
            / "fixtures"
            / "phase0-diagnostics"
            / "interface_list_sample.json"
        ).read_text()
    )
    for row in assigned.values():
        if isinstance(row, dict):
            captured |= _keys(row)

    read_keys = set(re.findall(r'\.get\(\s*"([^"]+)"', source))
    # Subscripts, but only where something is being indexed: a bare `["x"]` is
    # a list literal, not a key.
    read_keys |= set(re.findall(r'(?<=[\w)])\[\s*"([^"]+)"\s*\]', source))
    # The assignment pair is read through a variable, so the sweep cannot see
    # it. Named here because getting it wrong is exactly the defect this file
    # exists for: the width lives in its own key, not on the address.
    read_keys |= {"ipaddr", "subnet", "ipaddrv6", "subnetv6"}

    # Keys of dicts this module builds itself, plus the two endpoint maps and
    # the bootgrid envelope. None of these is read off a row.
    internal = {
        "get",
        "search",
        "show",
        "rows",
        "total",
        "outcome",
        "has_privkey",
        "has_psk",
        "instance_names",
        "instance_uuids",
        "peer_names",
        "peer_uuids",
        "tunnel_addresses",
    }
    # Keys no capture in this repository pins, recorded rather than left
    # invisible. `id` and `running` come from `/api/core/service/search`, which
    # nothing has captured; capturing it is what closes those two. `subnetv6`
    # is absent for a different reason: every captured v6 assignment is
    # `track6`, which the code skips before it reads a width, so the key is
    # taken from the model and from `interface_address.py`, which writes it.
    uncaptured = {"id", "running", "subnetv6"}

    missing = sorted(read_keys - captured - internal - uncaptured)
    assert not missing, (
        "wireguard.py reads keys no captured response contains, so the "
        "fixtures cannot prove the normalizer works: " + ", ".join(missing)
    )
    assert uncaptured <= read_keys, (
        "an exempted key is no longer read; drop it from the exemption rather "
        "than leaving it unexplained"
    )
