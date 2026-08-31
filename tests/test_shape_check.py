"""Unit tests for ``_row_keys`` / ``_node_keys`` shape extraction.

These tests exercise the key-extraction logic without a live firewall,
catching regressions that ``--check-shapes`` itself cannot see because it
needs network access.

D1b blind spot (this bucket): when ``_row_keys`` runs on a node-shaped
response it returns an empty set; when the *fixture* is also node-shaped
the same empty set comes back; they compare equal and the check reports
a match having compared nothing. These tests prove that no longer happens.

Falsification for this bucket: revert ``_node_keys`` so it just calls
``_row_keys`` on the raw payload — i.e., ignores ``root_key`` and looks
for ``"rows"``. That must fail because node-shaped payloads have no
``"rows"`` key, so ``_row_keys`` returns an empty set instead of reporting
the missing root key as drift.
"""

from __future__ import annotations

import json
import pathlib
import sys
from dataclasses import replace

import pytest

# Ensure benchmark_performance is on the path when run from tests/.
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from benchmark_performance import (  # noqa: E402
    FIXTURE_DIR,
    SHAPE_SOURCES,
    _keys_for_source,
    _node_keys,
    _row_keys,
    compare_shape_keys,
)

# ===================================================================
# Helpers
# ===================================================================


def _row_payload(rows_data: list[dict]) -> dict:
    """A bootgrid response with the given rows."""
    return {
        "current": 1,
        "rowCount": len(rows_data),
        "total": len(rows_data),
        "rows": rows_data,
    }


# ===================================================================
# _row_keys — row-shaped responses (regression)
# ===================================================================


class TestRowKeys:
    """``_row_keys`` must still handle row-shaped payloads correctly."""

    def test_empty_rows(self) -> None:
        assert _row_keys({"rows": []}) == set()

    def test_single_row(self) -> None:
        row = {"a": "1", "b": "2"}
        assert _row_keys(_row_payload([row])) == {"a", "b"}

    def test_union_across_rows(self) -> None:
        r1 = {"a": "1"}
        r2 = {"b": "2", "c": "3"}
        assert _row_keys(_row_payload([r1, r2])) == {"a", "b", "c"}

    def test_non_dict_rows_skipped(self) -> None:
        result = _row_keys(_row_payload(["not-a-dict", {"a": 1}]))  # type: ignore[list-item]
        assert result == {"a"}

    def test_no_rows_key_returns_empty(self) -> None:
        assert _row_keys({"entries": {"x": 1}}) == set()

    def test_none_input(self) -> None:
        assert _row_keys(None) == set()


# ===================================================================
# _node_keys — node-shaped responses
# ===================================================================


class TestNodeKeysExpectedRootKey:
    """When the root key exists, ``_node_keys`` returns its field names."""

    def test_simple_node(self) -> None:
        payload = {"node": {"a": "1", "b": "2"}}
        keys, err = _node_keys(payload, "node")
        assert err is None
        assert keys == {"a", "b"}

    def test_nested_fields_in_node_are_outer_only(self) -> None:
        # MVC selects have nested option dicts — only outer names count.
        payload = {
            "node": {
                "simple": "value",
                "select": {
                    "opt1": {"value": "A", "selected": 0},
                    "opt2": {"value": "B", "selected": 1},
                },
            }
        }
        keys, err = _node_keys(payload, "node")
        assert err is None
        assert keys == {"simple", "select"}


class TestNodeKeysMissingRootKeyTheD1Case:
    """The root key is absent — this is the exact shape of defect D1.

    Fixture said ``{"entry": {...}}``; live API sends ``{"entries": {...}}``.
    Old code ran ``_row_keys`` on both, got empty set from each, and passed.

    New code must report drift, not silently skip.
    """

    def test_root_key_absent_returns_error_not_empty(self) -> None:
        payload = {"entries": {"x": 1}}  # key is "entries", we look for "entry"
        keys, err = _node_keys(payload, "entry")
        assert err is not None
        assert keys is None

    def test_root_key_absent_no_valid_keys_in_result(self) -> None:
        """Even with rich data under a *different* key, yield nothing usable."""
        payload = {"entries": {"a": "1", "b": "2"}}
        keys, err = _node_keys(payload, "entry")
        assert err is not None
        assert keys is None or keys == set()

    def test_empty_dict_node_yields_empty_set_but_no_error(self) -> None:
        payload = {"node": {}}
        keys, err = _node_keys(payload, "node")
        assert err is None
        assert keys == set()


class TestNodeKeysEmptyVsEmptyNotAMatch:
    """An empty-vs-empty comparison must never pass for a node source.

    If the fixture expects root key ``entry`` and live has none (or a
    different one), both paths must surface as drift, not a match.
    """

    def test_fixture_and_live_missing_key_both_error(self) -> None:
        payload1 = {"entries": {}}
        payload2 = {"entries": {}}

        _k1, e1 = _node_keys(payload1, "entry")
        _k2, e2 = _node_keys(payload2, "entry")

        assert e1 is not None
        assert e2 is not None

        findings = compare_shape_keys(
            None,
            None,
            kind="node",
            expected_error=e1,
            live_error=e2,
        )
        assert findings
        assert findings[0][0] == "error"

    def test_empty_vs_empty_successful_extracts_are_not_ok(self) -> None:
        findings = compare_shape_keys(set(), set(), kind="node")
        assert findings
        assert findings[0][0] == "error"

    def test_live_response_has_key_but_empty(self) -> None:
        payload = {"node": {}}
        keys, err = _node_keys(payload, "node")
        assert err is None
        assert keys == set()


class TestNodeKeysEdgeCases:
    """Edge cases for ``_node_keys`` when payload is not a dict."""

    def test_list_payload(self) -> None:
        keys, err = _node_keys([{"a": 1}], "node")
        assert err is not None
        assert keys is None

    def test_string_payload(self) -> None:
        keys, err = _node_keys("hello", "node")
        assert err is not None
        assert keys is None


class TestNodeKeysRootKeyNotADict:
    """Root key exists but its value is not a dict."""

    def test_string_value(self) -> None:
        payload = {"node": "just-a-string"}
        keys, err = _node_keys(payload, "node")
        assert err is not None
        assert keys is None


class TestShapeSourcesDeclareKinds:
    """SHAPE_SOURCES must declare kind/root_key for every entry."""

    def test_all_sources_have_kind(self) -> None:
        for filename, source in SHAPE_SOURCES.items():
            assert source.kind in {"rows", "node"}, filename
            if source.kind == "node":
                assert source.root_key, filename
            else:
                assert source.root_key is None, filename

    def test_every_captured_fixture_is_registered(self) -> None:
        """A count of node fixtures made an unregistered capture invisible.

        Five WireGuard captures sat in the directory with no entry, and the
        assertion that was standing in for this one — a hard-coded set of four
        node filenames — failed when the omission was corrected. What matters
        is that a capture nothing tracks fails on arrival.
        """
        fixture_dir = pathlib.Path(__file__).parent / "fixtures" / "opnsense-26.7.3"
        # One file holds two responses (`search_range` and `get_range`) under
        # one root, which `ShapeSource` cannot address: it names one endpoint.
        multi_response = {"dnsmasq_v6_range_responses.json"}
        captured = {p.name for p in fixture_dir.glob("*.json")} - multi_response

        assert not captured - set(SHAPE_SOURCES), (
            "captured fixtures with no SHAPE_SOURCES entry, so --check-shapes "
            "never diffs them against the firewall: "
            + ", ".join(sorted(captured - set(SHAPE_SOURCES)))
        )
        assert not set(SHAPE_SOURCES) - captured, (
            "SHAPE_SOURCES names a fixture that does not exist: "
            + ", ".join(sorted(set(SHAPE_SOURCES) - captured))
        )

    def test_captured_fixtures_yield_keys_under_declared_root(self) -> None:
        fixture_dir = pathlib.Path(__file__).parent / "fixtures" / "opnsense-26.7.3"
        for filename, source in SHAPE_SOURCES.items():
            if source.kind != "node":
                continue
            payload = json.loads((fixture_dir / filename).read_text())
            assert source.root_key is not None
            keys, err = _node_keys(payload, source.root_key)
            assert err is None, filename
            assert keys, filename


# ===================================================================
# Falsification (bucket B2 acceptance bar)
# ===================================================================


class TestRegressionOldBehaviorDoesNotApplyToNodePayloads:
    """Prove the new ``_node_keys`` does NOT behave like the old ``_row_keys``.

    Falsification: revert ``_node_keys`` so it just calls ``_row_keys`` on the
    raw payload. This test **must fail** because node-shaped payloads have no
    ``"rows"`` key, so ``_row_keys`` returns an empty set instead of reporting
    the missing root key as drift.
    """

    def test_node_keys_detects_missing_root_key(self) -> None:
        payload = {"other_key": {"a": "1"}}
        keys, err = _node_keys(payload, "expected_key")

        assert err is not None, (
            "_node_keys should report drift when root key is missing. "
            "(If this passes after reverting _node_keys to just call "
            "_row_keys, the falsification test is broken.)"
        )
        assert keys is None

    def test_node_keys_with_correct_root_key_yields_fields(self) -> None:
        payload = {"node": {"field_a": "1", "field_b": "2"}}
        keys, err = _node_keys(payload, "node")
        assert err is None
        assert keys == {"field_a", "field_b"}, (
            "_node_keys should return the node's field names. "
            "(Old code running _row_keys would return empty set.)"
        )


@pytest.mark.parametrize(
    ("root", "fields"),
    [
        ("entries", {"enabled", "interface"}),
        ("host", {"hostname", "server"}),
        ("rule", {"source_net", "destination_net"}),
        ("vip", {"address", "network"}),
    ],
)
def test_row_keys_on_node_payload_is_silently_empty(
    root: str, fields: set[str]
) -> None:
    """Document the blind spot: ``_row_keys`` on a node payload yields nothing."""
    payload = {root: dict.fromkeys(fields, "")}
    assert _row_keys(payload) == set()
    keys, err = _node_keys(payload, root)
    assert err is None
    assert keys == fields


class TestDispatchRoutesNodeSourcesToNodeKeys:
    """The one line the node work rests on, and the one nothing covered.

    `_node_keys` was tested exhaustively and `SHAPE_SOURCES` was checked for
    its `kind`/`root_key` declarations, but nothing asserted that a node source
    is actually routed to `_node_keys`. Deleting the node branch from
    `_keys_for_source` left the whole suite green -- which is precisely the
    defect this bucket exists to prevent, surviving in the wiring between two
    well-tested halves.
    """

    def test_a_node_source_extracts_the_node_not_the_rows(self) -> None:
        source = SHAPE_SOURCES["radvd_get_entry.json"]
        assert source.kind == "node"
        payload = json.loads((FIXTURE_DIR / "radvd_get_entry.json").read_text())

        keys, err = _keys_for_source(payload, source)

        assert err is None
        # Routed through _row_keys this is empty, and an empty set compares
        # equal to an empty set, which is the silent pass.
        assert keys
        assert "AdvPreferredLifetime" in keys
        assert keys == _node_keys(payload, source.root_key)[0]

    def test_a_row_source_still_goes_through_row_keys(self) -> None:
        source = SHAPE_SOURCES["filter_searchrule_rows.json"]
        assert source.kind == "rows"
        payload = json.loads((FIXTURE_DIR / "filter_searchrule_rows.json").read_text())

        keys, err = _keys_for_source(payload, source)

        assert err is None
        assert keys == _row_keys(payload)

    def test_a_node_source_without_a_root_key_is_an_error(self) -> None:
        broken = replace(SHAPE_SOURCES["radvd_get_entry.json"], root_key="")

        keys, err = _keys_for_source({"entries": {"a": 1}}, broken)

        assert keys is None
        assert err is not None
