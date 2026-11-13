"""Writing back an MVC node that holds a list where an enum was expected.

PHP's ``json_encode`` renders an empty array as ``[]``, so an enum whose model
has no options at all (a firewall with no categories defined) reaches us as a
list rather than an option map. Reported against OPNsense 26.7.5 in GitHub PR
#31; tracked as Forgejo #164. ``flatten_mvc_node`` fell through to ``str()``
and posted ``"[]"``, which ``setRule`` rejects with "Related category not
found". The override loop had the same fallthrough for a caller's list.

The base node is a live ``getRule`` capture from 26.7.8 (sanitised), where one
category exists and ``categories`` is an option map. The ``[]`` variant swaps
that one field for the reported shape and checks nothing else moves.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from opnsense_mcp.utils.mvc_merge import flatten_mvc_node, merge_for_set

FIXTURE = Path(__file__).parent / "fixtures" / "opnsense-26.7.8" / "filter_getrule.json"
RULE = json.loads(FIXTURE.read_text())["rule"]


def _rule_with_empty_category_model() -> dict:
    """The captured rule as a firewall with zero categories would send it."""
    node = copy.deepcopy(RULE)
    node["categories"] = []
    return node


def test_captured_rule_flattens_to_real_values() -> None:
    """Guard the fixture: the normalised values must not be empty."""
    flat = flatten_mvc_node(RULE)

    assert flat["action"] == "pass"
    assert set(flat["interface"].split(",")) == {"opt2", "opt5", "opt9"}
    assert flat["protocol"] == "ICMP"
    assert flat["categories"] == ""
    assert "audit" not in flat


def test_an_empty_list_is_posted_as_an_empty_string() -> None:
    payload = merge_for_set(_rule_with_empty_category_model(), {})

    assert payload["categories"] == ""


def test_an_empty_list_changes_nothing_else_in_the_payload() -> None:
    from_map = merge_for_set(RULE, {"destination_net": "(self)"})
    from_list = merge_for_set(
        _rule_with_empty_category_model(), {"destination_net": "(self)"}
    )

    assert from_list == from_map


def test_a_list_of_scalars_is_comma_joined() -> None:
    node = {"categories": ["uuid-a", "uuid-b"]}

    assert flatten_mvc_node(node) == {"categories": "uuid-a,uuid-b"}


@pytest.mark.parametrize(
    ("override", "expected"),
    [(["uuid-a", "uuid-b"], "uuid-a,uuid-b"), ([], "")],
)
def test_a_list_override_is_comma_joined(override: list[str], expected: str) -> None:
    payload = merge_for_set(RULE, {"categories": override})

    assert payload["categories"] == expected


@pytest.mark.parametrize("bad", [[{"uuid": "x"}], [["nested"]]])
def test_a_list_of_non_scalars_is_refused_not_stringified(bad: list) -> None:
    """str() of a dict would post Python repr; fail before the write instead."""
    with pytest.raises(ValueError, match="categories"):
        flatten_mvc_node({"categories": bad})
    with pytest.raises(ValueError, match="categories"):
        merge_for_set({}, {"categories": bad})
