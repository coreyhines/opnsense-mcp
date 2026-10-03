"""Regression coverage for firewall-rule normalization and filtering."""

from __future__ import annotations

import pytest

from opnsense_mcp.tools.fw_rules import FwRulesTool, _map_search_rule_row


def test_nested_rule_inversion_flags_normalize_to_booleans() -> None:
    """Mock-shaped rules preserve the same inversion fields as API rows."""
    mapped = _map_search_rule_row(
        {
            "uuid": "nested",
            "source": {"net": "192.0.2.0/24", "port": ""},
            "destination": {"net": "any", "port": ""},
            "source_not": True,
            "destination_not": False,
        }
    )

    assert mapped["source_not"] is True
    assert mapped["destination_not"] is False


@pytest.mark.asyncio
async def test_interface_filter_rejects_substrings_and_floating_rules() -> None:
    """opt1 must not also select opt10 or an unbound floating rule."""
    rules = [
        {"id": "exact", "interface": "opt1"},
        {"id": "substring", "interface": "opt10"},
        {"id": "floating", "interface": ""},
    ]

    filtered = await FwRulesTool(None)._filter_rules_by_interface(rules, "opt1")

    assert [rule["id"] for rule in filtered] == ["exact"]


@pytest.mark.asyncio
async def test_interface_filter_matches_comma_separated_tokens() -> None:
    """A rule assigned to several interfaces matches each exact token."""
    rules = [
        {"id": "multi", "interface": "wan,opt1"},
        {"id": "other", "interface": "opt10"},
    ]

    filtered = await FwRulesTool(None)._filter_rules_by_interface(rules, "opt1")

    assert [rule["id"] for rule in filtered] == ["multi"]
