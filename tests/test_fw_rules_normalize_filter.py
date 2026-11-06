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


# group/search_item rows as the live firewall returns them, rebuilt from a
# list_groups read: the group is keyed by `ifname` and `members` is a comma
# string, not a list.
GROUP_ROWS = {
    "rows": [
        {
            "uuid": "1833c2c2-7f05-4b6f-b867-290dd50fb140",
            "ifname": "labNets",
            "members": "opt3,opt4,opt12",
            "%members": "VLAN3LAB, VLAN5LAB, VLAN9ipv6_lab",
            "nogroup": "0",
            "sequence": "0",
            "descr": "",
        },
        {
            "uuid": "1624f866-c496-465f-8968-a635a2d2d866",
            "ifname": "unTrustedNets",
            "members": "opt6,opt7",
            "%members": "VLAN4guest_wifi, VLAN6SolarDMZ",
            "nogroup": "0",
            "sequence": "0",
            "descr": "untrusted DMZs",
        },
        {
            "uuid": "63dd9d5b-2913-40d4-b58d-9088ff2f8a92",
            "ifname": "trustedNets",
            "members": "opt2,opt5",
            "%members": "VLAN2wired, VLAN81wifi",
            "nogroup": "0",
            "sequence": "0",
            "descr": "internal trusted vlans",
        },
    ],
    "total": 3,
}

GROUP_RULES = [
    {"id": "lab3", "interface": "opt3"},
    {"id": "lab12", "interface": "opt12"},
    {"id": "on_group", "interface": "labNets"},
    {"id": "guest", "interface": "opt6"},
    {"id": "wired", "interface": "opt2"},
    {"id": "letters", "interface": "lan"},
]


class _GroupClient:
    """Answers group/search_item only; every other read is empty."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def _make_request(self, method: str, endpoint: str, **_: object) -> object:
        self.calls.append((method, endpoint))
        if endpoint == "/api/firewall/group/search_item":
            return GROUP_ROWS
        return {"rows": [], "total": 0}


@pytest.mark.asyncio
async def test_interface_group_selects_its_members_rules() -> None:
    """A group name used to hit a missing endpoint and match nothing."""
    client = _GroupClient()
    tool = FwRulesTool(None)
    tool.client = client

    filtered = await tool._filter_rules_by_interface(GROUP_RULES, "labNets")

    assert [rule["id"] for rule in filtered] == ["lab3", "lab12", "on_group"]
    assert ("POST", "/api/firewall/group/search_item") in client.calls


@pytest.mark.asyncio
async def test_interface_group_match_is_exact() -> None:
    """trustedNets is a substring of unTrustedNets on the live firewall."""
    tool = FwRulesTool(None)
    tool.client = _GroupClient()

    filtered = await tool._filter_rules_by_interface(GROUP_RULES, "trustedNets")

    assert [rule["id"] for rule in filtered] == ["wired"]
