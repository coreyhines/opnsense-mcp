"""Tests for the read-only prefix inventory tool."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any

import pytest

from opnsense_mcp.tools.ula_inventory import (
    ALIASES_SEARCH,
    DHCP_HOSTS_SEARCH,
    FILTER_RULES_SEARCH,
    UNBOUND_SEARCH,
    InventoryPrefixTool,
    _inventory_aliases,
    _inventory_dhcp_hosts,
    _inventory_filter_rules,
    _inventory_unbound,
)

FIXTURES = Path(__file__).parent / "fixtures" / "opnsense-26.7.3"
PREFIX = ipaddress.ip_network("2001:db8:1e5:b502::/64")


PREFIX_TEXT_HOST = str(next(PREFIX.hosts()))


def test_filter_normalizer_reads_captured_search_rule_field_names() -> None:
    """The captured fixture uses source_net/destination_net, as the API does."""
    response = json.loads((FIXTURES / "filter_searchrule_rows.json").read_text())

    hits, skipped = _inventory_filter_rules(
        response, ipaddress.ip_network("2001:db8::/32")
    )

    assert skipped == 2  # the two literal ``any`` values
    assert hits == [
        {
            "source": "filter_rule",
            "uuid": "9b1c0a2e-1111-4a00-8000-000000000003",
            "name": "Staged v6 reject",
            "field": "destination_net",
            "address": "2001:db8::/32",
        }
    ]


def test_multi_address_alias_yields_each_matching_literal() -> None:
    response = {
        "rows": [
            {
                "uuid": "alias-uuid",
                "name": "OLD_GUAS",
                "type": "host",
                "content": (
                    "2001:0db8:1e5:b502::10\n2001:db8:1e5:b502::20\n2001:db8:ffff::30"
                ),
            }
        ],
        "total": 1,
    }

    hits, skipped = _inventory_aliases(response, PREFIX)

    assert skipped == 0
    assert [hit["address"] for hit in hits] == [
        "2001:0db8:1e5:b502::10",
        "2001:db8:1e5:b502::20",
    ]
    assert all(hit["uuid"] == "alias-uuid" for hit in hits)
    assert all(hit["name"] == "OLD_GUAS" for hit in hits)


def test_unbound_normalizer_reports_fqdn_uuid_and_server() -> None:
    response = {
        "rows": [
            {
                "uuid": "unbound-uuid",
                "hostname": "nas",
                "domain": "example.test",
                "rr": "AAAA",
                "server": "2001:db8:1e5:b502::19",
            },
            {
                "uuid": "outside-uuid",
                "hostname": "other",
                "domain": "example.test",
                "rr": "AAAA",
                "server": "2001:db8:ffff::19",
            },
        ],
        "total": 2,
    }

    hits, skipped = _inventory_unbound(response, PREFIX)

    assert skipped == 0
    assert hits == [
        {
            "source": "unbound_host_override",
            "uuid": "unbound-uuid",
            "name": "nas.example.test",
            "field": "server",
            "address": "2001:db8:1e5:b502::19",
        }
    ]


def test_dhcp_reservations_on_this_firewall_carry_a_prefix_relative_suffix() -> None:
    """The v6 half of a reservation is `::N`, not an address.

    This test replaces one that called `172.20.8.2,2001:db8:1e5:b502::2` the
    "real search_host ip shape". The firewall sends `<v4>,::2`: dnsmasq
    stores an interface identifier and prepends whatever prefix the interface
    serves, which is what the `dhcp create_host` schema calls an IPv6 suffix.

    A suffix parses cleanly as an absolute address in `::/128`, so it used to
    satisfy `parsed` and fail `matches` and land in neither counter. Every
    reservation on the box disappeared from a sweep that called itself
    complete.
    """
    response = {
        "rows": [
            {
                "uuid": "dhcp-uuid",
                "host": "printer",
                "ip": "192.0.2.2,::2",
                "hwaddr": "aa:bb:cc:dd:ee:ff",
            }
        ],
        "total": 1,
    }

    hits, skipped, suffixes = _inventory_dhcp_hosts(response, PREFIX)

    assert hits == []
    assert suffixes == [{"uuid": "dhcp-uuid", "name": "printer", "suffix": "::2"}]
    # The v4 half is a real address outside the queried v6 prefix, so it is a
    # skip. What matters is that nothing is silently uncounted.
    assert skipped == 1


def test_a_reservation_holding_a_full_address_is_still_a_hit() -> None:
    """Suffix handling must not swallow an absolute address inside the prefix."""
    response = {
        "rows": [
            {
                "uuid": "dhcp-uuid",
                "host": "nas",
                "ip": f"192.0.2.3,{PREFIX_TEXT_HOST}",
            }
        ],
        "total": 1,
    }

    hits, skipped, suffixes = _inventory_dhcp_hosts(response, PREFIX)

    assert suffixes == []
    assert [h["address"] for h in hits] == [PREFIX_TEXT_HOST]


def test_every_reservation_value_lands_in_exactly_one_bucket() -> None:
    """Hits, skips and suffixes must account for every value seen.

    The original defect was not a wrong answer but an unaccounted one: a value
    that matched no branch incremented no counter, so the totals looked
    healthy while 94 reservations went missing.
    """
    response = {
        "rows": [
            {"uuid": "a", "host": "one", "ip": "192.0.2.2,::2"},
            {"uuid": "b", "host": "two", "ip": f"192.0.2.3,{PREFIX_TEXT_HOST}"},
            {"uuid": "c", "host": "three", "ip": "192.0.2.9"},
            {"uuid": "d", "host": "four", "ip": "not-an-address"},
        ],
        "total": 4,
    }

    hits, skipped, suffixes = _inventory_dhcp_hosts(response, PREFIX)

    assert len(hits) + skipped + len(suffixes) == 6


def test_unparseable_values_are_skipped_and_counted() -> None:
    response = {
        "rows": [
            {
                "uuid": "alias-uuid",
                "name": "MIXED",
                "content": "not-an-address\n2001:db8:1e5:b502::42",
            }
        ]
    }

    hits, skipped = _inventory_aliases(response, PREFIX)

    assert skipped == 1
    assert hits[0]["address"] == "2001:db8:1e5:b502::42"


class FakeClient:
    """Serve fixture-shaped search responses and record read calls."""

    def __init__(self, responses: dict[str, Any]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []

    async def _make_request(
        self, method: str, endpoint: str, **kwargs: Any
    ) -> dict[str, Any]:
        self.calls.append((method, endpoint, kwargs.get("json")))
        return self.responses[endpoint]


@pytest.mark.asyncio
async def test_execute_sweeps_every_source_read_only_and_reports_values() -> None:
    client = FakeClient(
        {
            ALIASES_SEARCH: {
                "rows": [
                    {
                        "uuid": "alias-uuid",
                        "name": "OLD_GUAS",
                        "content": "2001:db8:1e5:b502::10",
                    }
                ]
            },
            FILTER_RULES_SEARCH: {
                "rows": [
                    {
                        "uuid": "rule-uuid",
                        "description": "Old routed network",
                        "source_net": "2001:db8:1e5:b502::/80",
                        "destination_net": "OLD_GUAS",
                    }
                ]
            },
            UNBOUND_SEARCH: {
                "rows": [
                    {
                        "uuid": "unbound-uuid",
                        "hostname": "nas",
                        "domain": "example.test",
                        "server": "2001:db8:1e5:b502::19",
                    }
                ]
            },
            DHCP_HOSTS_SEARCH: {
                "rows": [
                    {
                        "uuid": "dhcp-uuid",
                        "host": "printer",
                        "ip": "172.20.8.2,2001:db8:1e5:b502::2",
                    }
                ]
            },
        }
    )

    result = await InventoryPrefixTool(client).execute(
        {"prefix": "2001:0db8:1e5:b502::/64"}
    )

    assert result["status"] == "success"
    assert result["prefix"] == "2001:db8:1e5:b502::/64"
    assert result["count"] == 4
    # The OLD_GUAS rule reference, plus the v4 half of the reservation. That
    # second one used to be counted nowhere: parsed, outside the v6 prefix,
    # and matched by no branch.
    assert result["skipped_count"] == 2
    assert {hit["source"] for hit in result["hits"]} == {
        "firewall_alias",
        "filter_rule",
        "unbound_host_override",
        "dhcp_reservation",
    }
    assert all(method == "POST" for method, _, _ in client.calls)
    assert {endpoint for _, endpoint, _ in client.calls} == {
        ALIASES_SEARCH,
        FILTER_RULES_SEARCH,
        UNBOUND_SEARCH,
        DHCP_HOSTS_SEARCH,
    }


@pytest.mark.asyncio
async def test_empty_result_is_a_successful_sweep() -> None:
    client = FakeClient(
        {
            ALIASES_SEARCH: {"rows": [], "total": 0},
            FILTER_RULES_SEARCH: {"rows": [], "total": 0},
            UNBOUND_SEARCH: {"rows": [], "total": 0},
            DHCP_HOSTS_SEARCH: {"rows": [], "total": 0},
        }
    )

    result = await InventoryPrefixTool(client).execute({"prefix": "2001:db8::/32"})

    assert result == {
        "status": "success",
        "prefix": "2001:db8::/32",
        "count": 0,
        "skipped_count": 0,
        "suffix_count": 0,
        "suffixes": [],
        "hits": [],
    }
