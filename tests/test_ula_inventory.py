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


def test_dhcp_normalizer_splits_real_search_host_ip_shape() -> None:
    response = {
        "rows": [
            {
                "uuid": "dhcp-uuid",
                "host": "printer",
                "ip": "172.20.8.2,2001:db8:1e5:b502::2",
                "hwaddr": "aa:bb:cc:dd:ee:ff",
            }
        ],
        "total": 1,
    }

    hits, skipped = _inventory_dhcp_hosts(response, PREFIX)

    assert skipped == 0
    assert hits == [
        {
            "source": "dhcp_reservation",
            "uuid": "dhcp-uuid",
            "name": "printer",
            "field": "ip",
            "address": "2001:db8:1e5:b502::2",
        }
    ]


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
    assert result["skipped_count"] == 1  # unresolved OLD_GUAS rule reference
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
        "hits": [],
    }
