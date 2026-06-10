"""Tests for DHCP subnet DNS slot helpers."""

import pytest

from opnsense_mcp.utils.dhcp_subnet_dns import (
    format_dns_server_list,
    merge_slot_update,
    parse_dns_server_list,
    validate_address,
)


def test_merge_single_address_updates_slot_one() -> None:
    merged = merge_slot_update(
        ["10.0.10.5"],
        dns_server="10.0.10.4",
        family="ipv4",
    )
    assert merged == ["10.0.10.4"]


def test_merge_single_address_updates_slot_two() -> None:
    merged = merge_slot_update(
        ["10.0.10.4"],
        dns_server="10.0.10.5",
        slot=2,
        family="ipv4",
    )
    assert merged == ["10.0.10.4", "10.0.10.5"]


def test_merge_two_addresses_replace_both_slots() -> None:
    merged = merge_slot_update(
        ["10.0.10.1"],
        dns_servers=["10.0.10.4", "10.0.10.5"],
        family="ipv4",
    )
    assert merged == ["10.0.10.4", "10.0.10.5"]


def test_merge_rejects_empty_dns_servers() -> None:
    with pytest.raises(ValueError, match="Empty dns_servers"):
        merge_slot_update([], dns_servers=[], family="ipv4")


def test_merge_rejects_both_single_and_list() -> None:
    with pytest.raises(ValueError, match="not both"):
        merge_slot_update(
            [],
            dns_server="10.0.10.4",
            dns_servers=["10.0.10.5"],
            family="ipv4",
        )


def test_parse_and_format_ipv6_with_brackets() -> None:
    parsed = parse_dns_server_list("[2601:441:8483:b501::44]", "ipv6")
    assert parsed == ["2601:441:8483:b501::44"]
    formatted = format_dns_server_list(parsed, "ipv6")
    assert formatted == "[2601:441:8483:b501::44]"


def test_validate_address_family_mismatch() -> None:
    with pytest.raises(ValueError, match="Expected IPv4"):
        validate_address("2601:441:8483:b501::44", "ipv4")
