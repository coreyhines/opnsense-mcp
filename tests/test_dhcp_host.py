import pytest

from opnsense_mcp.utils.dhcp_host import (
    DhcpHostRecord,
    apply_v4_suffix,
    apply_v6_suffix,
    find_ipv4_conflicts,
    flatten_host_for_write,
    format_ip_field,
    parse_ip_field,
)


def test_parse_ip_field_v4_and_v6():
    assert parse_ip_field("10.0.8.2,::2") == ("10.0.8.2", "::2")


def test_parse_ip_field_v4_only():
    assert parse_ip_field("10.0.8.2") == ("10.0.8.2", None)


def test_parse_ip_field_v6_only():
    assert parse_ip_field("::2") == (None, "::2")


def test_parse_ip_field_empty():
    assert parse_ip_field("") == (None, None)


def test_format_ip_field_roundtrip():
    assert format_ip_field("10.0.8.2", "::2") == "10.0.8.2,::2"
    assert format_ip_field("10.0.8.2", None) == "10.0.8.2"
    assert format_ip_field(None, "::2") == "::2"


def test_record_from_search_row():
    row = {
        "uuid": "u1",
        "host": "printer",
        "domain": "",
        "ip": "10.0.8.2,::2",
        "hwaddr": "c8:a3:e8:dc:1b:b9",
        "client_id": "",
        "set_tag": "",
        "descr": "VLAN81wifi",
        "comments": "",
        "cnames": "",
        "aliases": "",
        "local": "0",
        "lease_time": "",
        "ignore": "0",
    }
    rec = DhcpHostRecord.from_row(row)
    assert rec.uuid == "u1"
    assert rec.host == "printer"
    assert rec.ipv4 == "10.0.8.2"
    assert rec.ipv6_suffix == "::2"
    assert rec.hwaddr == "c8:a3:e8:dc:1b:b9"


def test_record_to_summary():
    row = {
        "uuid": "u1",
        "host": "printer",
        "ip": "10.0.8.2,::2",
        "hwaddr": "c8:a3:e8:dc:1b:b9",
        "client_id": "duid-here",
        "descr": "VLAN81wifi",
    }
    summary = DhcpHostRecord.from_row(row).to_summary()
    assert summary["ipv4"] == "10.0.8.2"
    assert summary["ipv6_suffix"] == "::2"
    assert summary["has_ipv6"] is True
    assert summary["descr"] == "VLAN81wifi"
    assert summary["client_id"] == "duid-here"


def test_apply_v4_suffix_replaces_last_octet():
    assert apply_v4_suffix("10.0.8.55", 2) == "10.0.8.2"


def test_apply_v4_suffix_rejects_out_of_range():
    with pytest.raises(ValueError):
        apply_v4_suffix("10.0.8.55", 256)
    with pytest.raises(ValueError):
        apply_v4_suffix("10.0.8.55", 0)


def test_apply_v4_full_address_validates():
    assert apply_v4_suffix("10.0.8.55", "10.0.8.9") == "10.0.8.9"


def test_apply_v6_suffix_normalizes():
    assert apply_v6_suffix(2) == "::2"
    assert apply_v6_suffix(10) == "::10"
    assert apply_v6_suffix("::0x10") == "::16"


def test_apply_v6_full_suffix_passthrough():
    assert apply_v6_suffix("::abcd") == "::abcd"


def test_flatten_host_for_write_changes_ip_only():
    row = {
        "uuid": "u1",
        "host": "printer",
        "domain": "d",
        "local": "0",
        "ip": "10.0.8.2,::2",
        "cnames": "",
        "client_id": "",
        "hwaddr": "AA:BB",
        "lease_time": "",
        "ignore": "0",
        "set_tag": "t1",
        "descr": "x",
        "comments": "c",
        "aliases": "",
    }
    rec = DhcpHostRecord.from_row(row)
    payload = flatten_host_for_write(rec, new_ipv4="10.0.8.9", new_ipv6="::9")
    assert payload["ip"] == "10.0.8.9,::9"
    assert "uuid" not in payload
    assert payload["host"] == "printer"
    assert payload["set_tag"] == "t1"
    assert payload["descr"] == "x"
    assert payload["hwaddr"] == "AA:BB"


def test_find_ipv4_conflicts_other_reservation():
    hosts = [
        {"uuid": "u1", "host": "printer", "ip": "10.0.8.2,::2", "hwaddr": "AA"},
        {"uuid": "u2", "host": "bose", "ip": "10.0.8.9,::9", "hwaddr": "BB"},
    ]
    leases = [{"address": "10.0.8.50", "hwaddr": "CC", "hostname": "tv"}]
    conflicts = find_ipv4_conflicts(
        target_ipv4="10.0.8.9",
        moving_uuid="u1",
        hosts=hosts,
        leases=leases,
    )
    assert any(c["kind"] == "reservation" and c["host"] == "bose" for c in conflicts)


def test_find_ipv4_conflicts_active_lease():
    hosts = [{"uuid": "u1", "host": "printer", "ip": "10.0.8.2,::2", "hwaddr": "AA"}]
    leases = [{"address": "10.0.8.9", "hwaddr": "CC", "hostname": "tv"}]
    conflicts = find_ipv4_conflicts(
        target_ipv4="10.0.8.9",
        moving_uuid="u1",
        hosts=hosts,
        leases=leases,
    )
    assert any(c["kind"] == "lease" and c["address"] == "10.0.8.9" for c in conflicts)


def test_find_ipv4_conflicts_none_when_free():
    hosts = [{"uuid": "u1", "host": "printer", "ip": "10.0.8.2,::2", "hwaddr": "AA"}]
    assert (
        find_ipv4_conflicts(
            target_ipv4="10.0.8.9",
            moving_uuid="u1",
            hosts=hosts,
            leases=[],
        )
        == []
    )
