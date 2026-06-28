"""Tests for interface health helpers."""

from __future__ import annotations

import json
from pathlib import Path

from opnsense_mcp.utils.interface_health import (
    classify_interface,
    parse_counter,
    parse_link_speed,
    sort_interface_health,
    summarize_interfaces,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "phase0-diagnostics"


def load_interfaces() -> dict:
    """Load representative live-shaped interface rows."""
    return json.loads((FIXTURE_DIR / "interface_list_sample.json").read_text())


def test_parse_counter_flags_rollover_artifacts() -> None:
    """Uint64-looking negative artifacts are warning findings, not huge errors."""
    value, findings = parse_counter("18446744073709550493")

    assert value is None
    assert findings[0]["code"] == "counter_anomaly"
    assert findings[0]["severity"] == "warning"


def test_parse_link_speed_variants() -> None:
    """Common OPNsense and shorthand speed variants parse safely."""
    assert parse_link_speed("10000000000 bit/s") == 10_000_000_000
    assert parse_link_speed("10 Gbit") == 10_000_000_000
    assert parse_link_speed("1GbE") == 1_000_000_000
    assert parse_link_speed("100Mb") == 100_000_000
    assert parse_link_speed("") is None


def test_classify_warns_on_real_and_anomalous_counters() -> None:
    """WAN fixture includes both a real input error count and rollover artifact."""
    interfaces = load_interfaces()

    row = classify_interface("ax1", interfaces["ax1"], interfaces)

    assert row["health"] == "warning"
    assert "counter_nonzero" in row["health_flags"]
    assert "counter_anomaly" in row["health_flags"]
    assert row["key_counters"]["input_errors"] == 1675
    assert row["key_counters"]["output_errors"] is None


def test_unassigned_no_carrier_is_info_not_critical() -> None:
    """Unassigned physical ports should not page as critical."""
    interfaces = load_interfaces()

    row = classify_interface("igb0", interfaces["igb0"], interfaces)

    assert row["health"] == "info"
    assert "administratively_inactive" in row["health_flags"]


def test_bridge_member_down_warning() -> None:
    """Bridge rows report down member interfaces."""
    interfaces = load_interfaces()

    row = classify_interface("bridge0", interfaces["bridge0"], interfaces)

    assert row["health"] == "warning"
    assert "bridge_member_down" in row["health_flags"]


def test_sort_and_summary() -> None:
    """Rows can be sorted by severity and summarized."""
    interfaces = load_interfaces()
    rows = [
        classify_interface(name, data, interfaces)
        for name, data in interfaces.items()
        if name in {"ax1", "igb0", "bridge0"}
    ]

    sorted_rows = sort_interface_health(rows)
    summary = summarize_interfaces(rows)

    assert sorted_rows[0]["health"] == "warning"
    assert summary["total"] == 3
    assert summary["warning"] == 2
    assert summary["info"] == 1
