"""Tests for firewall log normalization helpers."""

from __future__ import annotations

import json
from pathlib import Path

from opnsense_mcp.utils.firewall_log_normalize import (
    normalize_log_dict,
    normalize_logs,
    parse_int,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "phase0-diagnostics"


def test_parse_int_is_null_safe() -> None:
    """Malformed, empty, and missing ports do not raise."""
    assert parse_int("53") == 53
    assert parse_int(443) == 443
    assert parse_int("") is None
    assert parse_int(None) is None
    assert parse_int("not-a-port") is None


def test_normalize_live_shaped_log_fields() -> None:
    """Live-shaped OPNsense keys are mapped to stable field names."""
    rows = json.loads((FIXTURE_DIR / "firewall_logs_sample.json").read_text())
    normalized = normalize_log_dict(rows[0])

    assert normalized["timestamp"] == rows[0]["__timestamp__"]
    assert normalized["interface"] == rows[0]["interface"]
    assert normalized["protocol"] == rows[0]["protoname"]
    assert normalized["src_ip"] == rows[0]["src"]
    assert normalized["dst_ip"] == rows[0]["dst"]
    assert normalized["src_port"] == int(rows[0]["srcport"])
    assert normalized["dst_port"] == int(rows[0]["dstport"])
    assert normalized["rule_id"] == rows[0]["rid"]
    assert normalized["rule_number"] == rows[0]["rulenr"]
    assert normalized["label"] == rows[0]["label"]
    assert normalized["raw"] == rows[0]


def test_normalize_alternate_keys_and_preserve_bad_raw_port() -> None:
    """Already-normalized key variants are accepted and bad raw values remain raw."""
    row = {
        "timestamp": "2026-06-28T12:00:00-05:00",
        "protocol": "TCP",
        "src_ip": "10.0.0.2",
        "dst_ip": "1.1.1.1",
        "src_port": "abc",
        "dst_port": "443",
    }

    normalized = normalize_log_dict(row)

    assert normalized["protocol"] == "tcp"
    assert normalized["src_port"] is None
    assert normalized["dst_port"] == 443
    assert normalized["raw"]["src_port"] == "abc"


def test_normalize_logs_keeps_repeated_events() -> None:
    """Repeated firewall log rows are real events and are not deduplicated."""
    row = {"protoname": "udp", "src": "10.0.0.2", "dst": "10.0.0.1"}

    assert len(normalize_logs([row, row])) == 2
