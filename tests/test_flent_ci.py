"""Tests for flent CI summary parsing and latency gates."""

from __future__ import annotations

from opnsense_mcp.utils.flent_summary import (
    FlentMetrics,
    evaluate_gate,
    parse_flent_summary,
)

_SAMPLE_SUMMARY = """
=== Flent summary ===
Ping (ms) ICMP               : mean=142.01 median=141.00 min=130.00 max=152.00
Ping (ms) UDP (mean)         : mean=140.40
TCP download (sum)           : mean=597.12 Mbits/s
TCP upload (sum)             : mean=193.44 Mbits/s
TCP totals                   : mean=790.56 Mbits/s
"""


def test_parse_flent_summary_extracts_icmp_and_throughput():
    metrics = parse_flent_summary(_SAMPLE_SUMMARY)
    assert metrics == FlentMetrics(
        icmp_mean_ms=142.01,
        tcp_down_mbit=597.12,
        tcp_up_mbit=193.44,
        tcp_total_mbit=790.56,
    )


def test_evaluate_gate_passes_under_threshold():
    metrics = parse_flent_summary(_SAMPLE_SUMMARY)
    gate = evaluate_gate(metrics, icmp_max_ms=145.0)
    assert gate.passed is True
    assert gate.icmp_mean_ms == 142.01


def test_evaluate_gate_fails_at_or_above_threshold():
    metrics = parse_flent_summary(_SAMPLE_SUMMARY)
    gate = evaluate_gate(metrics, icmp_max_ms=142.0)
    assert gate.passed is False


def test_evaluate_gate_fails_when_icmp_missing():
    metrics = parse_flent_summary("TCP totals : mean=100.00 Mbits/s")
    gate = evaluate_gate(metrics, icmp_max_ms=145.0)
    assert gate.passed is False
    assert "Could not parse ICMP mean" in gate.messages[0]
