"""Tests for opnsense_mcp/utils/shaper_types.py — bucket 0 contract."""

from __future__ import annotations

import pytest

from opnsense_mcp.utils.shaper_types import (
    AUDIT_CODES,
    DEFAULT_WAN_INTERFACES,
    PIPE_SCHEDULERS,
    TOOL_STATUS_ERROR,
    TOOL_STATUS_SUCCESS,
    TOOL_STATUS_WARNING,
    AuditFinding,
    AuditResult,
    FlatShaperPipe,
    FlatShaperQueue,
    FlatShaperRule,
    InterpretationResult,
    ShaperToolResponse,
    is_valid_scheduler,
    make_tool_response,
)

# ---------------------------------------------------------------------------
# make_tool_response — factory + validation
# ---------------------------------------------------------------------------


def test_make_tool_response_success_minimal():
    resp = make_tool_response(
        status="success",
        structured={"pipes": []},
        summary="No pipes configured.",
    )
    assert resp["status"] == "success"
    assert resp["structured"] == {"pipes": []}
    assert resp["summary"] == "No pipes configured."
    assert resp["hints"] == []


def test_make_tool_response_with_hints():
    resp = make_tool_response(
        status="warning",
        structured={},
        summary="Check config.",
        hints=["Hint A", "Hint B"],
    )
    assert resp["hints"] == ["Hint A", "Hint B"]
    assert resp["status"] == "warning"


def test_make_tool_response_with_snapshot_id():
    resp = make_tool_response(
        status="success",
        structured={},
        summary="Applied.",
        snapshot_id="snap-001",
    )
    assert resp["snapshot_id"] == "snap-001"


def test_make_tool_response_with_baseline_id():
    resp = make_tool_response(
        status="success",
        structured={},
        summary="Stats.",
        baseline_id="base-abc",
    )
    assert resp["baseline_id"] == "base-abc"


def test_make_tool_response_defaults_no_optional_keys():
    """snapshot_id and baseline_id should be absent when not supplied."""
    resp = make_tool_response(status="success", structured={}, summary="Ok.")
    assert "snapshot_id" not in resp
    assert "baseline_id" not in resp


def test_make_tool_response_error_status():
    resp = make_tool_response(
        status="error",
        structured={"detail": "not found"},
        summary="Pipe not found.",
    )
    assert resp["status"] == "error"


def test_make_tool_response_critical_status():
    resp = make_tool_response(
        status="critical",
        structured={},
        summary="Scheduler drift detected.",
    )
    assert resp["status"] == "critical"


def test_make_tool_response_rejects_invalid_status():
    with pytest.raises(ValueError, match="status"):
        make_tool_response(status="unknown", structured={}, summary="Bad.")


def test_make_tool_response_rejects_empty_status():
    with pytest.raises(ValueError, match="status"):
        make_tool_response(status="", structured={}, summary="Bad.")


# ---------------------------------------------------------------------------
# ShaperToolResponse TypedDict structure
# ---------------------------------------------------------------------------


def test_shaper_tool_response_is_dict():
    resp: ShaperToolResponse = make_tool_response(
        status="success", structured={}, summary="ok"
    )
    assert isinstance(resp, dict)
    assert "status" in resp
    assert "structured" in resp
    assert "summary" in resp
    assert "hints" in resp


# ---------------------------------------------------------------------------
# FlatShaperPipe TypedDict
# ---------------------------------------------------------------------------


def test_flat_shaper_pipe_all_fields():
    pipe: FlatShaperPipe = {
        "uuid": "e93038e5-1234",
        "number": "10000",
        "description": "Download pipe",
        "enabled": True,
        "bandwidth": 1776,
        "bandwidth_metric": "Mbit",
        "scheduler": "fq_codel",
        "mask": "none",
        "codel_enable": False,
        "codel_target_ms": None,
        "codel_interval_ms": None,
        "codel_ecn_enable": True,
        "fqcodel_quantum": None,
        "fqcodel_limit": None,
        "fqcodel_flows": None,
        "pie_enable": False,
    }
    assert pipe["bandwidth"] == 1776
    assert pipe["scheduler"] == "fq_codel"
    assert pipe["codel_ecn_enable"] is True
    assert pipe["fqcodel_quantum"] is None


# ---------------------------------------------------------------------------
# FlatShaperQueue TypedDict
# ---------------------------------------------------------------------------


def test_flat_shaper_queue_fields():
    queue: FlatShaperQueue = {
        "uuid": "84c6c7d8-abc",
        "description": "Download queue",
        "enabled": True,
        "pipe_uuid": "e93038e5-1234",
        "weight": 100,
        "mask": "none",
        "codel_enable": False,
        "codel_target_ms": None,
        "codel_interval_ms": None,
        "codel_ecn_enable": False,
        "pie_enable": False,
    }
    assert queue["pipe_uuid"] == "e93038e5-1234"
    assert queue["weight"] == 100


# ---------------------------------------------------------------------------
# FlatShaperRule TypedDict
# ---------------------------------------------------------------------------


def test_flat_shaper_rule_fields():
    rule: FlatShaperRule = {
        "uuid": "690c995b-xyz",
        "description": "Download Rule",
        "enabled": True,
        "interface": "wan",
        "interface2": None,
        "direction": "in",
        "proto": "ip",
        "source": "any",
        "source_port": None,
        "destination": "any",
        "destination_port": None,
        "dscp": None,
        "target_uuid": "84c6c7d8-abc",
        "sequence": 1,
    }
    assert rule["direction"] == "in"
    assert rule["proto"] == "ip"
    assert rule["target_uuid"] == "84c6c7d8-abc"


# ---------------------------------------------------------------------------
# AuditFinding + AuditResult
# ---------------------------------------------------------------------------


def test_audit_finding_fields():
    finding = AuditFinding(
        severity="error",
        code="SCHEDULER_DRIFT",
        message="Config FQ-CoDel but FIFO active.",
    )
    assert finding.severity == "error"
    assert finding.code == "SCHEDULER_DRIFT"
    assert finding.message == "Config FQ-CoDel but FIFO active."


def test_audit_finding_severities():
    for sev in ("error", "warning", "info"):
        f = AuditFinding(severity=sev, code="X", message="msg")
        assert f.severity == sev


def test_audit_result_fields():
    findings = [
        AuditFinding(severity="warning", code="IPV6_MISSING", message="No IPv6 rules.")
    ]
    result = AuditResult(
        findings=findings,
        score=80,
        status="warning",
        summary_lines=["Config mostly good.", "IPv6 rules missing."],
    )
    assert result.score == 80
    assert result.status == "warning"
    assert len(result.findings) == 1
    assert result.summary_lines[0] == "Config mostly good."


# ---------------------------------------------------------------------------
# InterpretationResult
# ---------------------------------------------------------------------------


def test_interpretation_result_fields():
    result = InterpretationResult(
        verdict="warning",
        hints=["Scheduler drift detected."],
        rule_stats={"download": {"pkts": 3200000, "bytes": 2500000000}},
    )
    assert result.verdict == "warning"
    assert len(result.hints) == 1
    assert result.baseline_delta is None


def test_interpretation_result_with_baseline():
    result = InterpretationResult(
        verdict="success",
        hints=[],
        rule_stats={},
        baseline_delta={"download_pkts_delta": 50000},
    )
    assert result.baseline_delta == {"download_pkts_delta": 50000}


# ---------------------------------------------------------------------------
# Constants — non-empty and stable
# ---------------------------------------------------------------------------


def test_pipe_schedulers_non_empty():
    assert len(PIPE_SCHEDULERS) > 0


def test_pipe_schedulers_contains_fq_codel():
    assert "fq_codel" in PIPE_SCHEDULERS


def test_pipe_schedulers_contains_fifo():
    assert "fifo" in PIPE_SCHEDULERS


def test_pipe_schedulers_contains_fq_pie():
    assert "fq_pie" in PIPE_SCHEDULERS


def test_pipe_schedulers_contains_qfq():
    assert "qfq" in PIPE_SCHEDULERS


def test_default_wan_interfaces_is_frozenset():
    assert isinstance(DEFAULT_WAN_INTERFACES, frozenset)


def test_default_wan_interfaces_contains_wan():
    assert "wan" in DEFAULT_WAN_INTERFACES


def test_audit_codes_non_empty():
    assert len(AUDIT_CODES) > 0


def test_audit_codes_are_strings():
    for key, val in AUDIT_CODES.items():
        assert isinstance(key, str)
        assert isinstance(val, str)


def test_audit_codes_has_scheduler_drift():
    assert "SCHEDULER_DRIFT" in AUDIT_CODES


def test_audit_codes_has_ipv6_missing():
    assert "IPV6_MISSING" in AUDIT_CODES


def test_audit_codes_has_bw_exceeds_line_rate():
    assert "BW_EXCEEDS_LINE_RATE" in AUDIT_CODES


def test_tool_status_constants():
    assert TOOL_STATUS_SUCCESS == "success"
    assert TOOL_STATUS_ERROR == "error"
    assert TOOL_STATUS_WARNING == "warning"


# ---------------------------------------------------------------------------
# is_valid_scheduler helper
# ---------------------------------------------------------------------------


def test_is_valid_scheduler_known():
    assert is_valid_scheduler("fq_codel") is True
    assert is_valid_scheduler("fifo") is True
    assert is_valid_scheduler("fq_pie") is True


def test_is_valid_scheduler_unknown():
    assert is_valid_scheduler("bogus") is False
    assert is_valid_scheduler("") is False
