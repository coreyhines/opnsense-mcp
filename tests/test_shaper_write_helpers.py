"""Tests for opnsense_mcp/utils/shaper_write_helpers.py — bucket 4b."""

from __future__ import annotations

from opnsense_mcp.utils.shaper_types import TOOL_STATUS_SUCCESS
from opnsense_mcp.utils.shaper_write_helpers import (
    build_mutation_response,
    detect_idempotent_set,
    issue_delete_confirm_token,
    pending_apply_fields,
    shaper_api_result_ok,
    validate_delete_confirm_token,
    validate_pipe_bandwidth,
    warn_lan_interface,
)


def test_delete_confirm_token_round_trip() -> None:
    issued = issue_delete_confirm_token("pipe", "abc-uuid")
    assert "token" in issued
    token = issued["token"]
    assert validate_delete_confirm_token("pipe", "abc-uuid", token) is True
    assert validate_delete_confirm_token("pipe", "abc-uuid", token) is False


def test_delete_confirm_wrong_token() -> None:
    issue_delete_confirm_token("queue", "q1")
    assert validate_delete_confirm_token("queue", "q1", "bad") is False


def test_detect_idempotent_pipe() -> None:
    flat = {
        "uuid": "u1",
        "bandwidth": 100,
        "bandwidth_metric": "Mbit",
        "scheduler": "fq_codel",
        "enabled": True,
    }
    assert detect_idempotent_set(flat, dict(flat)) is True
    changed = dict(flat)
    changed["bandwidth"] = 200
    assert detect_idempotent_set(flat, changed) is False


def test_validate_pipe_bandwidth_errors() -> None:
    hints = validate_pipe_bandwidth(2000, 1000)
    assert any("error" in h for h in hints)


def test_validate_pipe_bandwidth_isp_warning() -> None:
    hints = validate_pipe_bandwidth(100, 1000, isp_rate_mbit=100)
    assert any("warning" in h for h in hints)


def test_warn_lan_interface() -> None:
    assert warn_lan_interface("lan") is not None
    assert warn_lan_interface("wan") is None


def test_build_mutation_response() -> None:
    resp = build_mutation_response(
        {"ok": True},
        "Done",
        snapshot_id="snap-1",
        hints=["hint"],
    )
    assert resp["status"] == TOOL_STATUS_SUCCESS
    assert resp["snapshot_id"] == "snap-1"


def test_pending_apply_fields() -> None:
    pending = pending_apply_fields(False)
    assert pending["pending_changes"] is True
    applied = pending_apply_fields(True, {"status": "ok"})
    assert applied["applied"] is True
    failed = pending_apply_fields(True, {"status": "failed"})
    assert failed["applied"] is False
    assert failed["pending_changes"] is True


def test_pipe_bandwidth_mbit_gbit() -> None:
    from opnsense_mcp.utils.shaper_write_helpers import pipe_bandwidth_mbit

    assert pipe_bandwidth_mbit(1, "Gbit") == 1000.0


def test_collect_pipe_bandwidth_hints_metric_aware() -> None:
    from opnsense_mcp.utils.shaper_write_helpers import collect_pipe_bandwidth_hints

    flat = {"bandwidth": 1, "bandwidth_metric": "Gbit"}
    hints = collect_pipe_bandwidth_hints(flat, {"line_rate_mbit": 500})
    assert any("error" in h for h in hints)


def test_has_bandwidth_guardrail_error() -> None:
    from opnsense_mcp.utils.shaper_write_helpers import has_bandwidth_guardrail_error

    assert has_bandwidth_guardrail_error(["error: too big"]) is True
    assert has_bandwidth_guardrail_error(["warning: high"]) is False


def test_shaper_api_result_ok() -> None:
    ok, detail = shaper_api_result_ok({"status": "ok"})
    assert ok is True
    assert detail is None
    ok, detail = shaper_api_result_ok({"status": "failed", "error": "nope"})
    assert ok is False
    assert detail == "nope"


def test_bufferbloat_shaped_rate_mbit_rounds() -> None:
    from opnsense_mcp.utils.shaper_write_helpers import bufferbloat_shaped_rate_mbit

    assert bufferbloat_shaped_rate_mbit(100) == 85
    assert bufferbloat_shaped_rate_mbit(33.3) == 28
