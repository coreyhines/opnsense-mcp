"""Tests for FirewallLogsTool rule correlation (Bucket 8c)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from opnsense_mcp.tools.firewall_logs import FirewallLogsTool

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "phase0-diagnostics"


@pytest.fixture()
def fixture_rows() -> list[dict]:
    return json.loads((FIXTURE_DIR / "firewall_logs_sample.json").read_text())


def make_tool(
    rows: list[dict],
    rules: list[dict] | None = None,
    rules_error: Exception | None = None,
) -> tuple[FirewallLogsTool, MagicMock]:
    client = MagicMock()
    client.get_firewall_logs = AsyncMock(return_value=rows)
    if rules_error is not None:
        client.get_firewall_rules = AsyncMock(side_effect=rules_error)
    else:
        client.get_firewall_rules = AsyncMock(
            return_value=rules if rules is not None else []
        )
    return FirewallLogsTool(client=client), client


# ---------------------------------------------------------------------------
# Default path: no rule lookup
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_include_rules_does_not_call_get_firewall_rules(
    fixture_rows: list[dict],
) -> None:
    """Default execute() must not call get_firewall_rules."""
    tool, client = make_tool(fixture_rows)
    result = await tool.execute({})

    assert result["status"] == "success"
    client.get_firewall_rules.assert_not_called()


@pytest.mark.asyncio
async def test_include_rules_false_does_not_call_get_firewall_rules(
    fixture_rows: list[dict],
) -> None:
    """include_rules=False must not call get_firewall_rules."""
    tool, client = make_tool(fixture_rows)
    result = await tool.execute({"include_rules": False})

    assert result["status"] == "success"
    client.get_firewall_rules.assert_not_called()


# ---------------------------------------------------------------------------
# Opt-in lookup
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_include_rules_true_calls_get_firewall_rules_once(
    fixture_rows: list[dict],
) -> None:
    """include_rules=True calls get_firewall_rules exactly once per execute."""
    tool, client = make_tool(fixture_rows)
    await tool.execute({"include_rules": True})

    client.get_firewall_rules.assert_called_once()


@pytest.mark.asyncio
async def test_include_rules_top_rules_in_analysis(fixture_rows: list[dict]) -> None:
    """include_rules=True adds top_rules list to analysis."""
    tool, _ = make_tool(fixture_rows)
    result = await tool.execute({"include_rules": True})

    assert "top_rules" in result["analysis"]
    assert isinstance(result["analysis"]["top_rules"], list)


@pytest.mark.asyncio
async def test_include_rules_rule_lookup_status_ok(fixture_rows: list[dict]) -> None:
    """rule_lookup_status is 'ok' when rules are fetched successfully."""
    tool, _ = make_tool(fixture_rows, rules=[{"uuid": "abc", "sequence": "1"}])
    result = await tool.execute({"include_rules": True})

    assert result["analysis"]["rule_lookup_status"] == "ok"
    assert "rule_lookup_error" not in result["analysis"]


# ---------------------------------------------------------------------------
# Lookup failure: non-fatal
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_include_rules_lookup_failure_nonfatal(fixture_rows: list[dict]) -> None:
    """Failure in get_firewall_rules does not prevent log retrieval."""
    tool, _ = make_tool(fixture_rows, rules_error=RuntimeError("connection refused"))
    result = await tool.execute({"include_rules": True})

    assert result["status"] == "success"
    assert len(result["logs"]) > 0
    assert result["analysis"]["rule_lookup_status"] == "unavailable"
    assert "rule_lookup_error" in result["analysis"]


@pytest.mark.asyncio
async def test_include_rules_lookup_failure_top_rules_still_present(
    fixture_rows: list[dict],
) -> None:
    """top_rules is still built from log fields even when rule lookup fails."""
    tool, _ = make_tool(fixture_rows, rules_error=RuntimeError("timeout"))
    result = await tool.execute({"include_rules": True})

    assert "top_rules" in result["analysis"]
    assert isinstance(result["analysis"]["top_rules"], list)
    assert len(result["analysis"]["top_rules"]) > 0


# ---------------------------------------------------------------------------
# Confidence labels
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_include_rules_high_confidence_match() -> None:
    """When log rid matches rule uuid, match_confidence is 'high'."""
    log_row = {
        "rid": "aabbccdd1122",
        "rulenr": "10",
        "action": "block",
        "protoname": "tcp",
        "src": "1.2.3.4",
        "dst": "5.6.7.8",
        "srcport": "1234",
        "dstport": "80",
        "interface": "eth0",
    }
    rule = {
        "uuid": "aabbccdd1122",
        "sequence": "10",
        "description": "Block external",
    }
    tool, _ = make_tool([log_row], rules=[rule])
    result = await tool.execute({"include_rules": True})

    top_rules = result["analysis"]["top_rules"]
    assert len(top_rules) == 1
    assert top_rules[0]["match_confidence"] == "high"
    assert top_rules[0]["rule_id"] == "aabbccdd1122"


@pytest.mark.asyncio
async def test_include_rules_low_confidence_match() -> None:
    """When log rulenr matches rule sequence but rid doesn't match uuid, confidence is 'low'."""
    log_row = {
        "rid": "aabbccdd1122",
        "rulenr": "42",
        "action": "block",
        "protoname": "tcp",
        "src": "1.2.3.4",
        "dst": "5.6.7.8",
        "srcport": "1234",
        "dstport": "80",
        "interface": "eth0",
    }
    rule = {
        "uuid": "ffffffff-no-match",  # does not match rid
        "sequence": "42",  # matches rulenr
        "description": "Some rule",
    }
    tool, _ = make_tool([log_row], rules=[rule])
    result = await tool.execute({"include_rules": True})

    top_rules = result["analysis"]["top_rules"]
    assert len(top_rules) == 1
    assert top_rules[0]["match_confidence"] == "low"
    assert top_rules[0]["rule_number"] == "42"


@pytest.mark.asyncio
async def test_include_rules_high_beats_low_when_uuid_matches() -> None:
    """High-confidence (uuid) match takes precedence over low-confidence (sequence)."""
    log_row = {
        "rid": "exact-match-uuid",
        "rulenr": "7",
        "action": "pass",
        "protoname": "udp",
        "src": "10.0.0.1",
        "dst": "8.8.8.8",
        "srcport": "5353",
        "dstport": "53",
        "interface": "eth0",
    }
    rule = {
        "uuid": "exact-match-uuid",
        "sequence": "7",
        "description": "DNS pass",
    }
    tool, _ = make_tool([log_row], rules=[rule])
    result = await tool.execute({"include_rules": True})

    top_rules = result["analysis"]["top_rules"]
    assert len(top_rules) == 1
    assert top_rules[0]["match_confidence"] == "high"


# ---------------------------------------------------------------------------
# No-match: fields preserved
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_include_rules_no_match_preserves_fields() -> None:
    """When no rule matches, rule_id/rule_number/label keys are still present."""
    log_row = {
        "rid": "deadbeef",
        "rulenr": "99",
        "action": "block",
        "protoname": "tcp",
        "src": "10.0.0.2",
        "dst": "8.8.4.4",
        "srcport": "9999",
        "dstport": "443",
        "interface": "eth1",
    }
    tool, _ = make_tool([log_row], rules=[])  # empty rules → no matches
    result = await tool.execute({"include_rules": True})

    top_rules = result["analysis"]["top_rules"]
    assert len(top_rules) == 1
    entry = top_rules[0]
    assert "rule_id" in entry
    assert "rule_number" in entry
    assert "label" in entry
    assert "match_confidence" not in entry


# ---------------------------------------------------------------------------
# Existing 8b analysis keys must be preserved alongside 8c keys
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_existing_analysis_keys_preserved(fixture_rows: list[dict]) -> None:
    """All existing analysis keys from 8b remain alongside new 8c keys."""
    tool, _ = make_tool(fixture_rows)
    result = await tool.execute({"include_rules": True})

    analysis = result["analysis"]
    for key in (
        "total_logs",
        "actions",
        "protocols",
        "top_sources",
        "top_destinations",
        "blocked_attempts",
        "src_port_counts",
        "dst_port_counts",
    ):
        assert key in analysis, f"Missing 8b analysis key: {key}"

    assert "top_rules" in analysis
    assert "rule_lookup_status" in analysis
