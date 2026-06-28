"""Tests for FirewallLogsTool summary_only and include_rules call behavior (Bucket 8c)."""

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
) -> tuple[FirewallLogsTool, MagicMock]:
    client = MagicMock()
    client.get_firewall_logs = AsyncMock(return_value=rows)
    client.get_firewall_rules = AsyncMock(
        return_value=rules if rules is not None else []
    )
    return FirewallLogsTool(client=client), client


# ---------------------------------------------------------------------------
# summary_only behavior
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_summary_only_returns_empty_logs_list(fixture_rows: list[dict]) -> None:
    """summary_only=True returns logs: [] not the full list."""
    tool, _ = make_tool(fixture_rows)
    result = await tool.execute({"summary_only": True})

    assert result["status"] == "success"
    assert result["logs"] == []


@pytest.mark.asyncio
async def test_summary_only_total_retrieved_reflects_actual_count(
    fixture_rows: list[dict],
) -> None:
    """summary_only=True still reports total_retrieved from actual filtered count."""
    tool, _ = make_tool(fixture_rows)
    result = await tool.execute({"summary_only": True})

    assert result["total_retrieved"] == len(fixture_rows)


@pytest.mark.asyncio
async def test_summary_only_analysis_present(fixture_rows: list[dict]) -> None:
    """summary_only=True preserves analysis output with correct total_logs."""
    tool, _ = make_tool(fixture_rows)
    result = await tool.execute({"summary_only": True})

    assert "analysis" in result
    assert result["analysis"]["total_logs"] == len(fixture_rows)


@pytest.mark.asyncio
async def test_summary_only_false_returns_logs(fixture_rows: list[dict]) -> None:
    """summary_only=False returns the full logs list."""
    tool, _ = make_tool(fixture_rows)
    result = await tool.execute({"summary_only": False})

    assert result["logs"] == fixture_rows


@pytest.mark.asyncio
async def test_summary_only_default_returns_logs(fixture_rows: list[dict]) -> None:
    """Omitting summary_only defaults to False and returns logs."""
    tool, _ = make_tool(fixture_rows)
    result = await tool.execute({})

    assert len(result["logs"]) == len(fixture_rows)


@pytest.mark.asyncio
async def test_summary_only_preserves_filters_applied(fixture_rows: list[dict]) -> None:
    """summary_only=True still includes filters_applied in the response."""
    tool, _ = make_tool(fixture_rows)
    result = await tool.execute({"summary_only": True, "interface": "ax1"})

    assert "filters_applied" in result
    assert result["filters_applied"]["interface"] == "ax1"


# ---------------------------------------------------------------------------
# include_rules call count behavior
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_include_rules_false_performs_no_rule_lookup(
    fixture_rows: list[dict],
) -> None:
    """include_rules=False performs no rule lookup."""
    tool, client = make_tool(fixture_rows)
    await tool.execute({"include_rules": False})

    client.get_firewall_rules.assert_not_called()


@pytest.mark.asyncio
async def test_include_rules_default_performs_no_rule_lookup(
    fixture_rows: list[dict],
) -> None:
    """Omitting include_rules (default False) performs no rule lookup."""
    tool, client = make_tool(fixture_rows)
    await tool.execute({})

    client.get_firewall_rules.assert_not_called()


@pytest.mark.asyncio
async def test_include_rules_true_calls_exactly_once(fixture_rows: list[dict]) -> None:
    """include_rules=True calls get_firewall_rules exactly once per execute."""
    tool, client = make_tool(fixture_rows)
    await tool.execute({"include_rules": True})

    assert client.get_firewall_rules.call_count == 1


@pytest.mark.asyncio
async def test_include_rules_two_execute_calls_two_lookups(
    fixture_rows: list[dict],
) -> None:
    """Two separate execute calls with include_rules=True each make one lookup."""
    tool, client = make_tool(fixture_rows)
    await tool.execute({"include_rules": True})
    await tool.execute({"include_rules": True})

    assert client.get_firewall_rules.call_count == 2


# ---------------------------------------------------------------------------
# Lookup failure is non-fatal
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_include_rules_lookup_failure_logs_still_returned(
    fixture_rows: list[dict],
) -> None:
    """When rule lookup raises, log retrieval still succeeds."""
    client = MagicMock()
    client.get_firewall_logs = AsyncMock(return_value=fixture_rows)
    client.get_firewall_rules = AsyncMock(side_effect=RuntimeError("timeout"))
    tool = FirewallLogsTool(client=client)

    result = await tool.execute({"include_rules": True})

    assert result["status"] == "success"
    assert result["logs"] == fixture_rows
    assert result["analysis"]["rule_lookup_status"] == "unavailable"
    assert "rule_lookup_error" in result["analysis"]


# ---------------------------------------------------------------------------
# Combination: summary_only + include_rules
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_summary_only_with_include_rules(fixture_rows: list[dict]) -> None:
    """summary_only=True + include_rules=True returns empty logs with rule analysis."""
    tool, client = make_tool(
        fixture_rows,
        rules=[{"uuid": "abc-123", "sequence": "1", "description": "test"}],
    )
    result = await tool.execute({"summary_only": True, "include_rules": True})

    assert result["logs"] == []
    assert result["total_retrieved"] == len(fixture_rows)
    assert "top_rules" in result["analysis"]
    assert result["analysis"]["rule_lookup_status"] == "ok"
    client.get_firewall_rules.assert_called_once()
