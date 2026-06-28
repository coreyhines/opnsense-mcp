"""Tests for FirewallLogsTool.analyze_logs using live-shaped fixture data."""

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


@pytest.fixture()
def mock_client(fixture_rows: list[dict]) -> MagicMock:
    client = MagicMock()
    client.get_firewall_logs = AsyncMock(return_value=fixture_rows)
    return client


@pytest.fixture()
def tool(mock_client: MagicMock) -> FirewallLogsTool:
    return FirewallLogsTool(client=mock_client)


@pytest.mark.asyncio
async def test_protocols_not_unknown(
    tool: FirewallLogsTool, fixture_rows: list[dict]
) -> None:
    """analyze_logs on live-shaped rows produces named protocols, not 'unknown'."""
    analysis = await tool.analyze_logs(fixture_rows)

    assert "unknown" not in analysis["protocols"], (
        f"'unknown' protocol found: {analysis['protocols']}"
    )
    assert "tcp" in analysis["protocols"]
    assert "udp" in analysis["protocols"]


@pytest.mark.asyncio
async def test_top_sources_not_unknown(
    tool: FirewallLogsTool, fixture_rows: list[dict]
) -> None:
    """analyze_logs on live-shaped rows produces real IP sources, not 'unknown'."""
    analysis = await tool.analyze_logs(fixture_rows)

    source_ips = [ip for ip, _ in analysis["top_sources"]]
    assert "unknown" not in source_ips, f"'unknown' source found: {source_ips}"
    assert "216.180.246.111" in source_ips


@pytest.mark.asyncio
async def test_top_destinations_not_unknown(
    tool: FirewallLogsTool, fixture_rows: list[dict]
) -> None:
    """analyze_logs on live-shaped rows produces real IP destinations, not 'unknown'."""
    analysis = await tool.analyze_logs(fixture_rows)

    dest_ips = [ip for ip, _ in analysis["top_destinations"]]
    assert "unknown" not in dest_ips, f"'unknown' destination found: {dest_ips}"
    assert "2601:441:8483:b508::1" in dest_ips


@pytest.mark.asyncio
async def test_src_port_counts_present(
    tool: FirewallLogsTool, fixture_rows: list[dict]
) -> None:
    """analyze_logs populates src_port_counts from live-shaped rows."""
    analysis = await tool.analyze_logs(fixture_rows)

    assert "src_port_counts" in analysis
    assert len(analysis["src_port_counts"]) > 0
    assert 21750 in analysis["src_port_counts"]


@pytest.mark.asyncio
async def test_dst_port_counts_present(
    tool: FirewallLogsTool, fixture_rows: list[dict]
) -> None:
    """analyze_logs populates dst_port_counts from live-shaped rows."""
    analysis = await tool.analyze_logs(fixture_rows)

    assert "dst_port_counts" in analysis
    assert 53 in analysis["dst_port_counts"]
    assert 2001 in analysis["dst_port_counts"]
    assert analysis["dst_port_counts"][53] == 7


@pytest.mark.asyncio
async def test_actions_counted_correctly(
    tool: FirewallLogsTool, fixture_rows: list[dict]
) -> None:
    """analyze_logs counts actions from live-shaped rows."""
    analysis = await tool.analyze_logs(fixture_rows)

    assert analysis["actions"].get("block") == 1
    assert analysis["actions"].get("rdr") == 7
    assert analysis["blocked_attempts"] == 1


@pytest.mark.asyncio
async def test_total_logs_matches_fixture(
    tool: FirewallLogsTool, fixture_rows: list[dict]
) -> None:
    """total_logs equals the number of rows in the fixture."""
    analysis = await tool.analyze_logs(fixture_rows)

    assert analysis["total_logs"] == len(fixture_rows)


@pytest.mark.asyncio
async def test_execute_response_shape(tool: FirewallLogsTool) -> None:
    """execute returns the expected top-level response shape."""
    result = await tool.execute({})

    assert result["status"] == "success"
    assert "logs" in result
    assert "analysis" in result
    assert "total_retrieved" in result
    assert "filters_applied" in result


@pytest.mark.asyncio
async def test_execute_analysis_uses_normalized_protocols(
    tool: FirewallLogsTool,
) -> None:
    """execute produces non-unknown protocols in analysis via normalize path."""
    result = await tool.execute({})

    analysis = result["analysis"]
    assert "unknown" not in analysis["protocols"]
    assert "tcp" in analysis["protocols"] or "udp" in analysis["protocols"]


@pytest.mark.asyncio
async def test_empty_logs_returns_zero_analysis(tool: FirewallLogsTool) -> None:
    """analyze_logs with empty input returns zeroed structure."""
    analysis = await tool.analyze_logs([])

    assert analysis["total_logs"] == 0
    assert analysis["protocols"] == {}
    assert analysis["top_sources"] == []
    assert analysis["top_destinations"] == []
    assert analysis["blocked_attempts"] == 0
    assert analysis["src_port_counts"] == {}
    assert analysis["dst_port_counts"] == {}


@pytest.mark.asyncio
async def test_include_rules_param_ignored(tool: FirewallLogsTool) -> None:
    """include_rules param does not cause an error and returns normal results."""
    result = await tool.execute({"include_rules": True})

    assert result["status"] == "success"
    assert "logs" in result
