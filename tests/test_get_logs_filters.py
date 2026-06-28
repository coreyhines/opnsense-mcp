"""Tests for FirewallLogsTool filters on live-shaped log rows."""

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


def make_tool(rows: list[dict]) -> tuple[FirewallLogsTool, MagicMock]:
    client = MagicMock()
    client.get_firewall_logs = AsyncMock(return_value=rows)
    return FirewallLogsTool(client=client), client


# ---------------------------------------------------------------------------
# New filters: src_port, dst_port, interface
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_filter_by_interface_ax1(fixture_rows: list[dict]) -> None:
    """interface='ax1' returns only the 1 matching row."""
    tool, _ = make_tool(fixture_rows)
    logs = await tool.get_firewall_logs(interface="ax1")

    assert len(logs) == 1
    assert logs[0]["interface"] == "ax1"


@pytest.mark.asyncio
async def test_filter_by_interface_ax0_vlan81(fixture_rows: list[dict]) -> None:
    """interface='ax0_vlan81' returns all 7 matching rows."""
    tool, _ = make_tool(fixture_rows)
    logs = await tool.get_firewall_logs(interface="ax0_vlan81")

    assert len(logs) == 7
    assert all(r["interface"] == "ax0_vlan81" for r in logs)


@pytest.mark.asyncio
async def test_filter_by_dst_port_53(fixture_rows: list[dict]) -> None:
    """dst_port=53 returns the 7 DNS rows."""
    tool, _ = make_tool(fixture_rows)
    logs = await tool.get_firewall_logs(dst_port=53)

    assert len(logs) == 7
    assert all(r["dstport"] == "53" for r in logs)


@pytest.mark.asyncio
async def test_filter_by_dst_port_string(fixture_rows: list[dict]) -> None:
    """dst_port can be passed as a string and still filters correctly."""
    tool, _ = make_tool(fixture_rows)
    logs = await tool.get_firewall_logs(dst_port="53")

    assert len(logs) == 7


@pytest.mark.asyncio
async def test_filter_by_dst_port_2001(fixture_rows: list[dict]) -> None:
    """dst_port=2001 returns exactly 1 row."""
    tool, _ = make_tool(fixture_rows)
    logs = await tool.get_firewall_logs(dst_port=2001)

    assert len(logs) == 1
    assert logs[0]["dstport"] == "2001"


@pytest.mark.asyncio
async def test_filter_by_src_port(fixture_rows: list[dict]) -> None:
    """src_port=21750 returns exactly 1 row."""
    tool, _ = make_tool(fixture_rows)
    logs = await tool.get_firewall_logs(src_port=21750)

    assert len(logs) == 1
    assert logs[0]["srcport"] == "21750"


@pytest.mark.asyncio
async def test_filter_by_src_port_no_match(fixture_rows: list[dict]) -> None:
    """src_port that doesn't exist returns empty list."""
    tool, _ = make_tool(fixture_rows)
    logs = await tool.get_firewall_logs(src_port=9999)

    assert logs == []


# ---------------------------------------------------------------------------
# Existing filters still work on live-shaped rows
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_filter_by_src_ip(fixture_rows: list[dict]) -> None:
    """src_ip filter works on live-shaped rows using the 'src' key."""
    tool, _ = make_tool(fixture_rows)
    logs = await tool.get_firewall_logs(src_ip="216.180.246.111")

    assert len(logs) == 1
    assert logs[0]["src"] == "216.180.246.111"


@pytest.mark.asyncio
async def test_filter_by_dst_ip(fixture_rows: list[dict]) -> None:
    """dst_ip filter works on live-shaped rows using the 'dst' key."""
    tool, _ = make_tool(fixture_rows)
    logs = await tool.get_firewall_logs(dst_ip="68.47.7.163")

    assert len(logs) == 1
    assert logs[0]["dst"] == "68.47.7.163"


@pytest.mark.asyncio
async def test_filter_by_protocol(fixture_rows: list[dict]) -> None:
    """protocol='tcp' filters on the 'protoname' key in live-shaped rows."""
    tool, _ = make_tool(fixture_rows)
    logs = await tool.get_firewall_logs(protocol="tcp")

    assert len(logs) == 1
    assert logs[0]["protoname"] == "tcp"


@pytest.mark.asyncio
async def test_filter_by_protocol_case_insensitive(fixture_rows: list[dict]) -> None:
    """protocol filter is case-insensitive."""
    tool, _ = make_tool(fixture_rows)
    logs_lower = await tool.get_firewall_logs(protocol="udp")
    logs_upper = await tool.get_firewall_logs(protocol="UDP")

    assert len(logs_lower) == len(logs_upper) == 7


@pytest.mark.asyncio
async def test_filter_by_action(fixture_rows: list[dict]) -> None:
    """action='block' returns only the 1 block row."""
    tool, _ = make_tool(fixture_rows)
    logs = await tool.get_firewall_logs(action="block")

    assert len(logs) == 1
    assert logs[0]["action"] == "block"


@pytest.mark.asyncio
async def test_filter_by_action_rdr(fixture_rows: list[dict]) -> None:
    """action='rdr' returns all 7 redirect rows."""
    tool, _ = make_tool(fixture_rows)
    logs = await tool.get_firewall_logs(action="rdr")

    assert len(logs) == 7


# ---------------------------------------------------------------------------
# Combined filters
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_combined_interface_and_action(fixture_rows: list[dict]) -> None:
    """Combining interface and action filters narrows results correctly."""
    tool, _ = make_tool(fixture_rows)
    logs = await tool.get_firewall_logs(interface="ax1", action="block")

    assert len(logs) == 1


@pytest.mark.asyncio
async def test_combined_interface_and_dst_port(fixture_rows: list[dict]) -> None:
    """Combining interface and dst_port filters narrows results correctly."""
    tool, _ = make_tool(fixture_rows)
    logs = await tool.get_firewall_logs(interface="ax0_vlan81", dst_port=53)

    assert len(logs) == 7


# ---------------------------------------------------------------------------
# Filtered calls go to the client (no stale cache shortcut)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_filtered_call_hits_client(fixture_rows: list[dict]) -> None:
    """Each filtered execute call fetches from the client, not a cached shortcut."""
    tool, client = make_tool(fixture_rows)

    await tool.execute({"interface": "ax1"})
    await tool.execute({"dst_port": 53})

    assert client.get_firewall_logs.call_count == 2


@pytest.mark.asyncio
async def test_execute_with_src_port_filter(fixture_rows: list[dict]) -> None:
    """execute passes src_port through to get_firewall_logs."""
    tool, _ = make_tool(fixture_rows)
    result = await tool.execute({"src_port": 21750})

    assert result["status"] == "success"
    assert result["total_retrieved"] == 1
    assert result["filters_applied"]["src_port"] == 21750


@pytest.mark.asyncio
async def test_execute_with_interface_filter(fixture_rows: list[dict]) -> None:
    """execute passes interface through to get_firewall_logs."""
    tool, _ = make_tool(fixture_rows)
    result = await tool.execute({"interface": "ax0_vlan81"})

    assert result["status"] == "success"
    assert result["total_retrieved"] == 7
    assert result["filters_applied"]["interface"] == "ax0_vlan81"


@pytest.mark.asyncio
async def test_execute_with_dst_port_filter(fixture_rows: list[dict]) -> None:
    """execute passes dst_port through and filters correctly."""
    tool, _ = make_tool(fixture_rows)
    result = await tool.execute({"dst_port": 2001})

    assert result["status"] == "success"
    assert result["total_retrieved"] == 1
    assert result["filters_applied"]["dst_port"] == 2001
