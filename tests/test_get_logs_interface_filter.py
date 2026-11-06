"""get_logs interface filter resolves caller names to devices (#71).

filterlog rows carry the device (`vlan01`, `ax1`). The filter compared that
to the caller's string unchanged, so `interface="wan"` or `"opt13"` matched
nothing. Rows here are a live diagnostics/firewall/log capture.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from opnsense_mcp.tools.firewall_logs import FirewallLogsTool
from opnsense_mcp.utils.firewall_log_normalize import normalize_log_dict

FIX = Path(__file__).parent / "fixtures" / "opnsense-26.7.3"
ROWS = json.loads((FIX / "firewall_log_rows.json").read_text())["rows"]
OVERVIEW = json.loads((FIX / "interfaces_overview_export_min.json").read_text())["rows"]


def _tool(overview: Any = OVERVIEW) -> FirewallLogsTool:
    client = MagicMock()
    client.get_firewall_logs = AsyncMock(return_value=ROWS)
    if isinstance(overview, Exception):
        client._make_request = AsyncMock(side_effect=overview)
    else:
        client._make_request = AsyncMock(return_value=overview)
    return FirewallLogsTool(client=client)


def test_captured_rows_normalize_to_non_empty_values() -> None:
    """The normalizer's key choices against a real response, not a hand fixture."""
    for row in ROWS:
        norm = normalize_log_dict(row)
        for key in ("interface", "action", "protocol", "src_ip", "dst_ip"):
            assert norm[key], (key, row)
        assert norm["timestamp"] == row["__timestamp__"]
        assert norm["rule_number"] == row["rulenr"]
        assert isinstance(norm["dst_port"], int)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("asked", "devices"),
    [
        ("wan", {"ax1"}),
        ("WAN", {"ax1"}),
        ("opt13", {"vlan01"}),
        ("VLAN10Podman", {"vlan01"}),
        ("ax1", {"ax1"}),
    ],
)
async def test_identifier_description_or_device_select_the_device_rows(
    asked: str, devices: set[str]
) -> None:
    logs = await _tool().get_firewall_logs(limit=50, interface=asked)

    assert logs
    assert {row["interface"] for row in logs} == devices


@pytest.mark.asyncio
async def test_an_unknown_name_matches_nothing() -> None:
    assert await _tool().get_firewall_logs(limit=50, interface="nosuch") == []


@pytest.mark.asyncio
async def test_an_unreadable_overview_still_filters_by_device() -> None:
    tool = _tool(overview=RuntimeError("overview down"))

    logs = await tool.get_firewall_logs(limit=50, interface="ax1")

    assert {row["interface"] for row in logs} == {"ax1"}
