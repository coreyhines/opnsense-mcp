"""#64: `get_logs` limit must count matches, not raw rows fetched.

Falsification targets:

- fetch `limit` raw rows, then filter: the only matching rows that sit past
  the first `limit` raw rows are silently lost, so a working filter still
  undercounts and `limit` never fills with matches.
- no truncation after filtering: a filter plus `limit` returns more than
  `limit` entries, so the caller's limit is a lie.
- over-fetch on the unfiltered path: a plain read must request exactly
  `limit`, not a wider window.
"""

from __future__ import annotations

from typing import Any

import pytest

from opnsense_mcp.tools.firewall_logs import (
    FILTER_OVERFETCH_MAX,
    FILTER_OVERFETCH_MIN,
    FirewallLogsTool,
)
from opnsense_mcp.tools.get_logs import GetLogsTool


def make_row(
    index: int, *, dstport: str = "80", action: str = "pass"
) -> dict[str, Any]:
    """A live-shaped log row (the keys OPNsense actually returns)."""
    return {
        "interface": "wan",
        "action": action,
        "protoname": "tcp",
        "src": f"198.51.100.{(index % 250) + 1}",
        "srcport": "12345",
        "dst": "203.0.113.10",
        "dstport": dstport,
        "rid": "1",
        "label": "default allow",
    }


class WindowClient:
    """Mimics the real endpoint: serves only the first `limit` rows.

    This is the behaviour that made the old order wrong: the endpoint has no
    offset, so the first `limit` rows are all a plain fetch can see.
    """

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows
        self.requested_limits: list[Any] = []

    async def get_firewall_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        self.requested_limits.append(limit)
        return list(self.rows[:limit]) if limit else list(self.rows)


# ---------------------------------------------------------------------------
# The core defect: limit counted raw rows, so matches past the window were lost
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_limit_counts_matches_beyond_the_first_window() -> None:
    """Only rows 95-99 match; limit=5 must return 5, not the 0 the old order gave."""
    corpus = [make_row(i) for i in range(100)]
    for i in range(95, 100):
        corpus[i] = make_row(i, dstport="53")
    client = WindowClient(corpus)
    tool = FirewallLogsTool(client)

    logs = await tool.get_firewall_logs(limit=5, dst_port=53)

    # Old order (fetch 5 raw rows, filter) returns nothing here.
    assert len(logs) == 5
    assert all(r["dstport"] == "53" for r in logs)
    # The filter forced a wider fetch, not the bare limit.
    assert client.requested_limits[0] > 5


@pytest.mark.asyncio
async def test_sparse_match_with_tiny_limit_is_found() -> None:
    """A single matching row far down the log is reachable with limit=1."""
    corpus = [make_row(i) for i in range(FILTER_OVERFETCH_MAX)]
    # Past the first row the old order fetched, inside the over-fetch floor.
    corpus[150] = make_row(150, action="block")
    client = WindowClient(corpus)
    tool = FirewallLogsTool(client)

    logs = await tool.get_firewall_logs(limit=1, action="block")

    assert len(logs) == 1
    assert logs[0]["action"] == "block"


@pytest.mark.asyncio
async def test_filtered_read_truncates_back_to_limit() -> None:
    """Every row matches; the wider window must not leak past `limit`."""
    client = WindowClient([make_row(i, action="block") for i in range(100)])
    tool = FirewallLogsTool(client)

    logs = await tool.get_firewall_logs(limit=10, action="block")

    assert len(logs) == 10
    assert all(r["action"] == "block" for r in logs)


@pytest.mark.asyncio
async def test_registered_get_logs_tool_counts_matches() -> None:
    """The surface the server exposes (get_logs) gets the same fix."""
    corpus = [make_row(i, dstport="53") for i in range(60)]
    client = WindowClient(corpus)
    tool = GetLogsTool(client)

    result = await tool.execute({"limit": 25, "dst_port": 53})

    assert result["status"] == "success"
    assert result["total_retrieved"] == 25
    assert len(result["logs"]) == 25
    assert all(r["dstport"] == "53" for r in result["logs"])
    # 25*10=250, above the floor and below the cap.
    assert client.requested_limits == [250]


# ---------------------------------------------------------------------------
# The unfiltered path is unchanged: request exactly `limit`, no over-fetch
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unfiltered_read_requests_exactly_the_limit() -> None:
    client = WindowClient([make_row(i) for i in range(100)])
    tool = FirewallLogsTool(client)

    logs = await tool.get_firewall_logs(limit=7)

    assert len(logs) == 7
    assert client.requested_limits == [7]


@pytest.mark.asyncio
async def test_unfiltered_execute_requests_exactly_the_limit() -> None:
    client = WindowClient([make_row(i) for i in range(100)])
    tool = GetLogsTool(client)

    result = await tool.execute({"limit": 30})

    assert result["status"] == "success"
    assert result["total_retrieved"] == 30
    assert client.requested_limits == [30]


# ---------------------------------------------------------------------------
# Over-fetch window bounds: floor, factor, cap
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_overfetch_window_scales_and_caps() -> None:
    corpus = [make_row(i, action="block") for i in range(FILTER_OVERFETCH_MAX)]
    cases = [
        (5, FILTER_OVERFETCH_MIN),  # 5*10=50 < floor -> floor
        (50, 500),  # 50*10, between floor and cap
        (500, FILTER_OVERFETCH_MAX),  # 500*10=5000 > cap -> cap
    ]
    for limit, expected in cases:
        client = WindowClient(corpus)
        tool = FirewallLogsTool(client)
        await tool.get_firewall_logs(limit=limit, action="block")
        assert client.requested_limits == [expected], (limit, expected)


@pytest.mark.asyncio
async def test_zero_limit_with_filter_stays_unlimited() -> None:
    """limit=0 means "no limit" to the endpoint and must not be truncated."""
    corpus = [make_row(i, action="block") for i in range(50)]
    client = WindowClient(corpus)
    tool = FirewallLogsTool(client)

    logs = await tool.get_firewall_logs(limit=0, action="block")

    assert client.requested_limits == [0]
    assert len(logs) == 50
