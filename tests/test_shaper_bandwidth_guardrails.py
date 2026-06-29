"""Tests for metric-aware shaper bandwidth guardrails on write tools."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from opnsense_mcp.tools.shaper_pipes import AddShaperPipeTool
from opnsense_mcp.utils.shaper_types import TOOL_STATUS_ERROR


@pytest.mark.asyncio
async def test_add_shaper_pipe_blocks_gbit_over_line_rate() -> None:
    client = MagicMock()
    client._make_request = AsyncMock()
    tool = AddShaperPipeTool(client)
    resp = await tool.execute(
        {
            "description": "WAN download",
            "bandwidth": 1,
            "bandwidth_metric": "Gbit",
            "line_rate_mbit": 500,
            "apply": False,
        }
    )
    assert resp["status"] == TOOL_STATUS_ERROR
    client._make_request.assert_not_awaited()
