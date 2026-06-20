"""Traffic shaper runtime statistics tool."""

from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING, Any

from opnsense_mcp.tools.shaper_settings import (
    fetch_shaper_statistics,
    search_shaper_pipes,
)
from opnsense_mcp.utils.shaper_interpret import (
    format_statistics_summary,
    interpret_statistics,
    store_baseline,
)
from opnsense_mcp.utils.shaper_types import TOOL_STATUS_ERROR, make_tool_response

if TYPE_CHECKING:
    from opnsense_mcp.utils.api import OPNsenseClient
    from opnsense_mcp.utils.mock_api import MockOPNsenseClient

logger = logging.getLogger(__name__)

ClientT = "OPNsenseClient | MockOPNsenseClient | None"


class ShaperStatisticsTool:
    """Fetch runtime shaper statistics with interpretation and baseline compare."""

    name = "shaper_statistics"
    description = (
        "Get traffic shaper runtime statistics with structured hints; "
        "optional baseline_id compares against a prior snapshot"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "baseline_id": {
                "type": "string",
                "description": (
                    "Optional baseline id from a prior shaper_statistics call "
                    "for pkts/bytes delta comparison"
                ),
            },
        },
        "required": [],
    }

    def __init__(self, client: ClientT) -> None:
        """Initialize with an OPNsense API client."""
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Fetch statistics, interpret, and store a new baseline snapshot."""
        params = params or {}
        if not self.client:
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": "No client available"},
                summary="**Error:** No OPNsense client configured.",
            )

        compare_baseline_id = str(params.get("baseline_id") or "").strip() or None
        new_baseline_id = str(uuid.uuid4())

        try:
            statistics = await fetch_shaper_statistics(self.client)
            pipes = await search_shaper_pipes(self.client)
            interpretation = interpret_statistics(
                statistics,
                pipes=pipes,
                baseline_id=compare_baseline_id,
            )
            store_baseline(new_baseline_id, statistics)
        except Exception as exc:
            logger.exception("Failed to get shaper statistics")
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": str(exc)},
                summary=f"**Error:** Failed to get statistics — {exc}",
            )

        summary = format_statistics_summary(statistics, interpretation)
        if compare_baseline_id and interpretation.baseline_delta is not None:
            summary += (
                f"\n\nCompared against baseline `{compare_baseline_id}` "
                f"({len(interpretation.baseline_delta)} rule delta(s))."
            )
        summary += f"\n\nStored snapshot as baseline `{new_baseline_id}`."

        structured: dict[str, Any] = {
            "statistics": statistics,
            "verdict": interpretation.verdict,
            "rule_stats": interpretation.rule_stats,
            "baseline_delta": interpretation.baseline_delta,
            "stored_baseline_id": new_baseline_id,
        }

        return make_tool_response(
            status=interpretation.verdict,
            structured=structured,
            summary=summary,
            hints=interpretation.hints,
            baseline_id=new_baseline_id,
        )
