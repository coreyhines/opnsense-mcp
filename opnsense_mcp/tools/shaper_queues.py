"""Traffic shaper queue read tools."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from opnsense_mcp.tools.shaper_settings import search_shaper_queues
from opnsense_mcp.utils.shaper_normalize import normalize_queue
from opnsense_mcp.utils.shaper_types import (
    TOOL_STATUS_ERROR,
    TOOL_STATUS_SUCCESS,
    FlatShaperQueue,
    make_tool_response,
)

if TYPE_CHECKING:
    from opnsense_mcp.utils.api import OPNsenseClient
    from opnsense_mcp.utils.mock_api import MockOPNsenseClient

logger = logging.getLogger(__name__)

ClientT = "OPNsenseClient | MockOPNsenseClient | None"


def _filter_queues(
    queues: list[FlatShaperQueue],
    *,
    enabled: bool | None,
    description: str | None,
) -> list[FlatShaperQueue]:
    """Apply optional client-side filters to queue list."""
    result = queues
    if enabled is not None:
        result = [q for q in result if q.get("enabled") is enabled]
    if description:
        needle = description.lower()
        result = [q for q in result if needle in (q.get("description") or "").lower()]
    return result


def _format_queues_table(queues: list[FlatShaperQueue]) -> str:
    """Markdown table for queue summaries."""
    if not queues:
        return "No queues found."
    lines = [
        "| Description | Weight | Pipe UUID | Enabled | UUID |",
        "|-------------|--------|-----------|---------|------|",
    ]
    for queue in queues:
        desc = queue.get("description", "")
        weight = queue.get("weight", 0)
        pipe_uuid = queue.get("pipe_uuid", "")
        en = "yes" if queue.get("enabled") else "no"
        uuid = queue.get("uuid", "")
        lines.append(f"| {desc} | {weight} | `{pipe_uuid}` | {en} | `{uuid}` |")
    return "\n".join(lines)


def _find_queue(
    queues: list[FlatShaperQueue],
    *,
    uuid: str | None,
    description: str | None,
) -> FlatShaperQueue | None:
    """Match one queue by uuid (exact) or description substring."""
    if uuid:
        for queue in queues:
            if queue.get("uuid") == uuid:
                return queue
    if description:
        needle = description.lower()
        for queue in queues:
            if needle in (queue.get("description") or "").lower():
                return queue
    return None


class ListShaperQueuesTool:
    """List traffic shaper queues (flat normalized view)."""

    name = "list_shaper_queues"
    description = "List traffic shaper queues with optional enabled/description filters"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "enabled": {
                "type": "boolean",
                "description": "When set, filter to enabled or disabled queues only",
            },
            "description": {
                "type": "string",
                "description": "Optional description substring filter",
            },
        },
        "required": [],
    }

    def __init__(self, client: ClientT) -> None:
        """Initialize with an OPNsense API client."""
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Fetch and return all queues."""
        params = params or {}
        if not self.client:
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": "No client available"},
                summary="**Error:** No OPNsense client configured.",
            )

        enabled = params.get("enabled")
        if enabled is not None:
            enabled = bool(enabled)
        description = str(params.get("description") or "").strip() or None

        try:
            queues = await search_shaper_queues(self.client)
            queues = _filter_queues(queues, enabled=enabled, description=description)
        except Exception as exc:
            logger.exception("Failed to list shaper queues")
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": str(exc)},
                summary=f"**Error:** Failed to list queues — {exc}",
            )

        summary = (
            f"**Traffic Shaper Queues** — {len(queues)} queue(s)\n\n"
            f"{_format_queues_table(queues)}"
        )
        return make_tool_response(
            status=TOOL_STATUS_SUCCESS,
            structured={"queues": queues, "count": len(queues)},
            summary=summary,
        )


class GetShaperQueueTool:
    """Get one traffic shaper queue by uuid or description."""

    name = "get_shaper_queue"
    description = "Get one traffic shaper queue by uuid or description substring"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {
                "type": "string",
                "description": "Queue UUID",
            },
            "description": {
                "type": "string",
                "description": "Description substring when uuid is omitted",
            },
        },
        "required": [],
    }

    def __init__(self, client: ClientT) -> None:
        """Initialize with an OPNsense API client."""
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Fetch one queue by uuid or description."""
        params = params or {}
        if not self.client:
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": "No client available"},
                summary="**Error:** No OPNsense client configured.",
            )

        uuid = str(params.get("uuid") or "").strip() or None
        description = str(params.get("description") or "").strip() or None
        if not uuid and not description:
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": "uuid or description required"},
                summary="**Error:** Provide `uuid` or `description` to identify a queue.",
            )

        try:
            if uuid:
                resp = await self.client._make_request(
                    "GET",
                    f"/trafficshaper/settings/get_queue/{uuid}",
                )
                row = resp.get("queue") or {}
                if row:
                    queue = normalize_queue({**row, "uuid": row.get("uuid", uuid)})
                else:
                    queues = await search_shaper_queues(self.client)
                    queue = _find_queue(queues, uuid=uuid, description=None)
            else:
                queues = await search_shaper_queues(self.client)
                queue = _find_queue(queues, uuid=None, description=description)
        except Exception as exc:
            logger.exception("Failed to get shaper queue")
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": str(exc)},
                summary=f"**Error:** Failed to get queue — {exc}",
            )

        if queue is None:
            label = uuid or description or "?"
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={
                    "error": "queue not found",
                    "uuid": uuid,
                    "description": description,
                },
                summary=f"**Error:** No queue matched `{label}`.",
            )

        desc = queue.get("description", "")
        summary = (
            f"**Queue:** {desc}\n\n"
            f"- Weight: {queue.get('weight')}\n"
            f"- Pipe UUID: `{queue.get('pipe_uuid')}`\n"
            f"- Enabled: {queue.get('enabled')}\n"
            f"- UUID: `{queue.get('uuid')}`"
        )
        return make_tool_response(
            status=TOOL_STATUS_SUCCESS,
            structured={"queue": queue},
            summary=summary,
        )
