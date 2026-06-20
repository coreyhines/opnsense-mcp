"""Traffic shaper pipe read tools."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from opnsense_mcp.tools.shaper_settings import search_shaper_pipes
from opnsense_mcp.utils.shaper_normalize import normalize_pipe
from opnsense_mcp.utils.shaper_types import (
    TOOL_STATUS_ERROR,
    TOOL_STATUS_SUCCESS,
    FlatShaperPipe,
    make_tool_response,
)

if TYPE_CHECKING:
    from opnsense_mcp.utils.api import OPNsenseClient
    from opnsense_mcp.utils.mock_api import MockOPNsenseClient

logger = logging.getLogger(__name__)

ClientT = "OPNsenseClient | MockOPNsenseClient | None"


def _filter_pipes(
    pipes: list[FlatShaperPipe],
    *,
    enabled: bool | None,
    description: str | None,
) -> list[FlatShaperPipe]:
    """Apply optional client-side filters to pipe list."""
    result = pipes
    if enabled is not None:
        result = [p for p in result if p.get("enabled") is enabled]
    if description:
        needle = description.lower()
        result = [p for p in result if needle in (p.get("description") or "").lower()]
    return result


def _format_pipes_table(pipes: list[FlatShaperPipe]) -> str:
    """Markdown table for pipe summaries."""
    if not pipes:
        return "No pipes found."
    lines = [
        "| Description | BW | Scheduler | Enabled | UUID |",
        "|-------------|-----|-----------|---------|------|",
    ]
    for pipe in pipes:
        bw = pipe.get("bandwidth", 0)
        metric = pipe.get("bandwidth_metric", "Mbit")
        sched = pipe.get("scheduler", "")
        en = "yes" if pipe.get("enabled") else "no"
        desc = pipe.get("description", "")
        uuid = pipe.get("uuid", "")
        lines.append(f"| {desc} | {bw} {metric} | {sched} | {en} | `{uuid}` |")
    return "\n".join(lines)


def _find_pipe(
    pipes: list[FlatShaperPipe],
    *,
    uuid: str | None,
    description: str | None,
) -> FlatShaperPipe | None:
    """Match one pipe by uuid (exact) or description substring."""
    if uuid:
        for pipe in pipes:
            if pipe.get("uuid") == uuid:
                return pipe
    if description:
        needle = description.lower()
        for pipe in pipes:
            if needle in (pipe.get("description") or "").lower():
                return pipe
    return None


class ListShaperPipesTool:
    """List traffic shaper pipes (flat normalized view)."""

    name = "list_shaper_pipes"
    description = "List traffic shaper pipes with optional enabled/description filters"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "enabled": {
                "type": "boolean",
                "description": "When set, filter to enabled or disabled pipes only",
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
        """Fetch and return all pipes."""
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
            pipes = await search_shaper_pipes(self.client)
            pipes = _filter_pipes(pipes, enabled=enabled, description=description)
        except Exception as exc:
            logger.exception("Failed to list shaper pipes")
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": str(exc)},
                summary=f"**Error:** Failed to list pipes — {exc}",
            )

        summary = (
            f"**Traffic Shaper Pipes** — {len(pipes)} pipe(s)\n\n"
            f"{_format_pipes_table(pipes)}"
        )
        return make_tool_response(
            status=TOOL_STATUS_SUCCESS,
            structured={"pipes": pipes, "count": len(pipes)},
            summary=summary,
        )


class GetShaperPipeTool:
    """Get one traffic shaper pipe by uuid or description."""

    name = "get_shaper_pipe"
    description = "Get one traffic shaper pipe by uuid or description substring"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {
                "type": "string",
                "description": "Pipe UUID",
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
        """Fetch one pipe by uuid or description."""
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
                summary="**Error:** Provide `uuid` or `description` to identify a pipe.",
            )

        try:
            if uuid:
                resp = await self.client._make_request(
                    "GET",
                    f"/trafficshaper/settings/get_pipe/{uuid}",
                )
                row = resp.get("pipe") or {}
                if row:
                    pipe = normalize_pipe({**row, "uuid": row.get("uuid", uuid)})
                else:
                    pipes = await search_shaper_pipes(self.client)
                    pipe = _find_pipe(pipes, uuid=uuid, description=None)
            else:
                pipes = await search_shaper_pipes(self.client)
                pipe = _find_pipe(pipes, uuid=None, description=description)
        except Exception as exc:
            logger.exception("Failed to get shaper pipe")
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": str(exc)},
                summary=f"**Error:** Failed to get pipe — {exc}",
            )

        if pipe is None:
            label = uuid or description or "?"
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={
                    "error": "pipe not found",
                    "uuid": uuid,
                    "description": description,
                },
                summary=f"**Error:** No pipe matched `{label}`.",
            )

        desc = pipe.get("description", "")
        bw = pipe.get("bandwidth", 0)
        metric = pipe.get("bandwidth_metric", "Mbit")
        sched = pipe.get("scheduler", "")
        summary = (
            f"**Pipe:** {desc}\n\n"
            f"- Bandwidth: {bw} {metric}\n"
            f"- Scheduler: {sched}\n"
            f"- Enabled: {pipe.get('enabled')}\n"
            f"- UUID: `{pipe.get('uuid')}`"
        )
        return make_tool_response(
            status=TOOL_STATUS_SUCCESS,
            structured={"pipe": pipe},
            summary=summary,
        )
