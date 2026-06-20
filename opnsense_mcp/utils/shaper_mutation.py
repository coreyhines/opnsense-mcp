"""Shared async mutation helpers for traffic shaper write MCP tools."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from opnsense_mcp.tools.shaper_settings import (
    SEARCH_BODY,
    fetch_shaper_settings_raw,
    search_shaper_pipes,
    search_shaper_queues,
    search_shaper_rules,
)
from opnsense_mcp.utils.shaper_snapshot_store import capture_snapshot
from opnsense_mcp.utils.shaper_types import TOOL_STATUS_SUCCESS, TOOL_STATUS_WARNING
from opnsense_mcp.utils.shaper_write_helpers import (
    build_mutation_response,
    pending_apply_fields,
)

if TYPE_CHECKING:
    from opnsense_mcp.utils.api import OPNsenseClient
    from opnsense_mcp.utils.mock_api import MockOPNsenseClient

ClientT = "OPNsenseClient | MockOPNsenseClient"


async def _search_rows(client: ClientT, path: str) -> list[dict[str, Any]]:
    """POST a shaper search_* endpoint and return flat rows."""
    if not client:
        return []
    resp = await client._make_request("POST", path, json=SEARCH_BODY)
    return list(resp.get("rows") or [])


async def capture_pre_mutation_snapshot(
    client: ClientT,
    *,
    description: str = "",
) -> str:
    """Capture settings/get + search rows before a mutation."""
    settings_raw = await fetch_shaper_settings_raw(client)
    pipes = await _search_rows(client, "/trafficshaper/settings/search_pipes")
    queues = await _search_rows(client, "/trafficshaper/settings/search_queues")
    rules = await _search_rows(client, "/trafficshaper/settings/search_rules")
    return capture_snapshot(
        settings_get=settings_raw,
        search_pipes=pipes,
        search_queues=queues,
        search_rules=rules,
        description=description,
    )


async def reconfigure_shaper(client: ClientT) -> dict[str, Any]:
    """POST service/reconfigure."""
    if not client:
        raise RuntimeError("No client available")
    return await client._make_request("POST", "/trafficshaper/service/reconfigure")


def pipe_description_map(pipes: list[dict[str, Any]]) -> dict[str, str]:
    """Map pipe uuid -> description for queue/rule serialize enums."""
    return {
        str(row.get("uuid", "")): str(row.get("description", row.get("uuid", "")))
        for row in pipes
        if row.get("uuid")
    }


def target_description_map(
    queues: list[dict[str, Any]],
    pipes: list[dict[str, Any]],
) -> dict[str, str]:
    """Map target uuid -> label for rule serialize enums."""
    result = pipe_description_map(pipes)
    for row in queues:
        uid = str(row.get("uuid", ""))
        if uid:
            result[uid] = str(row.get("description", uid))
    return result


async def finish_mutation(
    client: ClientT,
    *,
    snapshot_id: str,
    apply: bool,
    summary: str,
    structured: dict[str, Any],
    hints: list[str] | None = None,
    status: str = "success",
) -> dict[str, Any]:
    """Apply reconfigure when requested and return standard tool envelope."""
    reconfigure_result: dict[str, Any] | None = None
    if apply:
        reconfigure_result = await reconfigure_shaper(client)
    merged = {**structured, **pending_apply_fields(apply, reconfigure_result)}
    final_status = status
    if apply and merged.get("pending_changes") and not merged.get("applied"):
        final_status = TOOL_STATUS_WARNING
    return build_mutation_response(
        merged,
        summary,
        snapshot_id=snapshot_id,
        hints=hints,
        status=final_status,
    )


async def load_pipe_queue_rule_rows(
    client: ClientT,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Fetch raw search rows for pipes, queues, and rules."""
    pipes = await _search_rows(client, "/trafficshaper/settings/search_pipes")
    queues = await _search_rows(client, "/trafficshaper/settings/search_queues")
    rules = await _search_rows(client, "/trafficshaper/settings/search_rules")
    return pipes, queues, rules
