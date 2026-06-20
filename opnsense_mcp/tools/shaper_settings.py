"""Traffic shaper global settings read tool and shared fetch helpers."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from opnsense_mcp.utils.shaper_normalize import (
    normalize_pipe,
    normalize_queue,
    normalize_rule,
    pipes_from_settings_get,
    queues_from_settings_get,
    rules_from_settings_get,
)
from opnsense_mcp.utils.shaper_types import (
    TOOL_STATUS_ERROR,
    TOOL_STATUS_SUCCESS,
    FlatShaperPipe,
    FlatShaperQueue,
    FlatShaperRule,
    make_tool_response,
)

if TYPE_CHECKING:
    from opnsense_mcp.utils.api import OPNsenseClient
    from opnsense_mcp.utils.mock_api import MockOPNsenseClient

logger = logging.getLogger(__name__)

SEARCH_BODY: dict[str, int] = {"current": 1, "rowCount": 50}

ClientT = "OPNsenseClient | MockOPNsenseClient | None"


def _unwrap_ts_section(section: dict[str, Any]) -> dict[str, Any]:
    """Unwrap nested pipe/queue/rule container from settings/get ts tree."""
    if len(section) == 1:
        sole_key = next(iter(section))
        if sole_key in {"pipe", "queue", "rule"} and isinstance(
            section[sole_key], dict
        ):
            return section[sole_key]
    return section


def _ts_from_settings_response(data: dict[str, Any]) -> dict[str, Any]:
    """Return the ``ts`` subtree from a settings/get response."""
    return data.get("ts") or {}


async def fetch_shaper_settings_raw(client: ClientT) -> dict[str, Any]:
    """GET /trafficshaper/settings/get."""
    if not client:
        raise RuntimeError("No client available")
    return await client._make_request("GET", "/trafficshaper/settings/get")


async def search_shaper_pipes(client: ClientT) -> list[FlatShaperPipe]:
    """POST search_pipes and normalize rows."""
    if not client:
        raise RuntimeError("No client available")
    resp = await client._make_request(
        "POST",
        "/trafficshaper/settings/search_pipes",
        json=SEARCH_BODY,
    )
    return [normalize_pipe(row) for row in resp.get("rows", [])]


async def search_shaper_queues(client: ClientT) -> list[FlatShaperQueue]:
    """POST search_queues and normalize rows."""
    if not client:
        raise RuntimeError("No client available")
    resp = await client._make_request(
        "POST",
        "/trafficshaper/settings/search_queues",
        json=SEARCH_BODY,
    )
    return [normalize_queue(row) for row in resp.get("rows", [])]


async def search_shaper_rules(client: ClientT) -> list[FlatShaperRule]:
    """POST search_rules and normalize rows."""
    if not client:
        raise RuntimeError("No client available")
    resp = await client._make_request(
        "POST",
        "/trafficshaper/settings/search_rules",
        json=SEARCH_BODY,
    )
    return [normalize_rule(row) for row in resp.get("rows", [])]


async def fetch_shaper_statistics(client: ClientT) -> dict[str, Any]:
    """GET /trafficshaper/service/statistics."""
    if not client:
        raise RuntimeError("No client available")
    return await client._make_request("GET", "/trafficshaper/service/statistics")


def settings_from_ts(ts: dict[str, Any]) -> dict[str, Any]:
    """Build structured global settings summary from a settings/get ts tree."""
    pipes_section = _unwrap_ts_section(ts.get("pipes", {}))
    queues_section = _unwrap_ts_section(ts.get("queues", {}))
    rules_section = _unwrap_ts_section(ts.get("rules", {}))

    normalized_ts = {
        "pipes": pipes_section,
        "queues": queues_section,
        "rules": rules_section,
    }

    pipes = pipes_from_settings_get(normalized_ts)
    queues = queues_from_settings_get(normalized_ts)
    rules = rules_from_settings_get(normalized_ts)

    global_enabled = ts.get("enabled")
    if isinstance(global_enabled, dict):
        global_enabled = any(
            isinstance(meta, dict) and meta.get("selected")
            for meta in global_enabled.values()
        )
    elif global_enabled is not None:
        global_enabled = str(global_enabled).lower() in {"1", "true", "yes"}

    return {
        "global_enabled": global_enabled,
        "pipe_count": len(pipes),
        "queue_count": len(queues),
        "rule_count": len(rules),
        "pipes": pipes,
        "queues": queues,
        "rules": rules,
    }


class GetShaperSettingsTool:
    """Read global traffic shaper settings and resource counts."""

    name = "get_shaper_settings"
    description = (
        "Get global traffic shaper settings and normalized pipe/queue/rule summary"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {},
        "required": [],
    }

    def __init__(self, client: ClientT) -> None:
        """Initialize with an OPNsense API client."""
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Fetch settings/get and return normalized structured summary."""
        _ = params
        if not self.client:
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": "No client available"},
                summary="**Error:** No OPNsense client configured.",
            )

        try:
            raw = await fetch_shaper_settings_raw(self.client)
            ts = _ts_from_settings_response(raw)
            structured = settings_from_ts(ts)
        except Exception as exc:
            logger.exception("Failed to get shaper settings")
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": str(exc)},
                summary=f"**Error:** Failed to get shaper settings — {exc}",
            )

        counts = (
            f"{structured['pipe_count']} pipe(s), "
            f"{structured['queue_count']} queue(s), "
            f"{structured['rule_count']} rule(s)"
        )
        enabled = structured.get("global_enabled")
        enabled_line = (
            f"Global shaper: **{'enabled' if enabled else 'disabled' if enabled is False else 'unknown'}**"
            if enabled is not None
            else "Global shaper enabled flag not present in settings/get."
        )
        summary = f"**Traffic Shaper Settings** — {counts}\n\n{enabled_line}"

        return make_tool_response(
            status=TOOL_STATUS_SUCCESS,
            structured=structured,
            summary=summary,
        )


class SetShaperSettingsTool:
    """Write global traffic shaper settings subset."""

    name = "set_shaper_settings"
    description = "Update global traffic shaper settings (apply=true by default)"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {"apply": {"type": "boolean", "default": True}},
        "required": [],
    }

    def __init__(self, client: ClientT) -> None:
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        from opnsense_mcp.utils.shaper_mutation import (
            capture_pre_mutation_snapshot,
            finish_mutation,
        )

        params = params or {}
        apply = bool(params.get("apply", True))
        if not self.client:
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": "No client"},
                summary="**Error:** No client.",
            )
        snapshot_id = await capture_pre_mutation_snapshot(
            self.client, description="Before set shaper settings"
        )
        result = await self.client._make_request(
            "POST", "/trafficshaper/settings/set", json={}
        )
        return await finish_mutation(
            self.client,
            snapshot_id=snapshot_id,
            apply=apply,
            summary="**Updated global shaper settings.**",
            structured={"api_result": result},
        )
