"""Traffic shaper pipe read tools."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from opnsense_mcp.tools.shaper_settings import search_shaper_pipes
from opnsense_mcp.utils.shaper_mutation import (
    capture_pre_mutation_snapshot,
    finish_mutation,
    mutation_snapshot_for_tool,
)
from opnsense_mcp.utils.shaper_normalize import normalize_pipe
from opnsense_mcp.utils.shaper_serialize import merge_flat_into_pipe, serialize_pipe
from opnsense_mcp.utils.shaper_types import (
    TOOL_STATUS_ERROR,
    TOOL_STATUS_SUCCESS,
    TOOL_STATUS_WARNING,
    FlatShaperPipe,
    make_tool_response,
)
from opnsense_mcp.utils.shaper_write_helpers import (
    detect_idempotent_set,
    issue_delete_confirm_token,
    validate_delete_confirm_token,
    validate_pipe_bandwidth,
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


def _flat_pipe_from_params(params: dict[str, Any], *, uuid: str = "") -> FlatShaperPipe:
    """Build a flat pipe record from MCP tool parameters."""
    flat: FlatShaperPipe = {
        "description": str(params.get("description") or ""),
        "enabled": bool(params.get("enabled", True)),
        "bandwidth": int(params.get("bandwidth") or 0),
        "bandwidth_metric": str(params.get("bandwidth_metric") or "Mbit"),
        "scheduler": str(params.get("scheduler") or "fq_codel"),
        "mask": str(params.get("mask") or "none"),
        "codel_enable": bool(params.get("codel_enable", False)),
        "codel_ecn_enable": bool(params.get("codel_ecn_enable", True)),
        "pie_enable": bool(params.get("pie_enable", False)),
    }
    if uuid:
        flat["uuid"] = uuid
    for key in (
        "codel_target_ms",
        "codel_interval_ms",
        "fqcodel_quantum",
        "fqcodel_limit",
        "fqcodel_flows",
    ):
        if params.get(key) is not None:
            flat[key] = params[key]  # type: ignore[literal-required]
    return flat


class AddShaperPipeTool:
    """Create a traffic shaper pipe."""

    name = "add_shaper_pipe"
    description = "Create a traffic shaper pipe (apply=true by default)"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "description": {"type": "string"},
            "bandwidth": {"type": "integer"},
            "bandwidth_metric": {"type": "string", "default": "Mbit"},
            "scheduler": {"type": "string", "default": "fq_codel"},
            "enabled": {"type": "boolean", "default": True},
            "apply": {"type": "boolean", "default": True},
            "mutation_snapshot_id": {"type": "string"},
            "capture_snapshot": {"type": "boolean", "default": True},
        },
        "required": ["description", "bandwidth"],
    }

    def __init__(self, client: ClientT) -> None:
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        params = params or {}
        if not self.client:
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": "No client available"},
                summary="**Error:** No OPNsense client configured.",
            )
        apply = bool(params.get("apply", True))
        flat = _flat_pipe_from_params(params)
        hints = validate_pipe_bandwidth(
            flat.get("bandwidth", 0),
            float(params.get("line_rate_mbit") or 10_000),
            isp_rate_mbit=params.get("isp_rate_mbit"),
        )
        try:
            snapshot_id = await mutation_snapshot_for_tool(
                self.client,
                params,
                description=f"Before add pipe {flat.get('description')}",
            )
            payload = serialize_pipe(flat)
            result = await self.client._make_request(
                "POST",
                "/trafficshaper/settings/add_pipe/",
                json=payload,
            )
            pipe_uuid = result.get("id") or result.get("uuid", "")
            flat["uuid"] = str(pipe_uuid)
        except Exception as exc:
            logger.exception("Failed to add shaper pipe")
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": str(exc)},
                summary=f"**Error:** Failed to add pipe — {exc}",
            )
        summary = f"**Added pipe** `{flat.get('description')}` (UUID `{pipe_uuid}`)."
        return await finish_mutation(
            self.client,
            snapshot_id=snapshot_id,
            apply=apply,
            summary=summary,
            structured={"pipe": flat, "api_result": result},
            hints=hints,
        )


class SetShaperPipeTool:
    """Update a traffic shaper pipe."""

    name = "set_shaper_pipe"
    description = "Update a traffic shaper pipe by uuid (apply=true by default)"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string"},
            "description": {"type": "string"},
            "bandwidth": {"type": "integer"},
            "bandwidth_metric": {"type": "string"},
            "scheduler": {"type": "string"},
            "enabled": {"type": "boolean"},
            "apply": {"type": "boolean", "default": True},
            "mutation_snapshot_id": {"type": "string"},
            "capture_snapshot": {"type": "boolean", "default": True},
        },
        "required": ["uuid"],
    }

    def __init__(self, client: ClientT) -> None:
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        params = params or {}
        if not self.client:
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": "No client available"},
                summary="**Error:** No OPNsense client configured.",
            )
        uuid = str(params.get("uuid") or "").strip()
        if not uuid:
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": "uuid required"},
                summary="**Error:** `uuid` is required.",
            )
        apply = bool(params.get("apply", True))
        try:
            existing_resp = await self.client._make_request(
                "GET",
                f"/trafficshaper/settings/get_pipe/{uuid}",
            )
            existing_gui = existing_resp.get("pipe") or {}
            existing_flat = normalize_pipe({**existing_gui, "uuid": uuid})
            proposed = dict(existing_flat)
            for key in (
                "description",
                "bandwidth",
                "bandwidth_metric",
                "scheduler",
                "enabled",
                "mask",
                "codel_enable",
                "codel_ecn_enable",
                "pie_enable",
            ):
                if key in params and params[key] is not None:
                    proposed[key] = params[key]  # type: ignore[index]
            if detect_idempotent_set(existing_flat, proposed):
                return make_tool_response(
                    status=TOOL_STATUS_WARNING,
                    structured={"pipe": existing_flat, "idempotent": True},
                    summary="**Warning:** Pipe unchanged (identical set request).",
                    hints=["No changes applied; payload matches existing config."],
                )
            snapshot_id = await mutation_snapshot_for_tool(
                self.client,
                params,
                description=f"Before set pipe {uuid}",
            )
            payload = merge_flat_into_pipe(existing_gui, proposed)  # type: ignore[arg-type]
            result = await self.client._make_request(
                "POST",
                f"/trafficshaper/settings/set_pipe/{uuid}",
                json=payload,
            )
        except Exception as exc:
            logger.exception("Failed to set shaper pipe")
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": str(exc)},
                summary=f"**Error:** Failed to set pipe — {exc}",
            )
        return await finish_mutation(
            self.client,
            snapshot_id=snapshot_id,
            apply=apply,
            summary=f"**Updated pipe** `{proposed.get('description')}` (`{uuid}`).",
            structured={"pipe": proposed, "api_result": result},
        )


class ToggleShaperPipeTool:
    """Enable or disable a traffic shaper pipe."""

    name = "toggle_shaper_pipe"
    description = "Toggle a traffic shaper pipe enabled state"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string"},
            "apply": {"type": "boolean", "default": True},
        },
        "required": ["uuid"],
    }

    def __init__(self, client: ClientT) -> None:
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        params = params or {}
        uuid = str(params.get("uuid") or "").strip()
        apply = bool(params.get("apply", True))
        if not self.client or not uuid:
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": "client and uuid required"},
                summary="**Error:** Client and `uuid` required.",
            )
        try:
            snapshot_id = await capture_pre_mutation_snapshot(
                self.client, description=f"Before toggle pipe {uuid}"
            )
            result = await self.client._make_request(
                "POST",
                f"/trafficshaper/settings/toggle_pipe/{uuid}",
            )
        except Exception as exc:
            logger.exception("Failed to toggle shaper pipe")
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": str(exc)},
                summary=f"**Error:** Failed to toggle pipe — {exc}",
            )
        return await finish_mutation(
            self.client,
            snapshot_id=snapshot_id,
            apply=apply,
            summary=f"**Toggled pipe** `{uuid}` (enabled={result.get('enabled')}).",
            structured={"uuid": uuid, "api_result": result},
        )


class DeleteShaperPipeTool:
    """Delete a traffic shaper pipe (confirmation token required)."""

    name = "delete_shaper_pipe"
    description = "Delete a traffic shaper pipe; requires confirm token from prior call"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string"},
            "confirm": {"type": "string"},
            "apply": {"type": "boolean", "default": True},
        },
        "required": ["uuid"],
    }

    def __init__(self, client: ClientT) -> None:
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        params = params or {}
        uuid = str(params.get("uuid") or "").strip()
        confirm = params.get("confirm")
        apply = bool(params.get("apply", True))
        if not self.client or not uuid:
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": "client and uuid required"},
                summary="**Error:** Client and `uuid` required.",
            )
        if not validate_delete_confirm_token("pipe", uuid, str(confirm or "")):
            token_info = issue_delete_confirm_token("pipe", uuid)
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={
                    "error": "confirmation_required",
                    "confirm_token": token_info["token"],
                },
                summary=f"**Confirmation required.** {token_info['message']}",
            )
        try:
            snapshot_id = await capture_pre_mutation_snapshot(
                self.client, description=f"Before delete pipe {uuid}"
            )
            result = await self.client._make_request(
                "POST",
                f"/trafficshaper/settings/del_pipe/{uuid}",
            )
        except Exception as exc:
            logger.exception("Failed to delete shaper pipe")
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": str(exc)},
                summary=f"**Error:** Failed to delete pipe — {exc}",
            )
        return await finish_mutation(
            self.client,
            snapshot_id=snapshot_id,
            apply=apply,
            summary=f"**Deleted pipe** `{uuid}`.",
            structured={"uuid": uuid, "api_result": result},
        )
