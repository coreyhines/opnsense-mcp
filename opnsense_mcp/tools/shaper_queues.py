"""Traffic shaper queue read tools."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from opnsense_mcp.tools.shaper_settings import (
    SHAPER_LIST_SEARCH_SCHEMA,
    parse_shaper_search_options,
    search_shaper_pipes,
    search_shaper_queues,
)
from opnsense_mcp.utils.shaper_mutation import (
    capture_pre_mutation_snapshot,
    finish_mutation,
    load_pipe_queue_rule_rows,
    mutation_snapshot_for_tool,
    pipe_description_map,
)
from opnsense_mcp.utils.shaper_normalize import normalize_queue
from opnsense_mcp.utils.shaper_serialize import (
    merge_flat_into_queue_api_post,
    serialize_queue_api_post,
)
from opnsense_mcp.utils.shaper_types import (
    TOOL_STATUS_ERROR,
    TOOL_STATUS_SUCCESS,
    TOOL_STATUS_WARNING,
    FlatShaperQueue,
    make_tool_response,
)
from opnsense_mcp.utils.shaper_write_helpers import (
    detect_idempotent_set,
    issue_delete_confirm_token,
    validate_delete_confirm_token,
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
            **SHAPER_LIST_SEARCH_SCHEMA,
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
        row_count, fetch_all = parse_shaper_search_options(
            row_count=params.get("row_count"),
            fetch_all=params.get("fetch_all"),
        )

        try:
            queues = await search_shaper_queues(
                self.client,
                row_count=row_count,
                fetch_all=fetch_all,
            )
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


def _flat_queue_from_params(
    params: dict[str, Any], *, uuid: str = ""
) -> FlatShaperQueue:
    flat: FlatShaperQueue = {
        "description": str(params.get("description") or ""),
        "enabled": bool(params.get("enabled", True)),
        "pipe_uuid": str(params.get("pipe_uuid") or ""),
        "weight": int(params.get("weight") or 100),
        "mask": str(params.get("mask") or "none"),
        "codel_enable": bool(params.get("codel_enable", False)),
        "codel_ecn_enable": bool(params.get("codel_ecn_enable", False)),
        "pie_enable": bool(params.get("pie_enable", False)),
    }
    if uuid:
        flat["uuid"] = uuid
    return flat


class AddShaperQueueTool:
    name = "add_shaper_queue"
    description = "Create a traffic shaper queue"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "description": {"type": "string"},
            "pipe_uuid": {"type": "string"},
            "weight": {"type": "integer", "default": 100},
            "apply": {"type": "boolean", "default": True},
            "mutation_snapshot_id": {"type": "string"},
            "capture_snapshot": {"type": "boolean", "default": True},
        },
        "required": ["description", "pipe_uuid"],
    }

    def __init__(self, client: ClientT) -> None:
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        params = params or {}
        if not self.client:
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": "No client"},
                summary="**Error:** No client.",
            )
        apply = bool(params.get("apply", True))
        flat = _flat_queue_from_params(params)
        pipe_uuid = flat.get("pipe_uuid", "")
        if not pipe_uuid:
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": "pipe_uuid required"},
                summary="**Error:** `pipe_uuid` is required.",
            )
        try:
            pipe_rows, _, _ = await load_pipe_queue_rule_rows(self.client)
            pmap = pipe_description_map(pipe_rows)
            if pipe_uuid not in pmap:
                return make_tool_response(
                    status=TOOL_STATUS_ERROR,
                    structured={"error": "pipe_uuid not found", "pipe_uuid": pipe_uuid},
                    summary=f"**Error:** Pipe `{pipe_uuid}` not found.",
                )
            snapshot_id = await mutation_snapshot_for_tool(
                self.client,
                params,
                description=f"Before add queue {flat.get('description')}",
            )
            payload = serialize_queue_api_post(flat, pmap)
            result = await self.client._make_request(
                "POST", "/trafficshaper/settings/add_queue/", json=payload
            )
            queue_uuid = result.get("id") or result.get("uuid", "")
            flat["uuid"] = str(queue_uuid)
        except Exception as exc:
            logger.exception("Failed to add shaper queue")
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": str(exc)},
                summary=f"**Error:** Failed to add queue — {exc}",
            )
        return await finish_mutation(
            self.client,
            snapshot_id=snapshot_id,
            apply=apply,
            summary=f"**Added queue** `{flat.get('description')}` (UUID `{queue_uuid}`).",
            structured={"queue": flat, "api_result": result},
        )


class SetShaperQueueTool:
    name = "set_shaper_queue"
    description = "Update a traffic shaper queue"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string"},
            "description": {"type": "string"},
            "pipe_uuid": {"type": "string"},
            "weight": {"type": "integer"},
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
        uuid = str(params.get("uuid") or "").strip()
        apply = bool(params.get("apply", True))
        if not self.client or not uuid:
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": "uuid required"},
                summary="**Error:** uuid required.",
            )
        try:
            gui_resp = await self.client._make_request(
                "GET", f"/trafficshaper/settings/get_queue/{uuid}"
            )
            existing_gui = gui_resp.get("queue") or {}
            existing = normalize_queue({**existing_gui, "uuid": uuid})
            proposed = dict(existing)
            for key in ("description", "pipe_uuid", "weight", "enabled"):
                if params.get(key) is not None:
                    proposed[key] = params[key]  # type: ignore[index]
            if detect_idempotent_set(existing, proposed):
                return make_tool_response(
                    status=TOOL_STATUS_WARNING,
                    structured={"queue": existing, "idempotent": True},
                    summary="**Warning:** Queue unchanged (identical set request).",
                    hints=["No changes applied; payload matches existing config."],
                )
            pipe_rows, _, _ = await load_pipe_queue_rule_rows(self.client)
            if proposed.get("pipe_uuid") and proposed[
                "pipe_uuid"
            ] not in pipe_description_map(pipe_rows):
                return make_tool_response(
                    status=TOOL_STATUS_ERROR,
                    structured={
                        "error": "pipe_uuid not found",
                        "pipe_uuid": proposed["pipe_uuid"],
                    },
                    summary=f"**Error:** Pipe `{proposed['pipe_uuid']}` not found.",
                )
            snapshot_id = await mutation_snapshot_for_tool(
                self.client,
                params,
                description=f"Before set queue {uuid}",
            )
            payload = merge_flat_into_queue_api_post(
                existing_gui, proposed, pipe_description_map(pipe_rows)
            )
            result = await self.client._make_request(
                "POST", f"/trafficshaper/settings/set_queue/{uuid}", json=payload
            )
        except Exception as exc:
            logger.exception("Failed to set shaper queue")
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": str(exc)},
                summary=f"**Error:** Failed to set queue — {exc}",
            )
        return await finish_mutation(
            self.client,
            snapshot_id=snapshot_id,
            apply=apply,
            summary=f"**Updated queue** `{uuid}`.",
            structured={"queue": proposed, "api_result": result},
        )


class ToggleShaperQueueTool:
    name = "toggle_shaper_queue"
    description = "Toggle queue enabled state"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {"uuid": {"type": "string"}, "apply": {"type": "boolean"}},
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
                self.client, description=f"Before toggle queue {uuid}"
            )
            result = await self.client._make_request(
                "POST", f"/trafficshaper/settings/toggle_queue/{uuid}"
            )
        except Exception as exc:
            logger.exception("Failed to toggle shaper queue")
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": str(exc)},
                summary=f"**Error:** Failed to toggle queue — {exc}",
            )
        return await finish_mutation(
            self.client,
            snapshot_id=snapshot_id,
            apply=apply,
            summary=f"**Toggled queue** `{uuid}` (enabled={result.get('enabled')}).",
            structured={"uuid": uuid, "api_result": result},
        )


class DeleteShaperQueueTool:
    name = "delete_shaper_queue"
    description = "Delete a queue (confirm token required)"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {"uuid": {"type": "string"}, "confirm": {"type": "string"}},
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
        if not validate_delete_confirm_token("queue", uuid, str(confirm or "")):
            token_info = issue_delete_confirm_token("queue", uuid)
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
                self.client, description=f"Before delete queue {uuid}"
            )
            result = await self.client._make_request(
                "POST", f"/trafficshaper/settings/del_queue/{uuid}"
            )
        except Exception as exc:
            logger.exception("Failed to delete shaper queue")
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": str(exc)},
                summary=f"**Error:** Failed to delete queue — {exc}",
            )
        return await finish_mutation(
            self.client,
            snapshot_id=snapshot_id,
            apply=apply,
            summary=f"**Deleted queue** `{uuid}`.",
            structured={"uuid": uuid, "api_result": result},
        )
