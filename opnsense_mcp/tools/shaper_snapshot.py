"""Restore traffic shaper configuration from a session snapshot."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from opnsense_mcp.utils.shaper_mutation import (
    capture_pre_mutation_snapshot,
    finish_mutation,
    pipe_description_map,
    target_description_map,
)
from opnsense_mcp.utils.shaper_normalize import (
    normalize_pipe,
    normalize_queue,
    normalize_rule,
)
from opnsense_mcp.utils.shaper_serialize import (
    merge_flat_into_pipe,
    merge_flat_into_queue,
    merge_flat_into_rule,
)
from opnsense_mcp.utils.shaper_snapshot_store import get_snapshot
from opnsense_mcp.utils.shaper_types import (
    TOOL_STATUS_ERROR,
    TOOL_STATUS_SUCCESS,
    make_tool_response,
)
from opnsense_mcp.utils.shaper_write_helpers import shaper_api_result_ok

if TYPE_CHECKING:
    from opnsense_mcp.utils.api import OPNsenseClient
    from opnsense_mcp.utils.mock_api import MockOPNsenseClient

logger = logging.getLogger(__name__)

ClientT = "OPNsenseClient | MockOPNsenseClient | None"


class RestoreShaperSnapshotTool:
    """Replay a captured shaper snapshot via set endpoints."""

    name = "restore_shaper_snapshot"
    description = "Restore traffic shaper config from a prior snapshot_id"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "snapshot_id": {"type": "string"},
            "apply": {"type": "boolean", "default": True},
        },
        "required": ["snapshot_id"],
    }

    def __init__(self, client: ClientT) -> None:
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        params = params or {}
        snapshot_id = str(params.get("snapshot_id") or "").strip()
        apply = bool(params.get("apply", True))
        if not self.client or not snapshot_id:
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": "client and snapshot_id required"},
                summary="**Error:** Client and snapshot_id required.",
            )
        snap = get_snapshot(snapshot_id)
        if snap is None:
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": "snapshot not found", "snapshot_id": snapshot_id},
                summary=f"**Error:** Snapshot `{snapshot_id}` not found.",
            )
        pre_restore_id = await capture_pre_mutation_snapshot(
            self.client,
            description=f"Before restore snapshot {snapshot_id}",
        )
        pipe_rows = list(snap.get("search_pipes") or [])
        queue_rows = list(snap.get("search_queues") or [])
        rule_rows = list(snap.get("search_rules") or [])
        pmap = pipe_description_map(pipe_rows)
        tmap = target_description_map(queue_rows, pipe_rows)
        results: list[dict[str, Any]] = []
        resource_updates = 0

        def _require_ok(action: str, uid: str, resp: dict[str, Any]) -> None:
            ok, detail = shaper_api_result_ok(resp)
            if not ok:
                msg = f"{action} {uid} failed"
                if detail:
                    msg = f"{msg}: {detail}"
                raise RuntimeError(msg)

        try:
            for row in pipe_rows:
                uid = str(row.get("uuid") or "").strip()
                if not uid:
                    continue
                gui_resp = await self.client._make_request(
                    "GET", f"/trafficshaper/settings/get_pipe/{uid}"
                )
                flat = normalize_pipe({**row, "uuid": uid})
                payload = merge_flat_into_pipe(gui_resp.get("pipe") or {}, flat)
                resp = await self.client._make_request(
                    "POST",
                    f"/trafficshaper/settings/set_pipe/{uid}",
                    json=payload,
                )
                _require_ok("set_pipe", uid, resp)
                results.append({"action": "set_pipe", "uuid": uid, "result": resp})
                resource_updates += 1
            for row in queue_rows:
                uid = str(row.get("uuid") or "").strip()
                if not uid:
                    continue
                gui_resp = await self.client._make_request(
                    "GET", f"/trafficshaper/settings/get_queue/{uid}"
                )
                flat = normalize_queue({**row, "uuid": uid})
                payload = merge_flat_into_queue(
                    gui_resp.get("queue") or {}, flat, pmap
                )
                resp = await self.client._make_request(
                    "POST",
                    f"/trafficshaper/settings/set_queue/{uid}",
                    json=payload,
                )
                _require_ok("set_queue", uid, resp)
                results.append({"action": "set_queue", "uuid": uid, "result": resp})
                resource_updates += 1
            for row in rule_rows:
                uid = str(row.get("uuid") or "").strip()
                if not uid:
                    continue
                gui_resp = await self.client._make_request(
                    "GET", f"/trafficshaper/settings/get_rule/{uid}"
                )
                flat = normalize_rule({**row, "uuid": uid})
                payload = merge_flat_into_rule(
                    gui_resp.get("rule") or {}, flat, tmap
                )
                resp = await self.client._make_request(
                    "POST",
                    f"/trafficshaper/settings/set_rule/{uid}",
                    json=payload,
                )
                _require_ok("set_rule", uid, resp)
                results.append({"action": "set_rule", "uuid": uid, "result": resp})
                resource_updates += 1
            settings_raw = snap.get("settings_get")
            if isinstance(settings_raw, dict) and settings_raw:
                settings_resp = await self.client._make_request(
                    "POST",
                    "/trafficshaper/settings/set",
                    json=settings_raw,
                )
                _require_ok("set_settings", "global", settings_resp)
                results.append({"action": "set_settings", "result": settings_resp})
        except Exception as exc:
            logger.exception("Failed to restore snapshot")
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={
                    "error": str(exc),
                    "partial_results": results,
                    "pre_restore_snapshot_id": pre_restore_id,
                },
                summary=f"**Error:** Restore failed — {exc}",
                snapshot_id=pre_restore_id,
            )
        structured: dict[str, Any] = {
            "restored": resource_updates,
            "resource_updates": resource_updates,
            "steps": len(results),
            "results": results,
            "restored_from": snapshot_id,
            "pre_restore_snapshot_id": pre_restore_id,
        }
        return await finish_mutation(
            self.client,
            snapshot_id=pre_restore_id,
            apply=apply,
            summary=(
                f"**Restored snapshot** `{snapshot_id}` "
                f"({len(results)} resource update(s))."
            ),
            structured=structured,
            status=TOOL_STATUS_SUCCESS,
        )
