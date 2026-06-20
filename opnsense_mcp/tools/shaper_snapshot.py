"""Restore traffic shaper configuration from a session snapshot."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from opnsense_mcp.utils.shaper_mutation import (
    capture_pre_mutation_snapshot,
    reconfigure_shaper,
)
from opnsense_mcp.utils.shaper_snapshot_store import build_restore_plan, get_snapshot
from opnsense_mcp.utils.shaper_types import TOOL_STATUS_ERROR, make_tool_response

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
        plan = build_restore_plan(snap)
        results: list[dict[str, Any]] = []
        try:
            for pipe in plan.get("pipes", []):
                uid = pipe["uuid"]
                resp = await self.client._make_request(
                    "POST",
                    f"/trafficshaper/settings/set_pipe/{uid}",
                    json=pipe.get("flat_data", {}),
                )
                results.append({"action": "set_pipe", "uuid": uid, "result": resp})
            for queue in plan.get("queues", []):
                uid = queue["uuid"]
                resp = await self.client._make_request(
                    "POST",
                    f"/trafficshaper/settings/set_queue/{uid}",
                    json=queue.get("flat_data", {}),
                )
                results.append({"action": "set_queue", "uuid": uid, "result": resp})
            for rule in plan.get("rules", []):
                uid = rule["uuid"]
                resp = await self.client._make_request(
                    "POST",
                    f"/trafficshaper/settings/set_rule/{uid}",
                    json=rule.get("flat_data", {}),
                )
                results.append({"action": "set_rule", "uuid": uid, "result": resp})
            await self.client._make_request(
                "POST", "/trafficshaper/settings/set", json={}
            )
            reconfigure_result = (
                await reconfigure_shaper(self.client) if apply else None
            )
        except Exception as exc:
            logger.exception("Failed to restore snapshot")
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": str(exc), "partial_results": results},
                summary=f"**Error:** Restore failed — {exc}",
                snapshot_id=snapshot_id,
            )
        structured = {
            "restored": len(results),
            "results": results,
            **(
                {"reconfigure_result": reconfigure_result}
                if apply
                else {"applied": False}
            ),
        }
        return make_tool_response(
            status="success",
            structured=structured,
            summary=f"**Restored snapshot** `{snapshot_id}` ({len(results)} resource updates).",
            snapshot_id=snapshot_id,
        )
