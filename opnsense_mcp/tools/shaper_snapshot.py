"""Restore traffic shaper configuration from a session snapshot."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from opnsense_mcp.utils.shaper_mutation import (
    apply_snapshot_restore,
    capture_pre_mutation_snapshot,
    finish_mutation,
)
from opnsense_mcp.utils.shaper_snapshot_store import get_snapshot
from opnsense_mcp.utils.shaper_types import (
    TOOL_STATUS_ERROR,
    TOOL_STATUS_SUCCESS,
    make_tool_response,
)

if TYPE_CHECKING:
    from opnsense_mcp.utils.api import OPNsenseClient
    from opnsense_mcp.utils.mock_api import MockOPNsenseClient

logger = logging.getLogger(__name__)

ClientT = "OPNsenseClient | MockOPNsenseClient | None"


class RestoreShaperSnapshotTool:
    """Replay a captured shaper snapshot via set endpoints."""

    name = "restore_shaper_snapshot"
    description = (
        "Restore traffic shaper config from a prior snapshot_id. "
        "Set remove_orphans=true to delete pipes/queues/rules not in the snapshot."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "snapshot_id": {"type": "string"},
            "apply": {"type": "boolean", "default": True},
            "remove_orphans": {
                "type": "boolean",
                "default": False,
                "description": "Delete live objects whose UUID is absent from the snapshot",
            },
        },
        "required": ["snapshot_id"],
    }

    def __init__(self, client: ClientT) -> None:
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        params = params or {}
        snapshot_id = str(params.get("snapshot_id") or "").strip()
        apply = bool(params.get("apply", True))
        remove_orphans = bool(params.get("remove_orphans", False))
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
        results: list[dict[str, Any]] = []
        try:
            results, resource_updates = await apply_snapshot_restore(
                self.client,
                snap,
                remove_orphans=remove_orphans,
            )
        except Exception as exc:
            logger.exception("Failed to restore snapshot")
            hint = (
                f" Roll back using snapshot `{pre_restore_id}`."
                if pre_restore_id
                else ""
            )
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={
                    "error": str(exc),
                    "partial_results": results,
                    "pre_restore_snapshot_id": pre_restore_id,
                },
                summary=f"**Error:** Restore failed — {exc}.{hint}",
                snapshot_id=pre_restore_id,
            )
        structured: dict[str, Any] = {
            "restored": resource_updates,
            "resource_updates": resource_updates,
            "steps": len(results),
            "results": results,
            "restored_from": snapshot_id,
            "pre_restore_snapshot_id": pre_restore_id,
            "remove_orphans": remove_orphans,
        }
        orphan_count = sum(1 for r in results if str(r.get("action", "")).startswith("del_"))
        summary = (
            f"**Restored snapshot** `{snapshot_id}` "
            f"({resource_updates} resource update(s)"
        )
        if remove_orphans and orphan_count:
            summary += f", {orphan_count} orphan(s) removed"
        summary += ")."
        return await finish_mutation(
            self.client,
            snapshot_id=pre_restore_id,
            apply=apply,
            summary=summary,
            structured=structured,
            status=TOOL_STATUS_SUCCESS,
        )
