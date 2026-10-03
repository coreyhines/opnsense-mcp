"""Restore traffic shaper configuration from a session snapshot."""

from __future__ import annotations

import logging
import secrets
import time
from typing import TYPE_CHECKING, Any

from opnsense_mcp.utils.shaper_mutation import (
    apply_snapshot_restore,
    capture_pre_mutation_snapshot,
    finish_mutation,
    plan_orphan_removal,
)
from opnsense_mcp.utils.shaper_snapshot_store import get_snapshot
from opnsense_mcp.utils.shaper_types import (
    TOOL_STATUS_CONFIRMATION_REQUIRED,
    TOOL_STATUS_ERROR,
    TOOL_STATUS_SUCCESS,
    make_tool_response,
)

if TYPE_CHECKING:
    from opnsense_mcp.utils.api import OPNsenseClient
    from opnsense_mcp.utils.mock_api import MockOPNsenseClient

logger = logging.getLogger(__name__)

ClientT = "OPNsenseClient | MockOPNsenseClient | None"

_ORPHAN_TOKEN_TTL_SECONDS = 300

# token -> {"snapshot_id", "targets", "expires"}. A token confirms one
# snapshot and one exact deletion set; it is consumed on first use.
_orphan_tokens: dict[str, dict[str, Any]] = {}


def _deletion_targets(orphans: dict[str, list[str]]) -> frozenset[tuple[str, str]]:
    """Flatten a deletion plan into ``(kind, uuid)`` pairs for comparison."""
    return frozenset(
        (kind, uid) for kind, uuids in orphans.items() for uid in uuids or []
    )


def _issue_orphan_token(snapshot_id: str, targets: frozenset[tuple[str, str]]) -> str:
    """Issue a one-time token bound to *snapshot_id* and *targets*."""
    now = time.time()
    for key in [k for k, v in _orphan_tokens.items() if v["expires"] <= now]:
        del _orphan_tokens[key]
    token = secrets.token_hex(8)
    _orphan_tokens[token] = {
        "snapshot_id": snapshot_id,
        "targets": targets,
        "expires": now + _ORPHAN_TOKEN_TTL_SECONDS,
    }
    return token


def _check_orphan_token(
    token: str, snapshot_id: str, targets: frozenset[tuple[str, str]]
) -> str:
    """Consume *token*; return ``""`` when it confirms this exact deletion.

    Otherwise return why not: ``"invalid"`` for an unknown, used or expired
    token, ``"changed"`` when it was issued for another snapshot or another
    set of uuids than the one live now.
    """
    stored = _orphan_tokens.pop(token, None)
    if stored is None or stored["expires"] <= time.time():
        return "invalid"
    if stored["snapshot_id"] != snapshot_id or stored["targets"] != targets:
        return "changed"
    return ""


class RestoreShaperSnapshotTool:
    """Replay a captured shaper snapshot, recreating objects deleted since."""

    name = "restore_shaper_snapshot"
    description = (
        "Restore traffic shaper config from a prior snapshot_id, recreating "
        "pipes/queues/rules deleted since. Set remove_orphans=true to also "
        "delete pipes/queues/rules not in the snapshot; that returns a "
        "deletion plan and a confirm token first."
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
            "confirm": {
                "type": "string",
                "description": (
                    "Token from a prior remove_orphans call; confirms that "
                    "snapshot and that exact deletion set"
                ),
            },
        },
        "required": ["snapshot_id"],
    }

    def __init__(self, client: ClientT) -> None:
        self.client = client

    async def _confirm_orphans(
        self,
        snapshot_id: str,
        confirm: str,
    ) -> tuple[dict[str, list[str]] | None, dict[str, Any] | None]:
        """Return ``(orphans, None)`` to proceed, or ``(None, response)`` to stop.

        One boolean used to authorize deleting every live object missing from
        the snapshot, with no preview. Deletes now need a token bound to the
        snapshot and the exact uuid set, and abort if that set has changed.
        """
        snap = get_snapshot(snapshot_id) or {}
        try:
            orphans = await plan_orphan_removal(self.client, snap)
        except Exception as exc:
            logger.exception("Failed to plan orphan removal")
            return None, make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": str(exc), "applied": False},
                summary=f"**Error:** Could not read live shaper objects — {exc}.",
            )
        targets = _deletion_targets(orphans)
        if not targets:
            return orphans, None
        if not confirm:
            token = _issue_orphan_token(snapshot_id, targets)
            return None, make_tool_response(
                status=TOOL_STATUS_CONFIRMATION_REQUIRED,
                structured={
                    "snapshot_id": snapshot_id,
                    "deletion_plan": orphans,
                    "delete_count": len(targets),
                    "confirm_token": token,
                    "expires_in_s": _ORPHAN_TOKEN_TTL_SECONDS,
                    "applied": False,
                },
                summary=(
                    f"**Confirmation required:** restoring `{snapshot_id}` with "
                    f"remove_orphans deletes {len(targets)} object(s) listed in "
                    f"`deletion_plan`. Call again with `confirm` = `{token}`."
                ),
            )
        reason = _check_orphan_token(confirm, snapshot_id, targets)
        if not reason:
            return orphans, None
        error = (
            "deletion set changed since confirmation"
            if reason == "changed"
            else "invalid or expired confirm token"
        )
        return None, make_tool_response(
            status=TOOL_STATUS_ERROR,
            structured={
                "error": error,
                "deletion_set_changed": reason == "changed",
                "deletion_plan": orphans,
                "applied": False,
            },
            summary=(
                f"**Error:** {error}; nothing was changed. Call again without "
                "`confirm` for a fresh deletion plan."
            ),
        )

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
        orphans: dict[str, list[str]] | None = None
        if remove_orphans:
            orphans, stop = await self._confirm_orphans(
                snapshot_id, str(params.get("confirm") or "").strip()
            )
            if stop is not None:
                return stop
        pre_restore_id = await capture_pre_mutation_snapshot(
            self.client,
            description=f"Before restore snapshot {snapshot_id}",
        )
        results: list[dict[str, Any]] = []
        try:
            results, resource_updates = await apply_snapshot_restore(
                self.client,
                snap,
                orphans=orphans,
                results=results,
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
        recreated = [
            {"resource": r["action"][4:], "uuid": r["uuid"], "snapshot_uuid": su}
            for r in results
            if (su := r.get("snapshot_uuid"))
        ]
        orphan_count = sum(
            1 for r in results if str(r.get("action", "")).startswith("del_")
        )
        structured: dict[str, Any] = {
            "restored": resource_updates,
            "resource_updates": resource_updates,
            "recreated": recreated,
            "steps": len(results),
            "results": results,
            "restored_from": snapshot_id,
            "pre_restore_snapshot_id": pre_restore_id,
            "remove_orphans": remove_orphans,
            "orphans_removed": orphan_count,
        }
        summary = (
            f"**Restored snapshot** `{snapshot_id}` "
            f"({resource_updates} resource update(s)"
        )
        if recreated:
            summary += f", {len(recreated)} recreated with new UUID(s)"
        if orphan_count:
            summary += f", {orphan_count} orphan(s) removed"
        summary += ")."
        # A delete leaves its dummynet pipe running after reconfigure, so a
        # restore that removed anything is checked against the kernel before
        # it reports applied, the same gate the single deletes use.
        return await finish_mutation(
            self.client,
            snapshot_id=pre_restore_id,
            apply=apply,
            summary=summary,
            structured=structured,
            status=TOOL_STATUS_SUCCESS,
            verify_kernel=orphan_count > 0,
        )
