"""Traffic shaper preset workflows."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from opnsense_mcp.tools.shaper_pipes import AddShaperPipeTool, SetShaperPipeTool
from opnsense_mcp.tools.shaper_queues import AddShaperQueueTool, SetShaperQueueTool
from opnsense_mcp.tools.shaper_rules import AddShaperRuleTool, SetShaperRuleTool
from opnsense_mcp.tools.shaper_settings import (
    search_shaper_pipes,
    search_shaper_queues,
    search_shaper_rules,
)
from opnsense_mcp.utils.shaper_mutation import (
    capture_pre_mutation_snapshot,
    finish_mutation,
)
from opnsense_mcp.utils.shaper_types import (
    TOOL_STATUS_ERROR,
    TOOL_STATUS_SUCCESS,
    TOOL_STATUS_WARNING,
    make_tool_response,
)
from opnsense_mcp.utils.shaper_write_helpers import bufferbloat_shaped_rate_mbit

if TYPE_CHECKING:
    from opnsense_mcp.utils.api import OPNsenseClient
    from opnsense_mcp.utils.mock_api import MockOPNsenseClient

logger = logging.getLogger(__name__)

ClientT = "OPNsenseClient | MockOPNsenseClient | None"

DL_PIPE_DESC = "Download pipe"
UL_PIPE_DESC = "Upload pipe"
DL_QUEUE_DESC = "Download queue"
UL_QUEUE_DESC = "Upload queue"

PRESET_RULES: tuple[dict[str, str], ...] = (
    {
        "description": "Download Rule",
        "interface": "wan",
        "direction": "in",
        "proto": "ip",
    },
    {
        "description": "Download Rule IPv6",
        "interface": "wan",
        "direction": "in",
        "proto": "ip6",
    },
    {
        "description": "Upload Rule",
        "interface": "wan",
        "direction": "out",
        "proto": "ip",
    },
    {
        "description": "Upload Rule IPv6",
        "interface": "wan",
        "direction": "out",
        "proto": "ip6",
    },
)


def _find_by_description(
    items: list[dict[str, Any]], description: str
) -> dict[str, Any] | None:
    needle = description.lower()
    for item in items:
        if (item.get("description") or "").lower() == needle:
            return item
    return None


def _require_tool_success(resp: dict[str, Any], step: str) -> None:
    status = resp.get("status")
    if status == TOOL_STATUS_ERROR:
        err = resp.get("structured", {}).get("error", "unknown error")
        msg = f"{step} failed: {err}"
        raise RuntimeError(msg)
    if status == TOOL_STATUS_WARNING and resp.get("structured", {}).get("idempotent"):
        return


class ApplyShaperPresetTool:
    """Apply a named shaper preset (bufferbloat_wan)."""

    name = "apply_shaper_preset"
    description = (
        "Apply bufferbloat_wan preset: FQ-CoDel pipes at 85% ISP rates, "
        "queues, dual-stack WAN rules"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "preset": {"type": "string", "default": "bufferbloat_wan"},
            "download_mbit": {"type": "number"},
            "upload_mbit": {"type": "number"},
            "wan_interface": {"type": "string", "default": "wan"},
            "apply": {"type": "boolean", "default": True},
        },
        "required": ["download_mbit", "upload_mbit"],
    }

    def __init__(self, client: ClientT) -> None:
        self.client = client

    async def _ensure_pipe(
        self,
        *,
        description: str,
        bandwidth: int,
        pipe_add: AddShaperPipeTool,
        pipe_set: SetShaperPipeTool,
        pipes: list[dict[str, Any]],
        actions: list[str],
        mutation_snapshot_id: str,
    ) -> dict[str, Any]:
        existing = _find_by_description(pipes, description)
        pipe_params = {
            "bandwidth": bandwidth,
            "scheduler": "fq_codel",
            "codel_ecn_enable": True,
            "apply": False,
            "mutation_snapshot_id": mutation_snapshot_id,
        }
        if existing and existing.get("uuid"):
            resp = await pipe_set.execute(
                {"uuid": existing["uuid"], "description": description, **pipe_params}
            )
            _require_tool_success(resp, f"set pipe {description}")
            if resp.get("status") != TOOL_STATUS_WARNING:
                actions.append(f"set pipe {description}")
            refreshed = _find_by_description(
                await search_shaper_pipes(self.client), description
            )
            return refreshed or existing
        resp = await pipe_add.execute({"description": description, **pipe_params})
        _require_tool_success(resp, f"add pipe {description}")
        actions.append(f"add pipe {description}")
        pipe = resp.get("structured", {}).get("pipe") or {}
        if pipe.get("uuid"):
            return pipe
        return (
            _find_by_description(await search_shaper_pipes(self.client), description)
            or {}
        )

    async def _ensure_queue(
        self,
        *,
        description: str,
        pipe_uuid: str,
        queue_add: AddShaperQueueTool,
        queue_set: SetShaperQueueTool,
        queues: list[dict[str, Any]],
        actions: list[str],
        mutation_snapshot_id: str,
    ) -> dict[str, Any]:
        existing = _find_by_description(queues, description)
        params = {
            "description": description,
            "pipe_uuid": pipe_uuid,
            "weight": 100,
            "apply": False,
            "mutation_snapshot_id": mutation_snapshot_id,
        }
        if existing and existing.get("uuid"):
            resp = await queue_set.execute({"uuid": existing["uuid"], **params})
            _require_tool_success(resp, f"set queue {description}")
            if resp.get("status") != TOOL_STATUS_WARNING:
                actions.append(f"set queue {description}")
            refreshed = _find_by_description(
                await search_shaper_queues(self.client), description
            )
            return refreshed or existing
        resp = await queue_add.execute(params)
        _require_tool_success(resp, f"add queue {description}")
        actions.append(f"add queue {description}")
        queue = resp.get("structured", {}).get("queue") or {}
        if queue.get("uuid"):
            return queue
        return (
            _find_by_description(await search_shaper_queues(self.client), description)
            or {}
        )

    async def _ensure_rule(
        self,
        *,
        spec: dict[str, str],
        target_uuid: str,
        wan: str,
        rule_add: AddShaperRuleTool,
        rule_set: SetShaperRuleTool,
        rules: list[dict[str, Any]],
        actions: list[str],
        mutation_snapshot_id: str,
    ) -> None:
        desc = spec["description"]
        existing = _find_by_description(rules, desc)
        params = {
            "description": desc,
            "interface": wan,
            "direction": spec["direction"],
            "proto": spec["proto"],
            "target_uuid": target_uuid,
            "apply": False,
            "mutation_snapshot_id": mutation_snapshot_id,
        }
        if existing and existing.get("uuid"):
            resp = await rule_set.execute({"uuid": existing["uuid"], **params})
            _require_tool_success(resp, f"set rule {desc}")
            if resp.get("status") != TOOL_STATUS_WARNING:
                actions.append(f"set rule {desc}")
            return
        resp = await rule_add.execute(params)
        _require_tool_success(resp, f"add rule {desc}")
        actions.append(f"add rule {desc}")

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        params = params or {}
        preset = str(params.get("preset") or "bufferbloat_wan")
        if preset != "bufferbloat_wan":
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": f"unknown preset {preset}"},
                summary=f"**Error:** Unknown preset `{preset}`.",
            )
        if not self.client:
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": "No client"},
                summary="**Error:** No client.",
            )
        try:
            dl_rate = float(params["download_mbit"])
            ul_rate = float(params["upload_mbit"])
        except (KeyError, TypeError, ValueError):
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": "download_mbit and upload_mbit required"},
                summary="**Error:** Valid `download_mbit` and `upload_mbit` required.",
            )
        if dl_rate <= 0 or ul_rate <= 0:
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": "rates must be positive"},
                summary="**Error:** Bandwidth rates must be positive.",
            )
        dl = bufferbloat_shaped_rate_mbit(dl_rate)
        ul = bufferbloat_shaped_rate_mbit(ul_rate)
        apply = bool(params.get("apply", True))
        wan = str(params.get("wan_interface") or "wan")
        snapshot_id = await capture_pre_mutation_snapshot(
            self.client, description="Before bufferbloat_wan preset"
        )
        actions: list[str] = []
        try:
            pipe_add = AddShaperPipeTool(self.client)
            pipe_set = SetShaperPipeTool(self.client)
            queue_add = AddShaperQueueTool(self.client)
            queue_set = SetShaperQueueTool(self.client)
            rule_add = AddShaperRuleTool(self.client)
            rule_set = SetShaperRuleTool(self.client)

            pipes = await search_shaper_pipes(self.client)
            dl_pipe = await self._ensure_pipe(
                description=DL_PIPE_DESC,
                bandwidth=dl,
                pipe_add=pipe_add,
                pipe_set=pipe_set,
                pipes=pipes,
                actions=actions,
                mutation_snapshot_id=snapshot_id,
            )
            pipes = await search_shaper_pipes(self.client)
            ul_pipe = await self._ensure_pipe(
                description=UL_PIPE_DESC,
                bandwidth=ul,
                pipe_add=pipe_add,
                pipe_set=pipe_set,
                pipes=pipes,
                actions=actions,
                mutation_snapshot_id=snapshot_id,
            )
            dl_uuid = str(dl_pipe.get("uuid") or "")
            if not dl_uuid:
                dl_ref = _find_by_description(
                    await search_shaper_pipes(self.client), DL_PIPE_DESC
                )
                dl_uuid = str((dl_ref or {}).get("uuid", ""))
            ul_uuid = str(ul_pipe.get("uuid") or "")
            if not ul_uuid:
                ul_ref = _find_by_description(
                    await search_shaper_pipes(self.client), UL_PIPE_DESC
                )
                ul_uuid = str((ul_ref or {}).get("uuid", ""))

            queues = await search_shaper_queues(self.client)
            dl_queue = await self._ensure_queue(
                description=DL_QUEUE_DESC,
                pipe_uuid=dl_uuid,
                queue_add=queue_add,
                queue_set=queue_set,
                queues=queues,
                actions=actions,
                mutation_snapshot_id=snapshot_id,
            )
            queues = await search_shaper_queues(self.client)
            ul_queue = await self._ensure_queue(
                description=UL_QUEUE_DESC,
                pipe_uuid=ul_uuid,
                queue_add=queue_add,
                queue_set=queue_set,
                queues=queues,
                actions=actions,
                mutation_snapshot_id=snapshot_id,
            )
            dl_q_uuid = str(dl_queue.get("uuid") or "")
            if not dl_q_uuid:
                dl_q_ref = _find_by_description(
                    await search_shaper_queues(self.client), DL_QUEUE_DESC
                )
                dl_q_uuid = str((dl_q_ref or {}).get("uuid", ""))
            ul_q_uuid = str(ul_queue.get("uuid") or "")
            if not ul_q_uuid:
                ul_q_ref = _find_by_description(
                    await search_shaper_queues(self.client), UL_QUEUE_DESC
                )
                ul_q_uuid = str((ul_q_ref or {}).get("uuid", ""))

            if not dl_uuid or not ul_uuid:
                msg = "download/upload pipe UUID missing after ensure step"
                raise RuntimeError(msg)
            if not dl_q_uuid or not ul_q_uuid:
                msg = "download/upload queue UUID missing after ensure step"
                raise RuntimeError(msg)

            rules = await search_shaper_rules(self.client)
            for spec in PRESET_RULES:
                target = dl_q_uuid if spec["direction"] == "in" else ul_q_uuid
                await self._ensure_rule(
                    spec=spec,
                    target_uuid=target,
                    wan=wan,
                    rule_add=rule_add,
                    rule_set=rule_set,
                    rules=rules,
                    actions=actions,
                    mutation_snapshot_id=snapshot_id,
                )
                rules = await search_shaper_rules(self.client)
        except Exception as exc:
            logger.exception("bufferbloat_wan preset failed")
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": str(exc), "actions": actions, "partial": True},
                summary=f"**Error:** Preset failed — {exc}",
                snapshot_id=snapshot_id,
            )
        return await finish_mutation(
            self.client,
            snapshot_id=snapshot_id,
            apply=apply,
            summary=(
                f"**Preset `{preset}`** applied ({dl}/{ul} Mbit pipes, "
                f"{len(actions)} step(s))."
            ),
            structured={
                "preset": preset,
                "actions": actions,
                "download_mbit": dl,
                "upload_mbit": ul,
                "line_download_mbit": dl_rate,
                "line_upload_mbit": ul_rate,
                "rate_policy": "85pct_round",
            },
        )
