"""Traffic shaper preset workflows."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from opnsense_mcp.tools.shaper_pipes import AddShaperPipeTool, SetShaperPipeTool
from opnsense_mcp.tools.shaper_rules import AddShaperRuleTool
from opnsense_mcp.tools.shaper_settings import search_shaper_pipes, search_shaper_rules
from opnsense_mcp.utils.shaper_mutation import (
    capture_pre_mutation_snapshot,
    finish_mutation,
)
from opnsense_mcp.utils.shaper_types import TOOL_STATUS_ERROR, make_tool_response

if TYPE_CHECKING:
    from opnsense_mcp.utils.api import OPNsenseClient
    from opnsense_mcp.utils.mock_api import MockOPNsenseClient

logger = logging.getLogger(__name__)

ClientT = "OPNsenseClient | MockOPNsenseClient | None"


class ApplyShaperPresetTool:
    """Apply a named shaper preset (bufferbloat_wan)."""

    name = "apply_shaper_preset"
    description = "Apply bufferbloat_wan preset: FQ-CoDel pipes at 85% ISP rates, dual-stack WAN rules"
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
        dl = int(float(params["download_mbit"]) * 0.85)
        ul = int(float(params["upload_mbit"]) * 0.85)
        apply = bool(params.get("apply", True))
        wan = str(params.get("wan_interface") or "wan")
        snapshot_id = await capture_pre_mutation_snapshot(
            self.client, description="Before bufferbloat_wan preset"
        )
        actions: list[str] = []
        pipes = await search_shaper_pipes(self.client)
        dl_pipe = next(
            (p for p in pipes if "download" in (p.get("description") or "").lower()),
            None,
        )
        ul_pipe = next(
            (p for p in pipes if "upload" in (p.get("description") or "").lower()), None
        )
        pipe_tool_add = AddShaperPipeTool(self.client)
        pipe_tool_set = SetShaperPipeTool(self.client)
        if dl_pipe and dl_pipe.get("uuid"):
            await pipe_tool_set.execute(
                {
                    "uuid": dl_pipe["uuid"],
                    "bandwidth": dl,
                    "scheduler": "fq_codel",
                    "apply": False,
                }
            )
            actions.append(f"set download pipe {dl_pipe['uuid']}")
        else:
            await pipe_tool_add.execute(
                {
                    "description": "Download pipe",
                    "bandwidth": dl,
                    "scheduler": "fq_codel",
                    "apply": False,
                }
            )
            actions.append("add download pipe")
        pipes = await search_shaper_pipes(self.client)
        dl_pipe = next(
            (p for p in pipes if "download" in (p.get("description") or "").lower()),
            dl_pipe,
        )
        if ul_pipe and ul_pipe.get("uuid"):
            await pipe_tool_set.execute(
                {
                    "uuid": ul_pipe["uuid"],
                    "bandwidth": ul,
                    "scheduler": "fq_codel",
                    "apply": False,
                }
            )
            actions.append(f"set upload pipe {ul_pipe['uuid']}")
        else:
            await pipe_tool_add.execute(
                {
                    "description": "Upload pipe",
                    "bandwidth": ul,
                    "scheduler": "fq_codel",
                    "apply": False,
                }
            )
            actions.append("add upload pipe")
        rules = await search_shaper_rules(self.client)
        rule_tool = AddShaperRuleTool(self.client)
        if not any(
            r.get("proto") == "ip" and r.get("direction") == "in" for r in rules
        ):
            await rule_tool.execute(
                {
                    "description": "Download Rule",
                    "interface": wan,
                    "direction": "in",
                    "proto": "ip",
                    "target_uuid": dl_pipe.get("uuid", "") if dl_pipe else "",
                    "apply": False,
                }
            )
            actions.append("add download ip rule")
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
            },
        )
