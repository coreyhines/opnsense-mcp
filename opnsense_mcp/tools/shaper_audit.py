"""Traffic shaper audit and explain read tools."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from opnsense_mcp.tools.shaper_settings import (
    fetch_shaper_statistics,
    search_shaper_pipes,
    search_shaper_queues,
    search_shaper_rules,
)
from opnsense_mcp.utils.shaper_audit_rules import (
    explain_shaper_config as build_explanation,
)
from opnsense_mcp.utils.shaper_audit_rules import (
    format_audit_summary,
    run_audit,
)
from opnsense_mcp.utils.shaper_types import TOOL_STATUS_ERROR, make_tool_response

if TYPE_CHECKING:
    from opnsense_mcp.utils.api import OPNsenseClient
    from opnsense_mcp.utils.mock_api import MockOPNsenseClient

logger = logging.getLogger(__name__)

ClientT = "OPNsenseClient | MockOPNsenseClient | None"


def _optional_float(value: Any) -> float | None:
    """Parse optional numeric parameter."""
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


class AuditShaperConfigTool:
    """Run best-practice audit checklist against current shaper config."""

    name = "audit_shaper_config"
    description = (
        "Audit traffic shaper configuration against best practices; "
        "optional ISP rates and WAN line rate for bandwidth checks"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "isp_download_mbit": {
                "type": "number",
                "description": "Reference ISP download rate in Mbit/s",
            },
            "isp_upload_mbit": {
                "type": "number",
                "description": "Reference ISP upload rate in Mbit/s",
            },
            "wan_line_rate_mbit": {
                "type": "number",
                "description": "WAN physical line rate cap in Mbit/s",
            },
        },
        "required": [],
    }

    def __init__(self, client: ClientT) -> None:
        """Initialize with an OPNsense API client."""
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Fetch config + statistics and run audit checklist."""
        params = params or {}
        if not self.client:
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": "No client available"},
                summary="**Error:** No OPNsense client configured.",
            )

        isp_download = _optional_float(params.get("isp_download_mbit"))
        isp_upload = _optional_float(params.get("isp_upload_mbit"))
        wan_line_rate = _optional_float(params.get("wan_line_rate_mbit"))

        try:
            pipes = await search_shaper_pipes(self.client)
            queues = await search_shaper_queues(self.client)
            rules = await search_shaper_rules(self.client)
            statistics = await fetch_shaper_statistics(self.client)
            audit = run_audit(
                pipes=pipes,
                queues=queues,
                rules=rules,
                statistics=statistics,
                wan_line_rate_mbit=wan_line_rate,
                isp_download_mbit=isp_download,
                isp_upload_mbit=isp_upload,
            )
        except Exception as exc:
            logger.exception("Failed to audit shaper config")
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": str(exc)},
                summary=f"**Error:** Audit failed — {exc}",
            )

        findings = [
            {
                "severity": f.severity,
                "code": f.code,
                "message": f.message,
            }
            for f in audit.findings
        ]
        structured = {
            "score": audit.score,
            "findings": findings,
            "finding_count": len(findings),
        }
        hints = [f.message for f in audit.findings]

        return make_tool_response(
            status=audit.status,
            structured=structured,
            summary=format_audit_summary(audit),
            hints=hints,
        )


class ExplainShaperConfigTool:
    """Plain-language explanation of traffic shaper configuration."""

    name = "explain_shaper_config"
    description = (
        "Explain traffic shaper configuration in plain language for non-technical users"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "include_audit": {
                "type": "boolean",
                "description": "When true, run audit first and weave findings into the narrative",
                "default": True,
            },
        },
        "required": [],
    }

    def __init__(self, client: ClientT) -> None:
        """Initialize with an OPNsense API client."""
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Fetch config and return a plain-language narrative."""
        params = params or {}
        if not self.client:
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": "No client available"},
                summary="**Error:** No OPNsense client configured.",
            )

        include_audit = bool(params.get("include_audit", True))

        try:
            pipes = await search_shaper_pipes(self.client)
            queues = await search_shaper_queues(self.client)
            rules = await search_shaper_rules(self.client)
            audit = None
            status = "success"
            hints: list[str] = []
            if include_audit:
                statistics = await fetch_shaper_statistics(self.client)
                audit = run_audit(
                    pipes=pipes,
                    queues=queues,
                    rules=rules,
                    statistics=statistics,
                )
                status = audit.status
                hints = [f.message for f in audit.findings]

            narrative = build_explanation(
                pipes=pipes,
                queues=queues,
                rules=rules,
                audit=audit,
            )
        except Exception as exc:
            logger.exception("Failed to explain shaper config")
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": str(exc)},
                summary=f"**Error:** Explain failed — {exc}",
            )

        structured: dict[str, Any] = {
            "narrative": narrative,
            "pipe_count": len(pipes),
            "queue_count": len(queues),
            "rule_count": len(rules),
        }
        if audit is not None:
            structured["audit_score"] = audit.score
            structured["audit_status"] = audit.status

        summary = f"**Traffic Shaper Explained**\n\n{narrative}"

        return make_tool_response(
            status=status,
            structured=structured,
            summary=summary,
            hints=hints,
        )
