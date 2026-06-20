"""Traffic shaper rule read tools."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from opnsense_mcp.tools.shaper_settings import search_shaper_rules
from opnsense_mcp.utils.shaper_normalize import normalize_rule
from opnsense_mcp.utils.shaper_types import (
    TOOL_STATUS_ERROR,
    TOOL_STATUS_SUCCESS,
    FlatShaperRule,
    make_tool_response,
)

if TYPE_CHECKING:
    from opnsense_mcp.utils.api import OPNsenseClient
    from opnsense_mcp.utils.mock_api import MockOPNsenseClient

logger = logging.getLogger(__name__)

ClientT = "OPNsenseClient | MockOPNsenseClient | None"


def _filter_rules(
    rules: list[FlatShaperRule],
    *,
    enabled: bool | None,
    description: str | None,
    interface: str | None,
) -> list[FlatShaperRule]:
    """Apply optional client-side filters to rule list."""
    result = rules
    if enabled is not None:
        result = [r for r in result if r.get("enabled") is enabled]
    if description:
        needle = description.lower()
        result = [r for r in result if needle in (r.get("description") or "").lower()]
    if interface:
        iface = interface.lower()
        result = [r for r in result if (r.get("interface") or "").lower() == iface]
    return result


def _format_rules_table(rules: list[FlatShaperRule]) -> str:
    """Markdown table for rule summaries."""
    if not rules:
        return "No rules found."
    lines = [
        "| Description | IF | Dir | Proto | Target | Enabled | UUID |",
        "|-------------|-----|-----|-------|--------|---------|------|",
    ]
    for rule in rules:
        desc = rule.get("description", "")
        iface = rule.get("interface", "")
        direction = rule.get("direction", "")
        proto = rule.get("proto", "")
        target = rule.get("target_uuid", "")
        en = "yes" if rule.get("enabled") else "no"
        uuid = rule.get("uuid", "")
        lines.append(
            f"| {desc} | {iface} | {direction} | {proto} | `{target}` | {en} | `{uuid}` |"
        )
    return "\n".join(lines)


def _find_rule(
    rules: list[FlatShaperRule],
    *,
    uuid: str | None,
    description: str | None,
) -> FlatShaperRule | None:
    """Match one rule by uuid (exact) or description substring."""
    if uuid:
        for rule in rules:
            if rule.get("uuid") == uuid:
                return rule
    if description:
        needle = description.lower()
        for rule in rules:
            if needle in (rule.get("description") or "").lower():
                return rule
    return None


class ListShaperRulesTool:
    """List traffic shaper rules (flat normalized view)."""

    name = "list_shaper_rules"
    description = "List traffic shaper rules with optional filters"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "enabled": {
                "type": "boolean",
                "description": "When set, filter to enabled or disabled rules only",
            },
            "description": {
                "type": "string",
                "description": "Optional description substring filter",
            },
            "interface": {
                "type": "string",
                "description": "Optional interface name filter (e.g. wan)",
            },
        },
        "required": [],
    }

    def __init__(self, client: ClientT) -> None:
        """Initialize with an OPNsense API client."""
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Fetch and return all rules."""
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
        interface = str(params.get("interface") or "").strip() or None

        try:
            rules = await search_shaper_rules(self.client)
            rules = _filter_rules(
                rules,
                enabled=enabled,
                description=description,
                interface=interface,
            )
        except Exception as exc:
            logger.exception("Failed to list shaper rules")
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": str(exc)},
                summary=f"**Error:** Failed to list rules — {exc}",
            )

        summary = (
            f"**Traffic Shaper Rules** — {len(rules)} rule(s)\n\n"
            f"{_format_rules_table(rules)}"
        )
        return make_tool_response(
            status=TOOL_STATUS_SUCCESS,
            structured={"rules": rules, "count": len(rules)},
            summary=summary,
        )


class GetShaperRuleTool:
    """Get one traffic shaper rule by uuid or description."""

    name = "get_shaper_rule"
    description = "Get one traffic shaper rule by uuid or description substring"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {
                "type": "string",
                "description": "Rule UUID",
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
        """Fetch one rule by uuid or description."""
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
                summary="**Error:** Provide `uuid` or `description` to identify a rule.",
            )

        try:
            if uuid:
                resp = await self.client._make_request(
                    "GET",
                    f"/trafficshaper/settings/get_rule/{uuid}",
                )
                row = resp.get("rule") or {}
                if row:
                    rule = normalize_rule({**row, "uuid": row.get("uuid", uuid)})
                else:
                    rules = await search_shaper_rules(self.client)
                    rule = _find_rule(rules, uuid=uuid, description=None)
            else:
                rules = await search_shaper_rules(self.client)
                rule = _find_rule(rules, uuid=None, description=description)
        except Exception as exc:
            logger.exception("Failed to get shaper rule")
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": str(exc)},
                summary=f"**Error:** Failed to get rule — {exc}",
            )

        if rule is None:
            label = uuid or description or "?"
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={
                    "error": "rule not found",
                    "uuid": uuid,
                    "description": description,
                },
                summary=f"**Error:** No rule matched `{label}`.",
            )

        desc = rule.get("description", "")
        summary = (
            f"**Rule:** {desc}\n\n"
            f"- Interface: {rule.get('interface')} ({rule.get('direction')})\n"
            f"- Proto: {rule.get('proto')}\n"
            f"- Target UUID: `{rule.get('target_uuid')}`\n"
            f"- Enabled: {rule.get('enabled')}\n"
            f"- UUID: `{rule.get('uuid')}`"
        )
        return make_tool_response(
            status=TOOL_STATUS_SUCCESS,
            structured={"rule": rule},
            summary=summary,
        )
