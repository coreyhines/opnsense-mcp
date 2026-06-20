"""Traffic shaper rule read tools."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from opnsense_mcp.tools.shaper_settings import search_shaper_rules
from opnsense_mcp.utils.shaper_mutation import (
    capture_pre_mutation_snapshot,
    finish_mutation,
    load_pipe_queue_rule_rows,
    mutation_snapshot_for_tool,
    target_description_map,
)
from opnsense_mcp.utils.shaper_normalize import normalize_rule
from opnsense_mcp.utils.shaper_serialize import merge_flat_into_rule, serialize_rule
from opnsense_mcp.utils.shaper_types import (
    TOOL_STATUS_ERROR,
    TOOL_STATUS_SUCCESS,
    TOOL_STATUS_WARNING,
    FlatShaperRule,
    make_tool_response,
)
from opnsense_mcp.utils.shaper_write_helpers import (
    detect_idempotent_set,
    issue_delete_confirm_token,
    validate_delete_confirm_token,
    warn_lan_interface,
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


def _flat_rule_from_params(params: dict[str, Any], *, uuid: str = "") -> FlatShaperRule:
    flat: FlatShaperRule = {
        "description": str(params.get("description") or ""),
        "enabled": bool(params.get("enabled", True)),
        "interface": str(params.get("interface") or "wan"),
        "interface2": str(params.get("interface2") or ""),
        "direction": str(params.get("direction") or "in"),
        "proto": str(params.get("proto") or "ip"),
        "source": str(params.get("source") or "any"),
        "destination": str(params.get("destination") or "any"),
        "target_uuid": str(params.get("target_uuid") or ""),
        "sequence": int(params.get("sequence") or 0),
    }
    if uuid:
        flat["uuid"] = uuid
    return flat


class AddShaperRuleTool:
    name = "add_shaper_rule"
    description = "Create a traffic shaper rule"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "description": {"type": "string"},
            "interface": {"type": "string"},
            "direction": {"type": "string"},
            "proto": {"type": "string"},
            "target_uuid": {"type": "string"},
            "apply": {"type": "boolean", "default": True},
            "mutation_snapshot_id": {"type": "string"},
            "capture_snapshot": {"type": "boolean", "default": True},
        },
        "required": ["description", "interface", "target_uuid"],
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
        flat = _flat_rule_from_params(params)
        target_uuid = flat.get("target_uuid", "")
        if not target_uuid:
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": "target_uuid required"},
                summary="**Error:** `target_uuid` is required.",
            )
        hints: list[str] = []
        lan_warn = warn_lan_interface(flat.get("interface", ""))
        if lan_warn:
            hints.append(lan_warn)
        try:
            pipe_rows, queue_rows, _ = await load_pipe_queue_rule_rows(self.client)
            tmap = target_description_map(queue_rows, pipe_rows)
            if target_uuid not in tmap:
                return make_tool_response(
                    status=TOOL_STATUS_ERROR,
                    structured={"error": "target_uuid not found", "target_uuid": target_uuid},
                    summary=f"**Error:** Target `{target_uuid}` not found.",
                )
            snapshot_id = await mutation_snapshot_for_tool(
                self.client,
                params,
                description=f"Before add rule {flat.get('description')}",
            )
            payload = serialize_rule(flat, tmap)
            result = await self.client._make_request(
                "POST", "/trafficshaper/settings/add_rule/", json=payload
            )
            rule_uuid = result.get("id") or result.get("uuid", "")
            flat["uuid"] = str(rule_uuid)
        except Exception as exc:
            logger.exception("Failed to add shaper rule")
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": str(exc)},
                summary=f"**Error:** Failed to add rule — {exc}",
            )
        return await finish_mutation(
            self.client,
            snapshot_id=snapshot_id,
            apply=bool(params.get("apply", True)),
            summary=f"**Added rule** `{flat.get('description')}` (UUID `{rule_uuid}`).",
            structured={"rule": flat, "api_result": result},
            hints=hints,
        )


class SetShaperRuleTool:
    name = "set_shaper_rule"
    description = "Update a traffic shaper rule"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string"},
            "description": {"type": "string"},
            "interface": {"type": "string"},
            "direction": {"type": "string"},
            "proto": {"type": "string"},
            "target_uuid": {"type": "string"},
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
                structured={"error": "client and uuid required"},
                summary="**Error:** Client and `uuid` required.",
            )
        hints: list[str] = []
        try:
            gui_resp = await self.client._make_request(
                "GET", f"/trafficshaper/settings/get_rule/{uuid}"
            )
            existing_gui = gui_resp.get("rule") or {}
            existing = normalize_rule({**existing_gui, "uuid": uuid})
            proposed = dict(existing)
            for key in (
                "description",
                "interface",
                "direction",
                "proto",
                "target_uuid",
                "enabled",
            ):
                if params.get(key) is not None:
                    proposed[key] = params[key]  # type: ignore[index]
            lan_warn = warn_lan_interface(str(proposed.get("interface") or ""))
            if lan_warn:
                hints.append(lan_warn)
            if detect_idempotent_set(existing, proposed):
                return make_tool_response(
                    status=TOOL_STATUS_WARNING,
                    structured={"rule": existing, "idempotent": True},
                    summary="**Warning:** Rule unchanged (identical set request).",
                    hints=["No changes applied; payload matches existing config."],
                )
            pipe_rows, queue_rows, _ = await load_pipe_queue_rule_rows(self.client)
            tmap = target_description_map(queue_rows, pipe_rows)
            if proposed.get("target_uuid") and proposed["target_uuid"] not in tmap:
                return make_tool_response(
                    status=TOOL_STATUS_ERROR,
                    structured={
                        "error": "target_uuid not found",
                        "target_uuid": proposed["target_uuid"],
                    },
                    summary=f"**Error:** Target `{proposed['target_uuid']}` not found.",
                )
            snapshot_id = await mutation_snapshot_for_tool(
                self.client,
                params,
                description=f"Before set rule {uuid}",
            )
            payload = merge_flat_into_rule(existing_gui, proposed, tmap)
            result = await self.client._make_request(
                "POST", f"/trafficshaper/settings/set_rule/{uuid}", json=payload
            )
        except Exception as exc:
            logger.exception("Failed to set shaper rule")
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": str(exc)},
                summary=f"**Error:** Failed to set rule — {exc}",
            )
        return await finish_mutation(
            self.client,
            snapshot_id=snapshot_id,
            apply=apply,
            summary=f"**Updated rule** `{proposed.get('description')}` (`{uuid}`).",
            structured={"rule": proposed, "api_result": result},
            hints=hints,
        )


class ToggleShaperRuleTool:
    name = "toggle_shaper_rule"
    description = "Toggle rule enabled state"
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
                self.client, description=f"Before toggle rule {uuid}"
            )
            result = await self.client._make_request(
                "POST", f"/trafficshaper/settings/toggle_rule/{uuid}"
            )
        except Exception as exc:
            logger.exception("Failed to toggle shaper rule")
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": str(exc)},
                summary=f"**Error:** Failed to toggle rule — {exc}",
            )
        return await finish_mutation(
            self.client,
            snapshot_id=snapshot_id,
            apply=apply,
            summary=f"**Toggled rule** `{uuid}` (enabled={result.get('enabled')}).",
            structured={"uuid": uuid, "api_result": result},
        )


class DeleteShaperRuleTool:
    name = "delete_shaper_rule"
    description = "Delete a rule (confirm token required)"
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
        if not validate_delete_confirm_token("rule", uuid, str(confirm or "")):
            token_info = issue_delete_confirm_token("rule", uuid)
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
                self.client, description=f"Before delete rule {uuid}"
            )
            result = await self.client._make_request(
                "POST", f"/trafficshaper/settings/del_rule/{uuid}"
            )
        except Exception as exc:
            logger.exception("Failed to delete shaper rule")
            return make_tool_response(
                status=TOOL_STATUS_ERROR,
                structured={"error": str(exc)},
                summary=f"**Error:** Failed to delete rule — {exc}",
            )
        return await finish_mutation(
            self.client,
            snapshot_id=snapshot_id,
            apply=apply,
            summary=f"**Deleted rule** `{uuid}`.",
            structured={"uuid": uuid, "api_result": result},
        )
