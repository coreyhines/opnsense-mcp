"""Expose several operations as one tool with an `action`.

One class per operation keeps schemas precise, validation local and refusals
legible. Exposing one MCP tool per operation is a different question, and at
this size the answer is no: near-identical names like `mk_route`, `mk_gateway`,
`mk_vlan`, `mk_npt_rule` and `mk_vip` are exactly where a model picks wrong, and
several of them are destructive.

A group keeps the classes and changes only how they are presented, so the
decision is reversible and the tests over the underlying tools still apply.

What grouping costs: JSON Schema cannot express "name is required, but only when
action is create". `oneOf` and `if`/`then` support is inconsistent across
clients, so per-action requirements are checked here instead, and `action="help"`
returns the contract a schema could not carry.
"""

from __future__ import annotations

import logging
from typing import Any

from opnsense_mcp.utils.schema_fields import SHARED_FIELDS, is_shared

logger = logging.getLogger(__name__)

HELP_ACTION = "help"

# `optional` is not a JSON Schema keyword. Clients ignore it and take
# requiredness from the `required` array, so emitting it on nearly a hundred
# properties bought nothing. Kept on the tool classes, where it reads well and
# `help` still surfaces it; dropped from the wire.
DEAD_SCHEMA_KEYS = frozenset({"optional"})


def strip_dead_keys(spec: dict[str, Any]) -> dict[str, Any]:
    """Copy a property spec without the keys no client reads."""
    return {k: v for k, v in spec.items() if k not in DEAD_SCHEMA_KEYS}


class GroupedTool:
    """Several operations behind one name, selected by `action`."""

    def __init__(
        self,
        name: str,
        description: str,
        members: dict[str, Any],
        field_aliases: dict[str, dict[str, str]] | None = None,
    ) -> None:
        """Build the group.

        ``members`` maps an action name to a tool instance. The instance keeps
        its own name, description and schema, which are what `help` reports.

        ``field_aliases`` maps a member tool's name to ``{own_field: alias}``.
        It exists because the group consumes `action` to pick the member, so a
        member declaring its own `action` field could never receive one: every
        rule created through `fw_rule` came out `pass`, list could not filter by
        action, and packet capture could be started but never stopped. The
        member keeps its own field name and standalone behaviour; only the name
        the group advertises changes, and it is translated back on dispatch.
        """
        self.name = name
        self.members = members
        self.field_aliases = field_aliases or {}
        # The action names are already in the `action` enum, so listing them
        # here too just pays for them twice.
        self.description = (
            f"{description}. Call action='{HELP_ACTION}' for each action's "
            f"fields and rules."
        )
        self.input_schema = self._build_schema()

    def _build_schema(self) -> dict[str, Any]:
        """Union every member's properties under one `action` selector.

        Fields listed in `SHARED_FIELDS` mean the same thing in every tool that
        takes them, so they get one canonical definition and no action prefix.
        That is where most of the saving is: those few names accounted for the
        majority of the repeated property text across the whole surface.

        Anything else that appears in more than one action lists every action
        that takes it. The previous rule kept whichever definition sorted first
        and dropped the others, so the surviving wording was arbitrary — and it
        gets worse as groups grow.
        """
        properties: dict[str, Any] = {
            "action": {
                "type": "string",
                "description": f"Operation to run. '{HELP_ACTION}' lists fields.",
                "enum": [*sorted(self.members), HELP_ACTION],
            }
        }
        # field -> actions that accept it, so a collision can name them all.
        used_by: dict[str, list[str]] = {}
        raw: dict[str, dict[str, Any]] = {}

        for action, tool in sorted(self.members.items()):
            schema = getattr(tool, "input_schema", {}) or {}
            aliases = self._aliases_for(tool)
            for field, spec in (schema.get("properties") or {}).items():
                advertised = aliases.get(field, field)
                used_by.setdefault(advertised, []).append(action)
                raw.setdefault(advertised, spec)

        for field, spec in raw.items():
            if is_shared(field):
                properties[field] = SHARED_FIELDS[field]
                continue
            merged = strip_dead_keys(spec)
            text = spec.get("description", field)
            merged["description"] = (
                f"[{', '.join(used_by[field])}] {text}"
                if len(self.members) > 1
                else text
            )
            properties[field] = merged

        return {
            "type": "object",
            "properties": properties,
            # Only `action` is universally required; the rest depend on it and
            # are enforced in execute().
            "required": ["action"],
        }

    def _aliases_for(self, tool: Any) -> dict[str, str]:
        """The `{own_field: alias}` map for one member tool."""
        return self.field_aliases.get(getattr(tool, "name", ""), {})

    def _rename_to_member_fields(
        self, tool: Any, params: dict[str, Any]
    ) -> dict[str, Any]:
        """Translate advertised alias names back to the member's own fields."""
        aliases = self._aliases_for(tool)
        if not aliases:
            return params
        renamed = dict(params)
        for own_field, alias in aliases.items():
            if alias in renamed:
                renamed[own_field] = renamed.pop(alias)
        return renamed

    def _help(self) -> dict[str, Any]:
        """Describe every action from its own tool's metadata."""
        actions = []
        for action, tool in sorted(self.members.items()):
            schema = getattr(tool, "input_schema", {}) or {}
            aliases = self._aliases_for(tool)
            props = {
                aliases.get(field, field): spec
                for field, spec in (schema.get("properties") or {}).items()
            }
            # `help` is the contract, so it names fields the way a caller must
            # send them, not the way the member declares them.
            required = [
                aliases.get(field, field) for field in (schema.get("required") or [])
            ]
            actions.append(
                {
                    "action": action,
                    "tool": getattr(tool, "name", action),
                    "description": getattr(tool, "description", ""),
                    "required": required,
                    "optional": sorted(f for f in props if f not in required),
                    "fields": {
                        field: spec.get("description", "")
                        for field, spec in sorted(props.items())
                    },
                }
            )
        return {
            "status": "success",
            "tool": self.name,
            "actions": actions,
        }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run the requested action, checking its own required fields first."""
        params = dict(params or {})
        action = params.pop("action", None)

        if not action:
            return {
                "status": "error",
                "error": (
                    f"action is required. Expected one of: "
                    f"{', '.join([*sorted(self.members), HELP_ACTION])}."
                ),
            }

        if action == HELP_ACTION:
            return self._help()

        tool = self.members.get(action)
        if tool is None:
            return {
                "status": "error",
                "error": (
                    f"unknown action {action!r}. Expected one of: "
                    f"{', '.join([*sorted(self.members), HELP_ACTION])}."
                ),
            }

        schema = getattr(tool, "input_schema", {}) or {}
        aliases = self._aliases_for(tool)
        missing = [
            aliases.get(field, field)
            for field in (schema.get("required") or [])
            if params.get(aliases.get(field, field)) in (None, "")
        ]
        if missing:
            return {
                "status": "error",
                "error": (
                    f"action {action!r} requires: {', '.join(missing)}. "
                    f"Call action='{HELP_ACTION}' for the full contract."
                ),
            }

        return await tool.execute(self._rename_to_member_fields(tool, params))
