"""Shared property definitions, and what happens when group members collide.

Two thirds of the exposed schema was the same handful of fields restated per
tool: `apply` appeared in seventeen tools, each with its own prose for the same
boolean. Defining them once is the largest single reduction available, and
unlike regrouping it changes no behaviour.

The collision rule matters more once groups get bigger. `_build_schema` used to
keep whichever definition sorted first and drop the rest silently, so a field's
description came from an arbitrary action.
"""

from __future__ import annotations

from opnsense_mcp.utils.grouped_tool import GroupedTool
from opnsense_mcp.utils.schema_fields import SHARED_FIELDS, canonical_property


class _Tool:
    """Minimal stand-in for a tool class."""

    def __init__(self, name: str, properties: dict, required: list[str] | None = None):
        self.name = name
        self.description = f"{name} description"
        self.input_schema = {
            "type": "object",
            "properties": properties,
            "required": required or [],
        }

    async def execute(self, params: dict | None = None) -> dict:
        return {"status": "success", "tool": self.name, "params": params}


def test_a_shared_field_gets_one_definition_regardless_of_caller() -> None:
    """`apply` means the same thing everywhere, so it reads the same everywhere."""
    a = canonical_property("apply", {"type": "boolean", "description": "Reload pf"})
    b = canonical_property(
        "apply", {"type": "boolean", "description": "Reconfigure dnsmasq"}
    )

    assert a == b
    assert a == SHARED_FIELDS["apply"]


def test_a_field_that_is_not_shared_is_returned_untouched() -> None:
    """Context-specific fields keep their own wording; that wording is the value."""
    spec = {"type": "string", "description": "Source network or alias to translate"}

    assert canonical_property("source_net", spec) == spec


def test_shared_fields_stay_short() -> None:
    """The point is fewer characters; a bloated canonical definition undoes it."""
    for name, spec in SHARED_FIELDS.items():
        assert len(spec.get("description", "")) <= 120, name


def test_group_schema_uses_the_canonical_definition() -> None:
    group = GroupedTool(
        name="thing",
        description="Things",
        members={
            "create": _Tool("mk", {"apply": {"type": "boolean", "description": "A"}}),
            "delete": _Tool("rm", {"apply": {"type": "boolean", "description": "B"}}),
        },
    )

    assert group.input_schema["properties"]["apply"] == SHARED_FIELDS["apply"]


def test_colliding_non_shared_fields_name_every_action_that_uses_them() -> None:
    """Dropping the second definition made the surviving one arbitrary."""
    group = GroupedTool(
        name="thing",
        description="Things",
        members={
            "create": _Tool(
                "mk", {"target": {"type": "string", "description": "where to put it"}}
            ),
            "move": _Tool(
                "mv", {"target": {"type": "string", "description": "where to move it"}}
            ),
        },
    )

    described = group.input_schema["properties"]["target"]["description"]
    assert "create" in described
    assert "move" in described


def test_a_field_used_by_one_action_still_says_which() -> None:
    group = GroupedTool(
        name="thing",
        description="Things",
        members={
            "create": _Tool(
                "mk", {"name": {"type": "string", "description": "a name"}}
            ),
            "list": _Tool("ls", {}),
        },
    )

    assert "[create]" in group.input_schema["properties"]["name"]["description"]


def test_shared_fields_are_not_prefixed_with_an_action() -> None:
    """They apply to whichever action takes them, so a prefix would mislead."""
    group = GroupedTool(
        name="thing",
        description="Things",
        members={
            "create": _Tool("mk", {"apply": {"type": "boolean", "description": "A"}}),
            "list": _Tool("ls", {}),
        },
    )

    assert "[create]" not in group.input_schema["properties"]["apply"]["description"]
