"""Grouping several operations behind one tool.

Eighty-nine tools is too many for a model to choose between reliably, and the
worst of it is near-identical names: mk_route, mk_gateway, mk_vlan, mk_npt_rule,
mk_alias, mk_vip, mk_loopback. Several are destructive.

The implementation stays one class per operation, which is what keeps the
schemas precise and the refusals legible. This wraps them so the exposed surface
is one tool per resource with an `action`, and the model picks the object first
and the verb second.

The cost is that JSON Schema cannot express per-action required fields, so those
are checked in code. `action="help"` gives back the per-action contract, which is
what a schema would have carried and more besides.
"""

from __future__ import annotations

from typing import Any

import pytest

from opnsense_mcp.utils.grouped_tool import GroupedTool


class _FakeTool:
    """Minimal stand-in with the metadata a group reads."""

    def __init__(self, name: str, required: list[str], props: dict[str, Any]) -> None:
        self.name = name
        self.description = f"does {name}"
        self.input_schema = {
            "type": "object",
            "properties": props,
            "required": required,
        }
        self.calls: list[dict[str, Any]] = []

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.calls.append(params or {})
        return {"status": "success", "from": self.name}


def _group() -> tuple[GroupedTool, dict[str, _FakeTool]]:
    members = {
        "list": _FakeTool("list_thing", [], {}),
        "create": _FakeTool(
            "mk_thing",
            ["name"],
            {"name": {"type": "string"}, "size": {"type": "number"}},
        ),
        "delete": _FakeTool(
            "rm_thing",
            ["uuid"],
            {"uuid": {"type": "string"}, "confirm": {"type": "string"}},
        ),
    }
    group = GroupedTool(
        name="thing",
        description="Manage things",
        members=members,
    )
    return group, members


def test_group_advertises_one_tool_with_an_action_enum() -> None:
    group, _ = _group()

    schema = group.input_schema

    assert group.name == "thing"
    assert schema["required"] == ["action"]
    assert set(schema["properties"]["action"]["enum"]) == {
        "list",
        "create",
        "delete",
        "help",
    }


def test_group_schema_unions_member_properties() -> None:
    """One schema has to describe every action's arguments."""
    group, _ = _group()

    props = group.input_schema["properties"]

    assert {"name", "size", "uuid", "confirm"} <= set(props)


def test_group_dispatches_to_the_right_member() -> None:
    group, members = _group()

    result = _run(group.execute({"action": "create", "name": "x"}))

    assert result["from"] == "mk_thing"
    assert members["create"].calls == [{"name": "x"}]


def test_group_strips_the_action_before_dispatching() -> None:
    """Members never see an argument they do not declare."""
    group, members = _group()

    _run(group.execute({"action": "list"}))

    assert members["list"].calls == [{}]


def test_group_rejects_an_unknown_action() -> None:
    group, _ = _group()

    result = _run(group.execute({"action": "explode"}))

    assert result["status"] == "error"
    assert "explode" in result["error"]
    assert "create" in result["error"]


def test_group_requires_an_action() -> None:
    group, _ = _group()

    result = _run(group.execute({"name": "x"}))

    assert result["status"] == "error"
    assert "action" in result["error"]


def test_group_checks_per_action_required_fields() -> None:
    """The schema cannot express this, so the group does."""
    group, members = _group()

    result = _run(group.execute({"action": "create"}))

    assert result["status"] == "error"
    assert "name" in result["error"]
    assert not members["create"].calls


def test_help_lists_every_action_and_its_fields() -> None:
    group, _ = _group()

    result = _run(group.execute({"action": "help"}))

    assert result["status"] == "success"
    actions = {a["action"]: a for a in result["actions"]}
    assert set(actions) == {"list", "create", "delete"}
    assert actions["create"]["required"] == ["name"]
    assert "size" in actions["create"]["optional"]


def test_help_reaches_no_member() -> None:
    """help is answered from metadata; it must not touch the firewall."""
    group, members = _group()

    _run(group.execute({"action": "help"}))

    assert all(not m.calls for m in members.values())


def test_help_is_in_the_description_so_it_is_discoverable() -> None:
    group, _ = _group()

    assert "help" in group.description


def test_group_reports_the_underlying_tool_name() -> None:
    """Errors and logs should still name the operation that ran."""
    group, _ = _group()

    result = _run(group.execute({"action": "delete", "uuid": "abc"}))

    assert result["from"] == "rm_thing"


def _run(coro: Any) -> Any:
    import asyncio

    return asyncio.get_event_loop().run_until_complete(coro)


@pytest.fixture(autouse=True)
def _event_loop_policy() -> Any:
    """Give _run a loop to use under pytest-asyncio's auto mode."""
    import asyncio

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield
    loop.close()


def test_every_operation_is_reachable_through_the_exposed_surface() -> None:
    """Grouping must not strand a tool.

    A tool that is neither in a group nor on the ungrouped list would still be
    passed through, but silently: this makes the omission visible so it gets a
    home deliberately.
    """
    from pathlib import Path

    from opnsense_mcp.fastmcp_server import build_shaper_tools
    from opnsense_mcp.utils.mock_api import MockOPNsenseClient
    from opnsense_mcp.utils.registry import build_tools
    from opnsense_mcp.utils.tool_groups import GROUPS, UNGROUPED, build_groups

    client = MockOPNsenseClient(
        {"development": {"mock_data_path": str(Path("examples/mock_data"))}}
    )
    operations = build_tools(client, extra=build_shaper_tools(client))
    exposed = build_groups(operations)

    grouped_ops = {
        tool_name
        for _desc, members in GROUPS.values()
        for tool_name in members.values()
    }
    homeless = set(operations) - grouped_ops - UNGROUPED

    assert not homeless, (
        f"operations with no group and not on the ungrouped list: {sorted(homeless)}"
    )
    assert set(exposed) == set(GROUPS) | UNGROUPED
    assert len(exposed) < len(operations) / 2


def test_group_names_do_not_collide_with_ungrouped_names() -> None:
    """A collision would silently shadow one of them."""
    from opnsense_mcp.utils.tool_groups import GROUPS, UNGROUPED

    assert not set(GROUPS) & UNGROUPED
