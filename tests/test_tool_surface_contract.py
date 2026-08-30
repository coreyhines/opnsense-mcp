"""The tool surface is a contract, pinned so a refactor cannot change it silently.

Two breaking changes are planned: the registry replaces `handle_message`'s
positional arguments and the hand-written FastMCP wrappers, and the shaper tools
are regrouped from 25 names to 3. Both are presentation changes that must not
alter behaviour, and both touch code that is thinly covered today
(`server.py` dispatch sits around 38%).

These tests are the net. They assert what the servers expose rather than how
they are wired, so they survive the refactor and fail if it changes the contract
by accident.

`tests/fixtures/tool_surface.json` is the golden snapshot. Regenerate it
deliberately, never to make a red test green:

    uv run python -m tests.regen_tool_surface
"""

from __future__ import annotations

import pytest

from tests.tool_surface import (
    GOLDEN,
    NO_CLIENT_TOOLS,
    classes_missing_metadata,
    current_surface,
    discover_all_tool_classes,
    discover_tool_classes,
    load_golden,
)

# Classes with no name/description/input_schema. These are deliberately not
# exposed as tools, so a registry keyed on `name` skips them:
#   FirewallLogsTool  base class that GetLogsTool extends
#   FirewallTool      legacy, referenced only by tools/__init__.TOOL_CLASSES
#   InterfaceTool     legacy, its get_interface_configuration returns {}
# Asserted as an exact set: a new tool class landing without metadata fails
# here rather than going missing after the dispatch rewrite.
KNOWN_MISSING_METADATA = frozenset(
    {
        "FirewallLogsTool",
        "FirewallTool",
        "InterfaceTool",
    }
)


def test_golden_snapshot_exists() -> None:
    """Without the snapshot the other assertions prove nothing."""
    assert GOLDEN.exists(), (
        f"{GOLDEN} is missing; run: uv run python -m tests.regen_tool_surface"
    )


def test_no_tool_disappears() -> None:
    """A rename must be deliberate. Regrouping still has to keep the old names
    for a release, so a name vanishing without the snapshot moving is a break."""
    missing = sorted(set(load_golden()) - set(current_surface()))

    assert not missing, (
        f"tools removed from the surface: {missing}. "
        "If intentional, regenerate the snapshot in the same commit."
    )


def test_no_tool_appears_unannounced() -> None:
    """New tools are fine, but the snapshot records them so review sees them."""
    added = sorted(set(current_surface()) - set(load_golden()))

    assert not added, f"tools added to the surface: {added}. Regenerate the snapshot."


@pytest.mark.parametrize("name", sorted(load_golden()))
def test_input_schema_is_unchanged(name: str) -> None:
    """The schema is the caller-facing contract; presentation changes must not
    alter it. Parametrised so a failure names the offending tool."""
    golden = load_golden()[name]["inputSchema"]

    assert current_surface()[name]["inputSchema"] == golden


def test_named_tools_declare_full_metadata() -> None:
    """Anything already carrying a name must carry the rest too."""
    incomplete = []
    for name, cls in sorted(discover_tool_classes().items()):
        if not getattr(cls, "description", None):
            incomplete.append(f"{name}: no description")
        if getattr(cls, "input_schema", None) is None:
            incomplete.append(f"{name}: no input_schema")

    assert not incomplete, "\n".join(incomplete)


def test_metadata_gap_matches_the_known_list() -> None:
    """The registry cannot read metadata that does not exist.

    Asserted as an exact set, not a ceiling: retrofitting a class must shrink
    the list in the same commit, and a new class without metadata fails here
    rather than surfacing as a missing tool after the dispatch rewrite.
    """
    actual = classes_missing_metadata()

    newly_broken = sorted(actual - KNOWN_MISSING_METADATA)
    assert not newly_broken, f"new classes without registry metadata: {newly_broken}"

    fixed = sorted(KNOWN_MISSING_METADATA - actual)
    assert not fixed, (
        f"these now have metadata: {fixed}. "
        "Remove them from KNOWN_MISSING_METADATA in this commit."
    )


def test_every_tool_class_is_discovered() -> None:
    """Guards the discovery itself: if it silently found nothing, every other
    assertion here would pass while proving nothing."""
    assert len(discover_all_tool_classes()) > 50
    assert len(discover_tool_classes()) > 40


def test_every_tool_is_constructible() -> None:
    """A generic registry builds these uniformly, so each must accept a client,
    or be listed as one that does not take one."""
    failures = []
    for name, cls in sorted(discover_tool_classes().items()):
        try:
            cls() if name in NO_CLIENT_TOOLS else cls(None)
        except Exception as exc:  # noqa: BLE001 - reporting, not handling
            failures.append(f"{name}: {type(exc).__name__}: {exc}")

    assert not failures, "\n".join(failures)


def test_every_tool_has_execute() -> None:
    """Dispatch calls execute(args); a registry cannot special-case each tool."""
    missing = [
        name
        for name, cls in sorted(discover_tool_classes().items())
        if not callable(getattr(cls, "execute", None))
    ]

    assert not missing, f"tools without execute(): {missing}"


def test_input_schemas_are_well_formed() -> None:
    """Malformed schemas break clients at registration, not at call time."""
    problems = []
    for name, entry in sorted(current_surface().items()):
        schema = entry["inputSchema"]
        if not isinstance(schema, dict):
            problems.append(f"{name}: schema is {type(schema).__name__}")
            continue
        if schema.get("type") != "object":
            problems.append(f"{name}: type is {schema.get('type')!r}, expected object")
        props = schema.get("properties")
        if not isinstance(props, dict):
            problems.append(f"{name}: properties is {type(props).__name__}")
            continue
        for req in schema.get("required", []):
            if req not in props:
                problems.append(f"{name}: required {req!r} is not in properties")
        # Cursor's MCP client rejects JSON Schema type unions written as
        # ``"type": ["integer", "string"]`` under properties (Zod: expected
        # record). Use anyOf/oneOf with typed objects instead.
        for prop_name, prop_schema in props.items():
            if not isinstance(prop_schema, dict):
                problems.append(
                    f"{name}.{prop_name}: property schema is "
                    f"{type(prop_schema).__name__}, expected object"
                )
                continue
            prop_type = prop_schema.get("type")
            if isinstance(prop_type, list):
                problems.append(
                    f"{name}.{prop_name}: type is a list {prop_type!r}; "
                    "use anyOf/oneOf for Cursor MCP compatibility"
                )

    assert not problems, "\n".join(problems)


def test_exposed_group_schemas_avoid_prototype_keys() -> None:
    """Grouped tools are what HTTP clients see; keep their keys Zod-safe.

    A property named ``constructor`` (dnsmasq's real field) shadows
    Object.prototype and makes Zod's z.record() reject the whole properties
    map — Cursor then loads zero tools. Alias before advertising.
    """
    from opnsense_mcp.fastmcp_server import build_shaper_tools
    from opnsense_mcp.utils.registry import build_tools
    from opnsense_mcp.utils.tool_groups import build_groups

    class _Client:
        pass

    exposed = build_groups(build_tools(_Client(), extra=build_shaper_tools(_Client())))
    forbidden = {"constructor", "__proto__", "prototype"}
    problems = []
    for name, tool in sorted(exposed.items()):
        props = (getattr(tool, "input_schema", None) or {}).get("properties") or {}
        bad = sorted(forbidden & set(props))
        if bad:
            problems.append(f"{name}: {bad}")
    assert not problems, (
        "exposed tool schemas must not advertise prototype-shadowing keys: "
        + "; ".join(problems)
    )
