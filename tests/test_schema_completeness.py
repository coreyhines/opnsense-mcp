"""Every key ``execute`` reads from ``params`` must be in ``input_schema``.

``GroupedTool._build_schema`` advertises the MCP surface from each member's
``input_schema.properties``. A field that ``execute`` reads but the schema does
not declare is unreachable for a strict client: that is how
``MkLoopbackTool``'s track6 refusal shipped and could never be reached (D4).

This walks the registry the same way ``test_guidance_names_are_real.py`` does,
then statically inspects each leaf tool's ``execute`` body. It does not call
the tools.
"""

from __future__ import annotations

import ast
import inspect
import pathlib
from typing import Any

REPO = pathlib.Path(__file__).resolve().parent.parent

# Narrow allowlist for reads that pre-date this check and live outside B3's
# owned files. Each entry is (tool.name, param_key) with a reason. Do not grow
# this to paper over a new tool that forgot its schema — fix the schema.
_ALLOWLIST: frozenset[tuple[str, str]] = frozenset(
    {
        # Optional filter used by execute; schema never declared it. Not B3.
        ("arp", "ipv6"),
        # Optional logical-name resolve; schema is empty. Not B3.
        ("interface_list", "resolve"),
        # Capture mode (text/raw); schema never declared it. Not B3.
        ("packet_capture", "mode"),
        # Delete paths honour apply but omit it from schema. Not B3.
        ("delete_shaper_queue", "apply"),
        ("delete_shaper_rule", "apply"),
        # Internal selector; schema is empty and the tool is ungrouped. Not B3.
        ("system", "action"),
    }
)


def _leaf_tools() -> list[Any]:
    """Every registered leaf tool (group members and ungrouped tools)."""
    from opnsense_mcp.fastmcp_server import build_shaper_tools
    from opnsense_mcp.utils.grouped_tool import GroupedTool
    from opnsense_mcp.utils.mock_api import MockOPNsenseClient
    from opnsense_mcp.utils.registry import build_tools
    from opnsense_mcp.utils.tool_groups import build_groups

    client = MockOPNsenseClient(
        {"development": {"mock_data_path": str(REPO / "examples" / "mock_data")}}
    )
    tools = build_tools(client, extra=build_shaper_tools(client))
    groups = build_groups(tools)

    leaves: dict[int, Any] = {}
    for group in groups.values():
        if isinstance(group, GroupedTool):
            for member in group.members.values():
                leaves[id(member)] = member
        else:
            leaves[id(group)] = group
    for tool in tools.values():
        if isinstance(tool, GroupedTool):
            continue
        leaves.setdefault(id(tool), tool)
    return list(leaves.values())


def _param_keys_read(execute_node: ast.AST) -> set[str]:
    """Literal keys taken from ``params`` via ``.get``, subscript, or ``in``."""
    keys: set[str] = set()
    for node in ast.walk(execute_node):
        if isinstance(node, ast.Call):
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "get"
                and isinstance(func.value, ast.Name)
                and func.value.id == "params"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                keys.add(node.args[0].value)
        elif isinstance(node, ast.Subscript):
            if (
                isinstance(node.value, ast.Name)
                and node.value.id == "params"
                and isinstance(node.slice, ast.Constant)
                and isinstance(node.slice.value, str)
            ):
                keys.add(node.slice.value)
        elif isinstance(node, ast.Compare):
            # ``"resolve" in params`` — a string constant membership test.
            if (
                isinstance(node.left, ast.Constant)
                and isinstance(node.left.value, str)
                and len(node.ops) == 1
                and isinstance(node.ops[0], ast.In)
                and len(node.comparators) == 1
                and isinstance(node.comparators[0], ast.Name)
                and node.comparators[0].id == "params"
            ):
                keys.add(node.left.value)
    return keys


def _execute_ast(tool: object) -> ast.AST | None:
    """Return the ``execute`` method AST for ``tool``'s class, if found."""
    cls = type(tool)
    try:
        source_path = pathlib.Path(inspect.getsourcefile(cls) or "").resolve()
    except TypeError:
        return None
    if not source_path.is_file():
        return None
    try:
        tree = ast.parse(source_path.read_text())
    except (OSError, SyntaxError, UnicodeDecodeError):
        return None
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or node.name != cls.__name__:
            continue
        for item in node.body:
            if (
                isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                and item.name == "execute"
            ):
                return item
    return None


def test_every_params_key_execute_reads_is_in_input_schema() -> None:
    """Fail when execute reads a key its own input_schema does not declare."""
    stale: list[str] = []
    for tool in _leaf_tools():
        name = getattr(tool, "name", type(tool).__name__)
        schema = getattr(tool, "input_schema", {}) or {}
        declared = set(schema.get("properties") or {})
        execute = _execute_ast(tool)
        if execute is None:
            continue
        for key in sorted(_param_keys_read(execute) - declared):
            if (name, key) in _ALLOWLIST:
                continue
            stale.append(f"{name}: reads {key!r} but input_schema omits it")

    assert not stale, (
        "execute reads params keys missing from input_schema "
        "(declare them, or add a narrow allowlist entry with a reason): "
        + "; ".join(stale)
    )
