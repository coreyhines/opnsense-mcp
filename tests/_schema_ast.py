"""Shared AST helpers for checks that compare ``execute`` bodies to schemas.

``test_schema_completeness.py`` (every ``params`` key ``execute`` reads must be
declared in ``input_schema``) and ``test_surface_consistency.py`` (every
``apply`` field states its default, including when the schema omits ``apply``
entirely) both need to know which literal keys an ``execute`` method reads
from ``params``. Kept here so there is exactly one AST walker for that
question instead of two that could drift apart.
"""

from __future__ import annotations

import ast
import inspect
import pathlib
from typing import Any

REPO = pathlib.Path(__file__).resolve().parent.parent


def leaf_tools(repo: pathlib.Path = REPO) -> list[Any]:
    """Every registered leaf tool (group members and ungrouped tools)."""
    from opnsense_mcp.fastmcp_server import build_shaper_tools
    from opnsense_mcp.utils.grouped_tool import GroupedTool
    from opnsense_mcp.utils.mock_api import MockOPNsenseClient
    from opnsense_mcp.utils.registry import build_tools
    from opnsense_mcp.utils.tool_groups import build_groups

    client = MockOPNsenseClient(
        {"development": {"mock_data_path": str(repo / "examples" / "mock_data")}}
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


def param_keys_read(execute_node: ast.AST) -> set[str]:
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


def execute_ast(tool: object) -> ast.AST | None:
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
