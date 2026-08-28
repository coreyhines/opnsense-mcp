"""Guidance strings must only name tools and actions the registry exposes.

`tests/test_review_wave4.py` walks tracked markdown for tool names the registry
does not know. Two stale names survived that sweep because they live in Python
string literals rather than in documentation: `apply_firewall_changes()`, a
client method offered to callers as though it were a tool, and
`action='diagnose'`, which was never a diagnostics action.

Guidance an agent reads before acting is part of the contract, so it gets the
same check the documents get.
"""

from __future__ import annotations

import ast
import pathlib
import subprocess

REPO = pathlib.Path(__file__).resolve().parent.parent
PACKAGE = REPO / "opnsense_mcp"


def _exposed() -> tuple[set[str], dict[str, set[str]]]:
    """Every registered tool name, and each group's action names."""
    from opnsense_mcp.fastmcp_server import build_shaper_tools
    from opnsense_mcp.utils.grouped_tool import HELP_ACTION
    from opnsense_mcp.utils.mock_api import MockOPNsenseClient
    from opnsense_mcp.utils.registry import build_tools
    from opnsense_mcp.utils.tool_groups import build_groups

    client = MockOPNsenseClient(
        {"development": {"mock_data_path": str(REPO / "examples" / "mock_data")}}
    )
    tools = build_tools(client, extra=build_shaper_tools(client))
    groups = build_groups(tools)
    actions = {
        name: set(getattr(group, "members", {})) | {HELP_ACTION}
        for name, group in groups.items()
    }
    return set(tools) | set(groups), actions


def _tracked_python() -> list[pathlib.Path]:
    """Python files git tracks under the package."""
    out = subprocess.run(
        ["git", "-C", str(REPO), "ls-files", "opnsense_mcp/*.py"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    return [REPO / line for line in out.splitlines() if line.strip()]


def _literals(path: pathlib.Path, *, skip_docstrings: bool) -> list[str]:
    """String constants in a module, optionally excluding docstrings.

    One parse, one tree. An earlier version parsed twice and matched nodes by
    `id()` across the two, which cannot work: the first tree is freed before
    the second is walked, so CPython reuses the addresses and the comparison
    silently succeeds or fails by luck.
    """
    try:
        tree = ast.parse(path.read_text())
    except (SyntaxError, UnicodeDecodeError, OSError):
        return []

    docstrings: set[int] = set()
    if skip_docstrings:
        for node in ast.walk(tree):
            if isinstance(
                node,
                (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                first = (node.body or [None])[0]
                if (
                    isinstance(first, ast.Expr)
                    and isinstance(first.value, ast.Constant)
                    and isinstance(first.value.value, str)
                ):
                    docstrings.add(id(first.value))

    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    ]


def test_no_guidance_string_names_an_action_that_does_not_exist() -> None:
    """`action='x'` inside a guidance string must be a real action somewhere."""
    import re

    _, actions = _exposed()
    every_action = set().union(*actions.values()) if actions else set()
    pattern = re.compile(r"""action=['"]([a-z_][a-z0-9_]*)['"]""")

    stale: list[str] = []
    for path in _tracked_python():
        for literal in _literals(path, skip_docstrings=False):
            for name in pattern.findall(literal):
                if name not in every_action:
                    stale.append(f"{path.relative_to(REPO)}: action={name!r}")

    assert not stale, "guidance names actions no group exposes: " + ", ".join(
        sorted(set(stale))
    )


def test_no_guidance_string_offers_a_call_that_is_not_a_tool() -> None:
    """Guidance telling a caller to invoke `something()` must name a real tool.

    `apply_firewall_changes()` was offered to callers for as long as the note
    existed; it is a method on OPNsenseClient and was never reachable over MCP.

    Scoped to imperative offers in runtime strings. Docstrings and comments
    naming internal or PHP helpers (`write_config()`, `interface_configure()`)
    are explaining machinery to a maintainer, not directing a caller, and are
    not this defect. Widening this to every call-shaped name in every literal
    turns it into an allowlist that grows with each new private helper -- the
    failure mode `_NOT_TOOLS` already demonstrates next door.
    """
    import re

    known, _ = _exposed()
    pattern = re.compile(
        r"\b(?:use|call|run|invoke|try)\s+`?([a-z][a-z0-9]*(?:_[a-z0-9]+)+)`?\(\)",
        re.IGNORECASE,
    )

    stale: list[str] = []
    for path in _tracked_python():
        for literal in _literals(path, skip_docstrings=True):
            for name in pattern.findall(literal):
                if name not in known:
                    stale.append(f"{path.relative_to(REPO)}: {name}()")

    assert not stale, (
        "guidance offers calls that are not registered tools "
        "(name the tool and action instead): " + ", ".join(sorted(set(stale)))
    )
