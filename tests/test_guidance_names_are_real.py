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
import re
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
    # Exposed names only. Leaf class names are not callable over MCP, and
    # counting them as known let any leaf name pass.
    return set(groups), actions


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


def _surface() -> tuple[set[str], set[str], dict[str, set[str]], list[tuple[str, str]]]:
    """Exposed names, leaf-only names, each group's actions, and caller text.

    Caller text is every description a client can read: each exposed tool's
    description and schema, plus every member's description and schema, which
    a group's `help` action serves.
    """
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
    exposed = set(groups)
    leaves = set(tools) - exposed
    actions = {
        name: set(getattr(group, "members", {})) | {HELP_ACTION}
        for name, group in groups.items()
    }

    def descriptions(node: object) -> list[str]:
        if isinstance(node, dict):
            found = [
                v for k, v in node.items() if k == "description" and isinstance(v, str)
            ]
            for value in node.values():
                found.extend(descriptions(value))
            return found
        if isinstance(node, list):
            return [d for item in node for d in descriptions(item)]
        return []

    text: list[tuple[str, str]] = []
    seen: set[int] = set()
    for owner, tool in [*groups.items(), *tools.items()]:
        if id(tool) in seen:
            continue
        seen.add(id(tool))
        text.append((owner, str(getattr(tool, "description", "") or "")))
        schema = getattr(tool, "input_schema", None) or getattr(
            tool, "inputSchema", None
        )
        text.extend((owner, d) for d in descriptions(schema or {}))
    return exposed, leaves, actions, text


_ACTION_LITERAL = re.compile(r"""action=['"][a-z0-9_]*['"]""")
_APPLIES_TO = re.compile(r"^\[[a-z0-9_, ]+\]\s*")


def test_caller_text_names_no_tool_a_client_cannot_call() -> None:
    """Only group names (and arp, system) are callable over MCP.

    The previous known set included every leaf class name, so "from
    list_gateways" passed although no client can call `list_gateways`. A leaf
    is reached as `group(action=...)`; text naming it bare sends the caller to
    a tool that does not exist.
    """
    exposed, leaves, _, text = _surface()
    # A leaf with an underscore is unmistakably a tool name. One without
    # (`aliases`, `dns`) is also an English word, so it counts only where the
    # text treats it as a tool: in backticks, "the dns tool", "use mkdns".
    snake = sorted((n for n in leaves if "_" in n), key=len, reverse=True)
    words = sorted((n for n in leaves if "_" not in n), key=len, reverse=True)
    snake_re = re.compile(
        r"(?<![A-Za-z0-9_])(" + "|".join(map(re.escape, snake)) + r")(?![A-Za-z0-9_])"
    )
    word_alt = "|".join(map(re.escape, words))
    word_re = re.compile(rf"`({word_alt})`|\b({word_alt}) tool\b|\buse ({word_alt})\b")

    def named(line: str) -> list[str]:
        # Grouped field text opens with the actions it applies to, e.g.
        # "[packet_capture, ping] ...", and those are action names.
        body = _ACTION_LITERAL.sub("", _APPLIES_TO.sub("", line))
        found = snake_re.findall(body)
        found += [g for groups in word_re.findall(body) for g in groups if g]
        return found

    stale = sorted(
        {
            f"{owner}: {name!r} in {line[:70]!r}"
            for owner, line in text
            for name in named(line)
        }
    )
    assert exposed
    assert not stale, "caller text names leaf tools: " + "; ".join(stale)


def test_group_action_offers_name_that_groups_actions() -> None:
    """`dhcp(action='apply')` must be a dhcp action, not just any group's."""
    _, _, actions, _ = _surface()
    pattern = re.compile(r"""\b([a-z][a-z0-9_]*)\(action=['"]([a-z0-9_]+)['"]""")

    stale: list[str] = []
    for path in _tracked_python():
        for literal in _literals(path, skip_docstrings=False):
            for group, action in pattern.findall(literal):
                if group in actions and action not in actions[group]:
                    stale.append(
                        f"{path.relative_to(REPO)}: {group}(action={action!r})"
                    )

    assert not stale, "offers actions the named group lacks: " + ", ".join(
        sorted(set(stale))
    )
