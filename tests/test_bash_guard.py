"""Tests for the PreToolUse Bash guard in .claude/hooks/bash_guard.py.

The guard claims it blocks a specific documented mistake without blocking
legitimate commands. Both halves of that claim get falsification tests here:
commands that must be denied, and commands that look similar but must pass.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from types import ModuleType

GUARD_PATH = (
    Path(__file__).resolve().parent.parent / ".claude" / "hooks" / "bash_guard.py"
)


def load_guard() -> ModuleType:
    """Import the guard from its hook path; .claude/hooks is not a package."""
    spec = importlib.util.spec_from_file_location("bash_guard", GUARD_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guard = load_guard()


def decide(command: str) -> dict:
    """Run the guard as the harness does and return its parsed decision."""
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
    result = subprocess.run(
        [sys.executable, str(GUARD_PATH)],
        input=payload,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    return json.loads(result.stdout) if result.stdout.strip() else {}


def is_denied(command: str) -> bool:
    """Report whether the guard denied the command, by field not by wording."""
    hook_output = decide(command).get("hookSpecificOutput", {})
    return hook_output.get("permissionDecision") == "deny"


DENIED = [
    # The exact command CLAUDE.md records as having pushed broken commits.
    "ruff check . ; git commit -m x && git push",
    "uv run pytest tests/ ; git commit -m x",
    "ruff format . ; git push",
    # A newline separates commands the same way `;` does.
    "ruff check .\ngit push",
    # Other separators that also let a failed gate through.
    "ruff check . & git push",
    "ruff check . || git commit -m x",
    "ruff check . | git commit -m x",
    # The separator is still ungated when it is several commands back.
    "ruff check . ; echo done && git push",
    # Flags between `git` and the subcommand must not hide the publish.
    "ruff check . ; git -c user.name=x commit -m y",
]

ALLOWED = [
    "ruff check . && git commit -m x && git push",
    "uv run pytest tests/ && ruff check . && git commit -m x && git push",
    # A semicolon inside the message is data, not a separator.
    'git commit -m "fix: one thing; then another"',
    # A semicolon only after the publish gates nothing.
    "git commit -m x && git push ; echo done",
    # Unrelated commands with semicolons.
    "ruff check . ; ruff format .",
    "ls -la ; echo done",
    # Words that merely contain a publishing subcommand.
    "ruff check . ; echo committing",
    "ruff check . ; git status",
    "ruff check . ; git log --oneline",
]


@pytest.mark.parametrize("command", DENIED)
def test_ungated_publish_is_denied(command: str) -> None:
    """Every way of reaching a publish past a failed gate is refused."""
    assert is_denied(command)


@pytest.mark.parametrize("command", ALLOWED)
def test_legitimate_command_is_allowed(command: str) -> None:
    """Correctly gated chains and lookalike commands pass through."""
    assert not is_denied(command)


def test_semicolon_inside_heredoc_body_is_not_a_separator() -> None:
    """A heredoc commit message is data; its semicolons must not trigger a deny."""
    command = "git commit -m \"$(\\cat <<'EOF'\nfix: one thing; then another\nEOF\n)\""
    assert not is_denied(command)


def test_ungated_publish_survives_a_heredoc_earlier_in_the_command() -> None:
    """Stripping heredoc bodies must not blind the guard to a real separator."""
    command = "echo \"$(\\cat <<'EOF'\nnotes; here\nEOF\n)\" ; git commit -m x"
    assert is_denied(command)


def test_bare_cat_heredoc_is_denied() -> None:
    """`cat` is aliased to `bat`; a bare-cat heredoc corrupts the commit message."""
    assert is_denied('git commit -m "$(cat <<EOF\nmsg\nEOF\n)"')


def test_escaped_cat_heredoc_is_allowed() -> None:
    """`\\cat` bypasses the alias and is the form CLAUDE.md requires."""
    assert not is_denied('git commit -m "$(\\cat <<EOF\nmsg\nEOF\n)"')


def test_commit_message_may_describe_the_bare_cat_pattern() -> None:
    """A message documenting `$(cat <<...)` is prose in a body, not a command.

    This blocked the guard's own commit: the check ran against the raw command
    instead of the command with heredoc bodies removed.
    """
    command = (
        "git commit -m \"$(\\cat <<'EOF'\n"
        "feat(hooks): guard the shell\n\n"
        "It denies $(cat <<...) in a commit message.\n"
        'EOF\n)"'
    )
    assert not is_denied(command)


def test_commit_message_may_describe_an_ungated_publish() -> None:
    """A message quoting `ruff check . ; git push` must not be read as one."""
    command = (
        "git commit -m \"$(\\cat <<'EOF'\n"
        "docs: never write ruff check . ; git push\n"
        'EOF\n)"'
    )
    assert not is_denied(command)


def test_single_line_message_quoting_a_publish_is_allowed() -> None:
    """Quoted text is one token; a separator inside it separates nothing."""
    assert not is_denied('git commit -m "warn against ruff check . ; git push"')


def test_commit_message_may_mention_the_live_client() -> None:
    """Prose naming get_opnsense_client() must not raise the advisory warning."""
    command = (
        "git commit -m \"$(\\cat <<'EOF'\n"
        "docs: prefer MCP over uv run python with get_opnsense_client\n"
        'EOF\n)"'
    )
    assert decide(command) == {}


def test_live_client_call_warns_without_blocking() -> None:
    """The mcp-first rule is advisory: it surfaces a message but allows the call."""
    command = (
        'uv run python -c "from opnsense_mcp.server import get_opnsense_client; '
        'print(get_opnsense_client())"'
    )
    decision = decide(command)
    assert "hookSpecificOutput" not in decision
    assert decision["systemMessage"]


def test_unparseable_command_is_allowed() -> None:
    """A guard for one mistake must not block commands whose quoting it cannot parse."""
    assert not is_denied('echo "unterminated')


def test_missing_command_field_produces_no_output() -> None:
    """A payload without a Bash command yields no decision at all."""
    result = subprocess.run(
        [sys.executable, str(GUARD_PATH)],
        input=json.dumps({"tool_name": "Read", "tool_input": {"file_path": "x"}}),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == ""


def test_malformed_stdin_produces_no_output() -> None:
    """Invalid JSON on stdin fails open rather than blocking every Bash call."""
    result = subprocess.run(
        [sys.executable, str(GUARD_PATH)],
        input="not json",
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == ""


def test_deny_reason_names_the_separator_and_subcommand() -> None:
    """The refusal has to tell the caller what to rewrite."""
    reason = guard.check_ungated_publish("ruff check . ; git push")
    assert reason is not None
    assert ";" in reason
    assert "push" in reason
