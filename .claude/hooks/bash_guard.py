#!/usr/bin/env python3
"""PreToolUse guard for Bash commands, enforcing rules this repo already paid for.

Each check here corresponds to an entry in CLAUDE.md's "Failure modes this
project has already paid for". That section's own thesis is that intending to
avoid a mistake did not work and the checks did; this script is the check for
the three failure modes that are shell-shaped.

Reads the PreToolUse hook payload on stdin and writes a permission decision to
stdout. Exits 0 in every case: a deny is expressed in the JSON body, not the
exit status.
"""

from __future__ import annotations

import json
import re
import shlex
import sys

HEREDOC_OPEN = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
BARE_CAT_HEREDOC = re.compile(r"\$\(\s*cat\s*<<")
LIVE_CLIENT_CALL = re.compile(r"uv\s+run\s+python.*get_opnsense_client", re.DOTALL)

# Separator tokens that, unlike `&&`, let a failed gate through to the next
# command. shlex with punctuation_chars=True emits these as standalone tokens.
UNGATED_SEPARATORS = {";", "&", "|", "||"}

PUBLISHING_GIT_SUBCOMMANDS = {"commit", "push"}


def _rewrite_heredocs(command: str, *, keep_opener: bool) -> str:
    """Remove heredoc bodies, optionally keeping the `<<DELIM` operator.

    Heredoc bodies are data, not shell syntax: a commit message that contains a
    semicolon, or that quotes a forbidden command, must not be read as the shell
    reading it. Every check here therefore runs against the command with bodies
    removed.

    Separator analysis drops the operator too, which leaves the surrounding
    quoting balanced for the tokenizer. Checks that inspect the command's own
    text keep the operator, since `<<DELIM` is part of the command.
    """
    out = command
    search_from = 0
    while True:
        opener = HEREDOC_OPEN.search(out, search_from)
        if opener is None:
            return out
        delimiter = opener.group(2)
        keep_upto = opener.end() if keep_opener else opener.start()
        line_end = out.find("\n", opener.end())
        if line_end == -1:
            out = out[:keep_upto] + " " + out[opener.end() :]
        else:
            terminator = re.compile(rf"^\s*{re.escape(delimiter)}\s*$", re.MULTILINE)
            match = terminator.search(out, line_end + 1)
            body_end = match.end() if match else len(out)
            out = out[:keep_upto] + " " + out[body_end:]
        # Keeping the opener means it would match again; resume past it.
        search_from = keep_upto if keep_opener else 0


def strip_heredocs(command: str) -> str:
    """Remove heredoc operators and their bodies, for separator analysis."""
    return _rewrite_heredocs(command, keep_opener=False)


def strip_heredoc_bodies(command: str) -> str:
    """Remove heredoc bodies but keep the `<<DELIM` operators, for text checks."""
    return _rewrite_heredocs(command, keep_opener=True)


def tokenize(command: str) -> list[str] | None:
    """Split a command into tokens, keeping operators separate from words.

    Returns None when the command cannot be parsed. Callers treat that as
    "no opinion": a guard for one specific mistake must not block every command
    whose quoting it fails to understand.
    """
    lexer = shlex.shlex(command, punctuation_chars=True, posix=True)
    lexer.whitespace_split = True
    try:
        return list(lexer)
    except ValueError:
        return None


def find_ungated_publish(tokens: list[str]) -> tuple[str, str] | None:
    """Find a git commit/push reached through a separator that ignores failure.

    Returns (separator, subcommand) for the first such publish, or None.
    `ruff check . ; git commit` reports (";", "commit") because the commit runs
    whether or not ruff passed.

    An ungated separator is never cleared by a later `&&`: in
    `ruff check . ; echo done && git push` the `&&` only gates the push on
    `echo`, so the push still runs when ruff fails.
    """
    separator: str | None = None
    for index, token in enumerate(tokens):
        if token in UNGATED_SEPARATORS and separator is None:
            separator = token
            continue
        if token != "git" or separator is None:
            continue
        for following in tokens[index + 1 :]:
            if following in UNGATED_SEPARATORS or following == "&&":
                break
            if following in PUBLISHING_GIT_SUBCOMMANDS:
                return separator, following
    return None


def check_ungated_publish(command: str) -> str | None:
    """Reject `git commit`/`git push` chained after a separator that isn't `&&`."""
    # A newline separates commands exactly as `;` does. Heredoc bodies are gone
    # by this point, so every remaining newline is a real separator.
    tokens = tokenize(strip_heredocs(command).replace("\n", " ; "))
    if tokens is None:
        return None
    found = find_ungated_publish(tokens)
    if found is None:
        return None
    separator, subcommand = found
    return (
        f"This chains `git {subcommand}` after `{separator}`, so it runs even if "
        f'the preceding command failed. CLAUDE.md: "Never chain a gate with `;`... '
        f"Use `&&` throughout. This pushed broken commits three times in one "
        f'session." Rewrite the chain with `&&`.'
    )


def check_bare_cat_heredoc(command: str) -> str | None:
    """Reject `$(cat <<...)` in commit messages; `cat` is aliased to `bat` here."""
    if not BARE_CAT_HEREDOC.search(strip_heredoc_bodies(command)):
        return None
    return (
        "This uses bare `cat` in a heredoc. `cat` is aliased to `bat` in this "
        "shell, which wraps the text in ANSI escape sequences that get stored "
        "literally. CLAUDE.md requires `\\cat` (backslash bypasses the alias)."
    )


def check_live_client_call(command: str) -> str | None:
    """Warn when a workspace script bypasses the MCP protocol path."""
    if not LIVE_CLIENT_CALL.search(strip_heredoc_bodies(command)):
        return None
    return (
        "This calls get_opnsense_client() from workspace Python, bypassing the "
        "MCP protocol path. .cursor/rules/mcp-first.mdc prefers MCP tools against "
        "the deployed server for live changes. Say why if falling back."
    )


BLOCKING_CHECKS = (check_ungated_publish, check_bare_cat_heredoc)
ADVISORY_CHECKS = (check_live_client_call,)


def main() -> int:
    """Read the hook payload, run the checks, emit a permission decision."""
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0

    command = payload.get("tool_input", {}).get("command")
    if not isinstance(command, str) or not command:
        return 0

    for check in BLOCKING_CHECKS:
        reason = check(command)
        if reason is not None:
            json.dump(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": reason,
                    }
                },
                sys.stdout,
            )
            return 0

    warnings = [reason for check in ADVISORY_CHECKS if (reason := check(command))]
    if warnings:
        json.dump({"systemMessage": " ".join(warnings)}, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
