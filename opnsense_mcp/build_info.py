"""OPNsense MCP server build and package metadata."""

from __future__ import annotations

import subprocess  # nosec B404 — subprocess required for local git metadata fallback
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from opnsense_mcp import _build_info_generated as _generated


def _package_version() -> str:
    try:
        return version("opnsense-mcp")
    except PackageNotFoundError:
        return "unknown"


def _runtime_git_commit() -> str | None:
    """Best-effort short HEAD for local/dev runs without embedded build metadata."""
    repo_root = Path(__file__).resolve().parent.parent
    if not (repo_root / ".git").is_dir():
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "--short=12", "HEAD"],
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        )  # nosec B603 B607 — hardcoded git command, no user input
    except (OSError, subprocess.SubprocessError):
        return None
    commit = result.stdout.strip()
    return commit or None


def _runtime_git_ref() -> str | None:
    repo_root = Path(__file__).resolve().parent.parent
    if not (repo_root / ".git").is_dir():
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        )  # nosec B603 B607 — hardcoded git command, no user input
    except (OSError, subprocess.SubprocessError):
        return None
    ref = result.stdout.strip()
    return ref or None


def get_build_info() -> dict[str, str]:
    """Return package and build metadata for the running MCP server."""
    git_commit = _generated.GIT_COMMIT
    git_ref = _generated.GIT_REF
    build_time = _generated.BUILD_TIME

    if git_commit == "unknown":
        runtime_commit = _runtime_git_commit()
        if runtime_commit:
            git_commit = runtime_commit
    if git_ref == "unknown":
        runtime_ref = _runtime_git_ref()
        if runtime_ref:
            git_ref = runtime_ref

    return {
        "name": "opnsense-mcp",
        "package_version": _package_version(),
        "git_commit": git_commit,
        "git_ref": git_ref,
        "build_time": build_time,
    }
