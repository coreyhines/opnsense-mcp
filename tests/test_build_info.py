"""Tests for MCP server build metadata."""

from opnsense_mcp import _build_info_generated as generated
from opnsense_mcp.build_info import get_build_info


def test_get_build_info_uses_embedded_metadata(monkeypatch) -> None:
    monkeypatch.setattr(generated, "GIT_COMMIT", "abc123def456")
    monkeypatch.setattr(generated, "GIT_REF", "main")
    monkeypatch.setattr(generated, "BUILD_TIME", "2026-06-07T22:00:00Z")

    info = get_build_info()

    assert info["name"] == "opnsense-mcp"
    assert info["git_commit"] == "abc123def456"
    assert info["git_ref"] == "main"
    assert info["build_time"] == "2026-06-07T22:00:00Z"
    assert info["package_version"] != "unknown"


def test_get_build_info_falls_back_to_runtime_git(monkeypatch) -> None:
    monkeypatch.setattr(generated, "GIT_COMMIT", "unknown")
    monkeypatch.setattr(generated, "GIT_REF", "unknown")
    monkeypatch.setattr(generated, "BUILD_TIME", "unknown")

    info = get_build_info()

    assert len(info["git_commit"]) >= 7
    assert info["git_ref"] != "unknown"
