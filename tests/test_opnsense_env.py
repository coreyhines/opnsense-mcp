"""Tests for opnsense_mcp.utils.env.load_opnsense_env."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

from opnsense_mcp.utils import env as env_module

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def clear_opnsense_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove keys so tests see only loaded files."""
    for key in list(os.environ):
        if key.startswith("OPNSENSE_") or key in ("MCP_SECRET_KEY",):
            monkeypatch.delenv(key, raising=False)


def test_load_opnsense_env_deploy_overrides_home(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    clear_opnsense_env_vars: None,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("OPNSENSE_MCP_INSTALL_ROOT", str(tmp_path))
    deploy = tmp_path / "environment"
    deploy.write_text("OPNSENSE_FIREWALL_HOST=from_deploy\n", encoding="utf-8")
    (tmp_path / ".opnsense-env").write_text(
        "OPNSENSE_FIREWALL_HOST=from_home\n", encoding="utf-8"
    )
    env_module.load_opnsense_env()
    assert os.environ.get("OPNSENSE_FIREWALL_HOST") == "from_deploy"


def test_load_opnsense_env_home_when_no_deploy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    clear_opnsense_env_vars: None,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("OPNSENSE_MCP_INSTALL_ROOT", str(tmp_path))
    (tmp_path / ".opnsense-env").write_text(
        "OPNSENSE_FIREWALL_HOST=from_home\n", encoding="utf-8"
    )
    env_module.load_opnsense_env()
    assert os.environ.get("OPNSENSE_FIREWALL_HOST") == "from_home"


def test_load_opnsense_env_file_overrides_deploy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    clear_opnsense_env_vars: None,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("OPNSENSE_MCP_INSTALL_ROOT", str(tmp_path))
    deploy = tmp_path / "environment"
    deploy.write_text("OPNSENSE_FIREWALL_HOST=deploy\n", encoding="utf-8")
    extra = tmp_path / "extra.env"
    extra.write_text("OPNSENSE_FIREWALL_HOST=extra\n", encoding="utf-8")
    monkeypatch.setenv("OPNSENSE_ENV_FILE", str(extra))
    env_module.load_opnsense_env()
    assert os.environ.get("OPNSENSE_FIREWALL_HOST") == "extra"


def test_load_opnsense_env_home_fills_missing_after_deploy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    clear_opnsense_env_vars: None,
) -> None:
    """Home files use override=False so they do not replace deploy keys."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("OPNSENSE_MCP_INSTALL_ROOT", str(tmp_path))
    deploy = tmp_path / "environment"
    deploy.write_text("OPNSENSE_FIREWALL_HOST=deploy\n", encoding="utf-8")
    (tmp_path / ".opnsense-env").write_text(
        "OPNSENSE_FIREWALL_HOST=home\nMCP_SECRET_KEY=from_home\n", encoding="utf-8"
    )
    env_module.load_opnsense_env()
    assert os.environ.get("OPNSENSE_FIREWALL_HOST") == "deploy"
    assert os.environ.get("MCP_SECRET_KEY") == "from_home"
