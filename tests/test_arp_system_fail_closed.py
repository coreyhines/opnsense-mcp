"""ARP fails closed (#87) and system diagnose_mcp changes nothing (#93)."""

from __future__ import annotations

import subprocess
import sys
from typing import Any

import pytest

from opnsense_mcp.tools.arp import ARPTool
from opnsense_mcp.tools.system import SystemTool


class _BrokenClient:
    """Every table call fails the way a dead API does."""

    async def get_arp_table(self) -> list[dict[str, Any]]:
        raise ConnectionError("firewall unreachable")

    async def get_ndp_table(self) -> list[dict[str, Any]]:
        raise ConnectionError("firewall unreachable")

    async def search_arp_table(self, query: str) -> list[dict[str, Any]]:
        raise ConnectionError("firewall unreachable")

    async def search_ndp_table(self, query: str) -> list[dict[str, Any]]:
        raise ConnectionError("firewall unreachable")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "params", [{}, {"search": "*"}, {"search": "printer"}, {"ip": "192.0.2.1"}]
)
async def test_arp_reports_error_with_no_rows_when_the_api_fails(
    params: dict[str, Any],
) -> None:
    """A failed lookup used to return a fabricated neighbour as success."""
    result = await ARPTool(_BrokenClient()).execute(params)

    assert result["status"] == "error"
    assert "arp" not in result
    assert "ndp" not in result


@pytest.mark.asyncio
async def test_arp_reports_error_with_no_rows_when_there_is_no_client() -> None:
    """No client is a lookup that did not run, not an empty or sample table."""
    result = await ARPTool(None).execute({})

    assert result["status"] == "error"
    assert "arp" not in result
    assert "ndp" not in result


def test_arp_has_no_dummy_data_path() -> None:
    """The fabricated table is gone, not just unreachable from execute."""
    assert not hasattr(ARPTool, "_get_dummy_data")


@pytest.fixture
def diagnose_worst_case(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> list[list[str]]:
    """Every condition that used to trigger an auto-correction, recorded.

    The server looks down, there is no .venv, and paramiko will not import.
    Before #93 each of these ran a mutating command.
    """
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], *args: Any, **kwargs: Any) -> Any:
        calls.append(list(cmd))
        return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setitem(sys.modules, "paramiko", None)
    return calls


@pytest.mark.asyncio
async def test_diagnose_mcp_runs_only_pgrep(
    diagnose_worst_case: list[list[str]], tmp_path: Any
) -> None:
    """No restart, venv or pip, even when every check fails."""
    result = await SystemTool(None).execute({"action": "diagnose_mcp"})

    assert [cmd[0] for cmd in diagnose_worst_case] == ["pgrep"]
    assert not (tmp_path / ".venv").exists()
    assert result["status"] == "needs_attention"
    assert "auto_corrections" not in result
    assert len(result["issues"]) == 4
    assert len(result["solutions"]) == 4


def test_system_schema_declares_action() -> None:
    """A strict client can only reach diagnose_mcp if the schema offers it."""
    action = SystemTool.input_schema["properties"]["action"]
    assert set(action["enum"]) == {"status", "diagnose_mcp"}
