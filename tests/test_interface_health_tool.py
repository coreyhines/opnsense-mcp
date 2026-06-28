"""Tests for the interface_health tool."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from opnsense_mcp.tools.interface_health import InterfaceHealthTool

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "phase0-diagnostics"


class FakeClient:
    """Minimal client for InterfaceListTool-backed tests."""

    def __init__(self, interfaces: dict[str, Any]) -> None:
        """Store interface overview rows."""
        self.interfaces = interfaces

    async def _make_request(self, method: str, endpoint: str) -> dict[str, Any]:
        """Return interface overview export data."""
        assert method == "GET"
        assert endpoint == "/api/interfaces/overview/export"
        return self.interfaces

    async def get_interfaces(self) -> list[dict[str, Any]]:
        """No ARP/NDP supplement required for these tests."""
        return []


def load_interfaces() -> dict[str, Any]:
    """Load representative live-shaped interface rows."""
    return json.loads((FIXTURE_DIR / "interface_list_sample.json").read_text())


@pytest.mark.asyncio
async def test_interface_health_warnings_only_compact_output() -> None:
    """Warnings-only returns warning rows without raw payload by default."""
    result = await InterfaceHealthTool(FakeClient(load_interfaces())).execute(
        {"warnings_only": True}
    )

    assert result["status"] == "success"
    assert result["interfaces"]
    assert all(row["health"] in {"warning", "critical"} for row in result["interfaces"])
    assert all("raw" not in row for row in result["interfaces"])
    assert result["summary"]["warning"] >= 1


@pytest.mark.asyncio
async def test_interface_filter_and_include_raw() -> None:
    """Interface filter matches descriptions and can include raw data."""
    result = await InterfaceHealthTool(FakeClient(load_interfaces())).execute(
        {"interface": "WAN", "include_raw": True}
    )

    assert result["total"] == 1
    assert result["interfaces"][0]["name"] == "ax1"
    assert result["interfaces"][0]["raw"]["description"] == "WAN"


@pytest.mark.asyncio
async def test_max_results_clamps_and_truncates() -> None:
    """max_results bounds output and reports truncation."""
    result = await InterfaceHealthTool(FakeClient(load_interfaces())).execute(
        {"max_results": 1}
    )

    assert len(result["interfaces"]) == 1
    assert result["truncated"] is True
    assert result["max_results"] == 1


@pytest.mark.asyncio
async def test_no_client_returns_error() -> None:
    """Missing client returns a stable error envelope."""
    result = await InterfaceHealthTool(None).execute({})

    assert result["status"] == "error"
    assert result["interfaces"] == []
