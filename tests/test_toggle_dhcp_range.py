"""Tests for dnsmasq DHCP range toggle."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from opnsense_mcp.utils.dhcp_providers.dnsmasq import DnsmasqProvider


@pytest.mark.asyncio
async def test_toggle_range_dry_run() -> None:
    make_request = AsyncMock(
        side_effect=[
            {"rows": [{"uuid": "r1", "interface": "opt10", "disabled": "0", "start_addr": "10.0.5.100", "end_addr": "10.0.5.200"}]},
            {"range": {"uuid": "r1", "interface": "opt10", "disabled": "0", "start_addr": "10.0.5.100", "end_addr": "10.0.5.200", "domain": "lan"}},
        ]
    )
    provider = DnsmasqProvider(make_request)
    result = await provider.toggle_range(
        enabled=False,
        uuid="r1",
        dry_run=True,
    )
    assert result["status"] == "dry_run"
    assert result["planned"]["enabled"] is False


@pytest.mark.asyncio
async def test_toggle_range_noop_when_already_disabled() -> None:
    make_request = AsyncMock(
        return_value={"rows": [{"uuid": "r1", "interface": "opt10", "disabled": "1"}]}
    )
    provider = DnsmasqProvider(make_request)
    result = await provider.toggle_range(enabled=False, uuid="r1", dry_run=False)
    assert result["status"] == "noop"


@pytest.mark.asyncio
async def test_toggle_range_apply_success() -> None:
    """Apply path: set_range and reconfigure are called when dry_run=False."""
    make_request = AsyncMock(
        side_effect=[
            {"rows": [{"uuid": "r1", "interface": "opt10", "disabled": "0", "start_addr": "10.0.5.100", "end_addr": "10.0.5.200"}]},
            {"range": {"uuid": "r1", "interface": "opt10", "disabled": "0", "start_addr": "10.0.5.100", "end_addr": "10.0.5.200", "domain": ""}},
            {"result": "saved"},
            {},
        ]
    )
    provider = DnsmasqProvider(make_request)
    result = await provider.toggle_range(enabled=False, uuid="r1", dry_run=False)
    assert result["status"] == "success"
    assert result["enabled"] is False
    assert result["applied"] is True
    assert make_request.call_count == 4


@pytest.mark.asyncio
async def test_toggle_range_not_found() -> None:
    """Unknown uuid returns an error without modifying state."""
    make_request = AsyncMock(return_value={"rows": []})
    provider = DnsmasqProvider(make_request)
    result = await provider.toggle_range(enabled=True, uuid="missing-uuid", dry_run=False)
    assert result["status"] == "error"
    assert "No matching DHCP range" in result["error"]


@pytest.mark.asyncio
async def test_toggle_range_interface_scope() -> None:
    """Range lookup via interface name resolves through the overview export."""
    make_request = AsyncMock(
        side_effect=[
            {"opt10": {"identifier": "opt10"}},
            {"rows": [{"uuid": "r1", "interface": "opt10", "disabled": "1", "start_addr": "10.0.5.100", "end_addr": "10.0.5.200"}]},
            {"range": {"uuid": "r1", "interface": "opt10", "disabled": "1", "start_addr": "10.0.5.100", "end_addr": "10.0.5.200", "domain": ""}},
        ]
    )
    provider = DnsmasqProvider(make_request)
    result = await provider.toggle_range(enabled=True, interface="opt10", dry_run=True)
    assert result["status"] == "dry_run"
    assert result["planned"]["enabled"] is True
    assert result["planned"]["interface"] == "opt10"
