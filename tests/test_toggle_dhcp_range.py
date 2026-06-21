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
