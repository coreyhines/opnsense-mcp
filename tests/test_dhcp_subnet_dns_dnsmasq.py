"""Tests for dnsmasq subnet DNS provider methods."""

from unittest.mock import AsyncMock

import pytest

from opnsense_mcp.utils.dhcp_providers.dnsmasq import DnsmasqProvider


@pytest.fixture
def make_request() -> AsyncMock:
    """Create a mock request callable."""
    return AsyncMock()


@pytest.mark.asyncio
async def test_list_subnet_dns_reads_scoped_options(make_request: AsyncMock) -> None:
    make_request.side_effect = [
        {
            "opt2": {
                "identifier": "opt2",
                "description": "VLAN2wired",
                "ipaddr": "10.0.2.1",
                "subnet": "24",
            }
        },
        {
            "rows": [
                {
                    "uuid": "opt-v4",
                    "interface": "opt2",
                    "option": "6",
                    "value": "10.0.10.4,10.0.10.5",
                },
                {
                    "uuid": "opt-v6",
                    "interface": "opt2",
                    "option6": "23",
                    "value": "[2601:441:8483:b501::44]",
                },
            ]
        },
        {
            "rows": [
                {
                    "uuid": "opt-v4",
                    "interface": "opt2",
                    "option": "6",
                    "value": "10.0.10.4,10.0.10.5",
                },
                {
                    "uuid": "opt-v6",
                    "interface": "opt2",
                    "option6": "23",
                    "value": "[2601:441:8483:b501::44]",
                },
            ]
        },
    ]

    provider = DnsmasqProvider(make_request)
    result = await provider.list_subnet_dns(interface="opt2")

    assert result["backend"] == "dnsmasq"
    assert result["scope"]["interface"] == "opt2"
    assert result["ipv4"] == ["10.0.10.4", "10.0.10.5"]
    assert result["ipv6"] == ["2601:441:8483:b501::44"]


@pytest.mark.asyncio
async def test_set_subnet_dns_updates_and_reconfigures(make_request: AsyncMock) -> None:
    make_request.side_effect = [
        {"opt2": {"identifier": "opt2", "ipaddr": "10.0.2.1", "subnet": "24"}},
        {
            "rows": [
                {
                    "uuid": "opt-v4",
                    "interface": "opt2",
                    "option": "6",
                    "value": "10.0.10.5",
                }
            ]
        },
        {"uuid": "opt-v4", "interface": "opt2", "option": "6", "value": "10.0.10.5"},
        {"result": "saved"},
        {"result": "done"},
    ]

    provider = DnsmasqProvider(make_request)
    result = await provider.set_subnet_dns(
        interface="opt2",
        family="ipv4",
        servers=["10.0.10.4"],
    )

    assert result["status"] == "success"
    assert result["before"] == ["10.0.10.5"]
    assert result["after"] == ["10.0.10.4"]
    set_calls = [
        call
        for call in make_request.call_args_list
        if call.args[:2] == ("POST", "/api/dnsmasq/settings/set_option/opt-v4")
    ]
    assert set_calls
    assert set_calls[0].kwargs["json"]["option"]["value"] == "10.0.10.4"


@pytest.mark.asyncio
async def test_set_subnet_dns_rolls_back_on_reconfigure_failure(
    make_request: AsyncMock,
) -> None:
    make_request.side_effect = [
        {"opt2": {"identifier": "opt2", "ipaddr": "10.0.2.1", "subnet": "24"}},
        {
            "rows": [
                {
                    "uuid": "opt-v4",
                    "interface": "opt2",
                    "option": "6",
                    "value": "10.0.10.5",
                }
            ]
        },
        {"result": "saved"},
        RuntimeError("reconfigure failed"),
        {"result": "saved"},
        {"result": "done"},
    ]

    provider = DnsmasqProvider(make_request)
    result = await provider.set_subnet_dns(
        interface="opt2",
        family="ipv4",
        servers=["10.0.10.4"],
    )

    assert result["status"] == "error"
    assert result["restored"] is True
    assert result["before"] == ["10.0.10.5"]
