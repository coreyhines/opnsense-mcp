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
        {"rows": []},
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
        {"rows": []},
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
        {"rows": []},
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
        {"rows": []},
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


@pytest.mark.asyncio
async def test_list_subnet_dns_uses_dhcp_range_tag(make_request: AsyncMock) -> None:
    internal_tag = "97f6eab8-edd3-4390-a721-dfe9584c6b73"
    make_request.side_effect = [
        {
            "opt5": {
                "identifier": "opt5",
                "description": "VLAN81wifi",
                "ipaddr": "10.0.8.1",
                "subnet": "24",
            }
        },
        {
            "rows": [
                {
                    "interface": "opt5",
                    "set_tag": internal_tag,
                    "start_addr": "10.0.8.2",
                    "end_addr": "10.0.8.240",
                }
            ]
        },
        {
            "rows": [
                {
                    "uuid": "opt-v4",
                    "interface": "",
                    "tag": internal_tag,
                    "option": "6",
                    "value": "10.0.2.2,10.0.10.46",
                    "force": "1",
                }
            ]
        },
        {"rows": []},
    ]

    provider = DnsmasqProvider(make_request)
    result = await provider.list_subnet_dns(interface="opt5")

    assert result["ipv4"] == ["10.0.2.2", "10.0.10.46"]


@pytest.mark.asyncio
async def test_set_subnet_dns_creates_tagged_option(make_request: AsyncMock) -> None:
    internal_tag = "97f6eab8-edd3-4390-a721-dfe9584c6b73"
    make_request.side_effect = [
        {
            "opt5": {
                "identifier": "opt5",
                "ipaddr": "10.0.8.1",
                "subnet": "24",
            }
        },
        {
            "rows": [
                {
                    "interface": "opt5",
                    "set_tag": internal_tag,
                    "start_addr": "10.0.8.2",
                    "end_addr": "10.0.8.240",
                }
            ]
        },
        {"rows": []},
        {"result": "added"},
        {
            "rows": [
                {
                    "uuid": "new-opt-v4",
                    "interface": "",
                    "tag": internal_tag,
                    "option": "6",
                    "value": "10.0.2.2,10.0.10.46",
                    "force": "1",
                }
            ]
        },
        {"result": "done"},
    ]

    provider = DnsmasqProvider(make_request)
    result = await provider.set_subnet_dns(
        interface="opt5",
        family="ipv4",
        servers=["10.0.2.2", "10.0.10.46"],
    )

    assert result["status"] == "success"
    add_calls = [
        call
        for call in make_request.call_args_list
        if call.args[:2] == ("POST", "/api/dnsmasq/settings/add_option")
    ]
    assert add_calls
    option = add_calls[0].kwargs["json"]["option"]
    assert option["tag"] == internal_tag
    assert option["interface"] == ""
    assert option["force"] == "1"
    assert option["value"] == "10.0.2.2,10.0.10.46"
