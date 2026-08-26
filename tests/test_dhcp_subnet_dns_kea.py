"""Tests for Kea subnet DNS provider methods."""

from unittest.mock import AsyncMock

import pytest

from opnsense_mcp.utils.dhcp_providers.kea import KeaProvider


@pytest.fixture
def make_request() -> AsyncMock:
    """Create a mock request callable."""
    return AsyncMock()


@pytest.mark.asyncio
async def test_list_subnet_dns_reads_subnet_option_data(
    make_request: AsyncMock,
) -> None:
    subnet_payload = {
        "uuid": "subnet-v4",
        "subnet": "172.20.2.0/24",
        "interface": "opt2",
        "option_data_autocollect": "1",
        "option_data": {
            "domain_name_servers": {"value": "172.20.10.4,172.20.10.5", "selected": 1}
        },
    }
    make_request.side_effect = [
        {
            "rows": [
                {"uuid": "subnet-v4", "subnet": "172.20.2.0/24", "interface": "opt2"}
            ]
        },
        {"subnet4": dict(subnet_payload)},
        {"rows": []},
    ]

    provider = KeaProvider(make_request)
    result = await provider.list_subnet_dns(subnet="172.20.2.0/24")

    assert result["backend"] == "kea"
    assert result["ipv4"] == ["172.20.10.4", "172.20.10.5"]
    assert result["ipv6"] == []


@pytest.mark.asyncio
async def test_set_subnet_dns_disables_autocollect(make_request: AsyncMock) -> None:
    subnet_payload = {
        "uuid": "subnet-v4",
        "subnet": "172.20.2.0/24",
        "interface": "opt2",
        "option_data_autocollect": "1",
        "option_data": {"domain_name_servers": {"value": "172.20.10.5", "selected": 1}},
    }
    make_request.side_effect = [
        {
            "rows": [
                {"uuid": "subnet-v4", "subnet": "172.20.2.0/24", "interface": "opt2"}
            ]
        },
        {"subnet4": dict(subnet_payload)},
        {"result": "saved"},
        {"result": "done"},
    ]

    provider = KeaProvider(make_request)
    result = await provider.set_subnet_dns(
        subnet="172.20.2.0/24",
        family="ipv4",
        servers=["172.20.10.4"],
    )

    assert result["status"] == "success"
    set_calls = [
        call
        for call in make_request.call_args_list
        if call.args[:2] == ("POST", "/api/kea/dhcpv4/set_subnet/subnet-v4")
    ]
    assert set_calls
    payload = set_calls[0].kwargs["json"]["subnet4"]
    assert payload["option_data_autocollect"] == "0"
    assert payload["option_data"]["domain_name_servers"]["value"] == "172.20.10.4"
