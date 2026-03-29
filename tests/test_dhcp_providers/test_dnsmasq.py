"""Tests for dnsmasq DHCP provider."""

from unittest.mock import AsyncMock

import pytest

from opnsense_mcp.utils.dhcp_providers.dnsmasq import DnsmasqProvider


@pytest.fixture
def make_request() -> AsyncMock:
    """Create mock request callable."""
    return AsyncMock()


@pytest.fixture
def provider(make_request: AsyncMock) -> DnsmasqProvider:
    """Create provider with mocked requests."""
    return DnsmasqProvider(make_request)


def test_name(provider: DnsmasqProvider) -> None:
    assert provider.name == "dnsmasq"


@pytest.mark.asyncio
async def test_get_v4_filters_family(
    provider: DnsmasqProvider, make_request: AsyncMock
) -> None:
    make_request.return_value = {
        "rows": [
            {"ip": "10.0.0.1", "protocol": "ipv4"},
            {"ip": "2001:db8::1", "protocol": "ipv6"},
        ]
    }
    result = await provider.get_v4_leases()
    assert result == [{"ip": "10.0.0.1", "protocol": "ipv4"}]
    make_request.assert_called_once_with("GET", "/api/dnsmasq/leases/search")


@pytest.mark.asyncio
async def test_search_v6(provider: DnsmasqProvider, make_request: AsyncMock) -> None:
    make_request.return_value = {"rows": [{"ip": "2001:db8::1", "protocol": "ipv6"}]}
    result = await provider.search_v6_leases("host")
    assert result == [{"ip": "2001:db8::1", "protocol": "ipv6"}]
    make_request.assert_called_once_with(
        "POST",
        "/api/dnsmasq/leases/search",
        json={"searchPhrase": "host", "current": 1, "rowCount": -1},
    )


@pytest.mark.asyncio
async def test_delete_not_supported(provider: DnsmasqProvider) -> None:
    result = await provider.delete_v6_lease("2001:db8::1")
    assert result["status"] == "error"
    assert "not supported" in result["error"]
