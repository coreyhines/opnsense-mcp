"""Tests for ISC DHCP provider."""

from unittest.mock import AsyncMock

import pytest

from opnsense_mcp.utils.dhcp_providers.isc import ISCProvider


@pytest.fixture
def make_request() -> AsyncMock:
    """Create mock request callable."""
    return AsyncMock()


@pytest.fixture
def provider(make_request: AsyncMock) -> ISCProvider:
    """Create provider with mocked requests."""
    return ISCProvider(make_request)


@pytest.mark.asyncio
async def test_get_v4_rows(provider: ISCProvider, make_request: AsyncMock) -> None:
    make_request.return_value = {"rows": [{"ip": "10.0.0.1"}]}
    result = await provider.get_v4_leases()
    assert result == [{"ip": "10.0.0.1"}]
    make_request.assert_called_once_with("GET", "/api/dhcpv4/leases/search_lease")


@pytest.mark.asyncio
async def test_search_v6(provider: ISCProvider, make_request: AsyncMock) -> None:
    make_request.return_value = {"leases": [{"ip": "2001:db8::1"}]}
    result = await provider.search_v6_leases("host")
    assert result == [{"ip": "2001:db8::1"}]
    make_request.assert_called_once_with(
        "POST",
        "/api/dhcpv6/leases/search_lease",
        json={"searchPhrase": "host", "current": 1, "rowCount": -1},
    )


@pytest.mark.asyncio
async def test_delete_v4_error(provider: ISCProvider, make_request: AsyncMock) -> None:
    make_request.side_effect = Exception("boom")
    result = await provider.delete_v4_lease("10.0.0.2")
    assert result["status"] == "error"
    assert "boom" in result["error"]
