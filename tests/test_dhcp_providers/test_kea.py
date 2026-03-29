"""Tests for Kea DHCP provider."""

from unittest.mock import AsyncMock

import pytest

from opnsense_mcp.utils.dhcp_providers.kea import KeaProvider


@pytest.fixture
def make_request() -> AsyncMock:
    """Create mock request callable."""
    return AsyncMock()


@pytest.fixture
def provider(make_request: AsyncMock) -> KeaProvider:
    """Create provider with mocked requests."""
    return KeaProvider(make_request)


def test_name(provider: KeaProvider) -> None:
    assert provider.name == "kea"


@pytest.mark.asyncio
async def test_get_v4_rows(provider: KeaProvider, make_request: AsyncMock) -> None:
    make_request.return_value = {"rows": [{"ip": "10.0.0.10"}]}
    result = await provider.get_v4_leases()
    assert result == [{"ip": "10.0.0.10"}]
    make_request.assert_called_once_with("GET", "/api/kea/leases4/search")


@pytest.mark.asyncio
async def test_get_v6_arguments_leases(
    provider: KeaProvider, make_request: AsyncMock
) -> None:
    make_request.return_value = {"arguments": {"leases": [{"ip": "2001:db8::20"}]}}
    result = await provider.get_v6_leases()
    assert result == [{"ip": "2001:db8::20"}]


@pytest.mark.asyncio
async def test_delete_not_supported(provider: KeaProvider) -> None:
    result = await provider.delete_v4_lease("10.0.0.1")
    assert result["status"] == "error"
    assert "not supported" in result["error"]
