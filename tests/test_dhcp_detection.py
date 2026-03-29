"""Tests for DHCP backend auto-detection."""

from unittest.mock import AsyncMock

import pytest

from opnsense_mcp.utils.dhcp_provider import detect_dhcp_backend
from opnsense_mcp.utils.dhcp_providers.dnsmasq import DnsmasqProvider
from opnsense_mcp.utils.dhcp_providers.isc import ISCProvider
from opnsense_mcp.utils.dhcp_providers.kea import KeaProvider


@pytest.fixture
def make_request() -> AsyncMock:
    """Create a mock request callable."""
    return AsyncMock()


@pytest.mark.asyncio
async def test_selects_kea_when_kea_probe_succeeds(make_request: AsyncMock) -> None:
    make_request.return_value = {"status": "running"}
    provider = await detect_dhcp_backend(make_request)
    assert isinstance(provider, KeaProvider)


@pytest.mark.asyncio
async def test_selects_dnsmasq_when_kea_fails(make_request: AsyncMock) -> None:
    call_count = 0

    async def side_effect(
        method: str, endpoint: str, **kwargs: object
    ) -> dict[str, str]:
        del method, endpoint, kwargs
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("not found")
        return {"status": "ok"}

    make_request.side_effect = side_effect
    provider = await detect_dhcp_backend(make_request)
    assert isinstance(provider, DnsmasqProvider)


@pytest.mark.asyncio
async def test_falls_back_to_isc_when_all_probes_fail(make_request: AsyncMock) -> None:
    make_request.side_effect = Exception("all down")
    provider = await detect_dhcp_backend(make_request)
    assert isinstance(provider, ISCProvider)


@pytest.mark.asyncio
async def test_skips_disabled_kea_and_selects_running_dnsmasq(
    make_request: AsyncMock,
) -> None:
    responses = iter(
        [
            {"status": "disabled"},
            {"status": "running"},
        ]
    )

    async def side_effect(
        method: str, endpoint: str, **kwargs: object
    ) -> dict[str, str]:
        del method, endpoint, kwargs
        return next(responses)

    make_request.side_effect = side_effect
    provider = await detect_dhcp_backend(make_request)
    assert isinstance(provider, DnsmasqProvider)
