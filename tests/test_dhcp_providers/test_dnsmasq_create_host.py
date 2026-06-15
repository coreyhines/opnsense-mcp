"""Tests for DnsmasqProvider.create_host."""

import pytest

from opnsense_mcp.utils.dhcp_providers.dnsmasq import DnsmasqProvider


def _make_provider(responses: dict):
    """Return a DnsmasqProvider backed by a fake request function."""
    async def fake_request(method, endpoint, **kwargs):
        return responses.get(endpoint, {})

    return DnsmasqProvider(fake_request)


def _search_response(rows):
    return {"rows": rows, "rowCount": len(rows)}


_EXISTING_ROW = {
    "uuid": "uuid-existing",
    "host": "existing",
    "hwaddr": "11:22:33:44:55:66",
    "ip": "10.0.8.10",
}

_LEASE_ENDPOINT = "/api/dnsmasq/leases/search"
_HOST_SEARCH_ENDPOINT = "/api/dnsmasq/settings/search_host"
_HOST_ADD_ENDPOINT = "/api/dnsmasq/settings/add_host"
_RECONFIGURE_ENDPOINT = "/api/dnsmasq/service/reconfigure"


@pytest.mark.asyncio
async def test_dry_run_returns_planned():
    calls = []

    async def fake_request(method, endpoint, **kwargs):
        calls.append(endpoint)
        if endpoint == _HOST_SEARCH_ENDPOINT:
            return _search_response([])
        if endpoint == _LEASE_ENDPOINT:
            return {"rows": []}
        return {}

    provider = DnsmasqProvider(fake_request)
    result = await provider.create_host(
        hostname="newhost",
        mac="aa:bb:cc:dd:ee:ff",
        ipv4="10.0.8.50",
        dry_run=True,
    )
    assert result["status"] == "dry_run"
    assert result["planned"]["host"] == "newhost"
    assert result["planned"]["hwaddr"] == "aa:bb:cc:dd:ee:ff"
    assert result["planned"]["ipv4"] == "10.0.8.50"
    assert _HOST_ADD_ENDPOINT not in calls
    assert _RECONFIGURE_ENDPOINT not in calls


@pytest.mark.asyncio
async def test_apply_creates_and_reconfigures():
    calls = []

    async def fake_request(method, endpoint, **kwargs):
        calls.append(endpoint)
        if endpoint == _HOST_SEARCH_ENDPOINT:
            return _search_response([])
        if endpoint == _LEASE_ENDPOINT:
            return {"rows": []}
        if endpoint == _HOST_ADD_ENDPOINT:
            return {"result": "saved", "uuid": "new-uuid"}
        return {}

    provider = DnsmasqProvider(fake_request)
    result = await provider.create_host(
        hostname="newhost",
        mac="aa:bb:cc:dd:ee:ff",
        ipv4="10.0.8.50",
        dry_run=False,
    )
    assert result["status"] == "success"
    assert result["created"]["uuid"] == "new-uuid"
    assert _RECONFIGURE_ENDPOINT in calls


@pytest.mark.asyncio
async def test_duplicate_mac_blocked():
    async def fake_request(method, endpoint, **kwargs):
        if endpoint == _HOST_SEARCH_ENDPOINT:
            return _search_response([_EXISTING_ROW])
        if endpoint == _LEASE_ENDPOINT:
            return {"rows": []}
        return {}

    provider = DnsmasqProvider(fake_request)
    result = await provider.create_host(
        hostname="newhost",
        mac="11:22:33:44:55:66",
        ipv4="10.0.8.50",
        dry_run=False,
    )
    assert result["status"] == "error"
    assert any(c["reason"] == "duplicate MAC" for c in result["conflicts"])


@pytest.mark.asyncio
async def test_duplicate_ipv4_blocked():
    async def fake_request(method, endpoint, **kwargs):
        if endpoint == _HOST_SEARCH_ENDPOINT:
            return _search_response([_EXISTING_ROW])
        if endpoint == _LEASE_ENDPOINT:
            return {"rows": []}
        return {}

    provider = DnsmasqProvider(fake_request)
    result = await provider.create_host(
        hostname="newhost",
        mac="aa:bb:cc:dd:ee:ff",
        ipv4="10.0.8.10",
        dry_run=False,
    )
    assert result["status"] == "error"
    assert result["conflicts"]


@pytest.mark.asyncio
async def test_invalid_mac_rejected():
    provider = DnsmasqProvider(None)
    result = await provider.create_host(
        hostname="host",
        mac="not-a-mac",
        ipv4="10.0.8.1",
        dry_run=True,
    )
    assert result["status"] == "error"
    assert "MAC" in result["error"]


@pytest.mark.asyncio
async def test_invalid_ipv4_rejected():
    provider = DnsmasqProvider(None)
    result = await provider.create_host(
        hostname="host",
        mac="aa:bb:cc:dd:ee:ff",
        ipv4="not-an-ip",
        dry_run=True,
    )
    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_no_address_rejected():
    provider = DnsmasqProvider(None)
    result = await provider.create_host(
        hostname="host",
        mac="aa:bb:cc:dd:ee:ff",
        dry_run=True,
    )
    assert result["status"] == "error"
    assert "ipv4" in result["error"] or "ipv6" in result["error"]


@pytest.mark.asyncio
async def test_ipv6_only_dry_run():
    async def fake_request(method, endpoint, **kwargs):
        if endpoint == _HOST_SEARCH_ENDPOINT:
            return _search_response([])
        if endpoint == _LEASE_ENDPOINT:
            return {"rows": []}
        return {}

    provider = DnsmasqProvider(fake_request)
    result = await provider.create_host(
        hostname="host6",
        mac="aa:bb:cc:dd:ee:ff",
        ipv6=50,
        dry_run=True,
    )
    assert result["status"] == "dry_run"
    assert result["planned"]["ipv6_suffix"] == "::50"
    assert result["planned"]["ipv4"] is None


@pytest.mark.asyncio
async def test_mac_normalized():
    async def fake_request(method, endpoint, **kwargs):
        if endpoint == _HOST_SEARCH_ENDPOINT:
            return _search_response([])
        if endpoint == _LEASE_ENDPOINT:
            return {"rows": []}
        return {}

    provider = DnsmasqProvider(fake_request)
    result = await provider.create_host(
        hostname="host",
        mac="AA-BB-CC-DD-EE-FF",
        ipv4="10.0.8.5",
        dry_run=True,
    )
    assert result["planned"]["hwaddr"] == "aa:bb:cc:dd:ee:ff"
