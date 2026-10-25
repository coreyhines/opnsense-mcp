"""Tests for Unbound DNS host override record type selection."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from opnsense_mcp.tools.dns import DNSTool
from opnsense_mcp.tools.mkdns import MkdnsTool
from opnsense_mcp.utils.api import OPNsenseClient, _record_type_for_server


@pytest.mark.parametrize(
    ("server", "expected_rr"),
    [
        ("172.20.2.2", "A"),
        ("192.168.1.1", "A"),
        ("2001:db8:5eed:b501::5", "AAAA"),
        ("2001:db8::1", "AAAA"),
    ],
)
def test_record_type_for_server(server: str, expected_rr: str) -> None:
    assert _record_type_for_server(server) == expected_rr


def test_record_type_for_server_rejects_invalid_ip() -> None:
    with pytest.raises(ValueError):
        _record_type_for_server("not-an-ip")


@pytest.mark.asyncio
async def test_add_host_override_posts_ipv6_as_aaaa() -> None:
    config = {
        "firewall_host": "192.0.2.1",
        "api_key": "k",
        "api_secret": "s",
    }
    captured: dict = {}

    async def fake_make_request(
        method: str,
        endpoint: str,
        **kwargs: object,
    ) -> dict:
        captured["method"] = method
        captured["endpoint"] = endpoint
        captured["json"] = kwargs.get("json")
        return {"uuid": "test-uuid-1"}

    with (
        patch.object(OPNsenseClient, "_detect_endpoint", return_value=None),
        patch("opnsense_mcp.utils.api.requests.Session") as sess_cls,
    ):
        sess_cls.return_value = MagicMock()
        client = OPNsenseClient(config)
        client._make_request = AsyncMock(side_effect=fake_make_request)

        await client.add_host_override(
            hostname="pi5",
            domain="example.com",
            server="2001:db8:5eed:b501::5",
        )

    assert captured["method"] == "POST"
    assert captured["endpoint"] == "/api/unbound/settings/addHostOverride"
    host = captured["json"]["host"]
    assert host["rr"] == "AAAA"
    assert host["server"] == "2001:db8:5eed:b501::5"


@pytest.mark.asyncio
async def test_mkdns_returns_aaaa_for_ipv6_server() -> None:
    client = AsyncMock()
    client.add_host_override.return_value = {"uuid": "abc-123"}
    client.reconfigure_unbound.return_value = {"status": "ok"}
    mkdns = MkdnsTool(client)

    result = await mkdns.execute(
        {
            "hostname": "pi5",
            "domain": "example.com",
            "server": "2001:db8:5eed:b501::5",
        }
    )

    assert result["status"] == "success"
    assert result["rr"] == "AAAA"
    client.add_host_override.assert_awaited_once_with(
        hostname="pi5",
        domain="example.com",
        server="2001:db8:5eed:b501::5",
        description="",
        enabled=True,
    )


@pytest.mark.asyncio
async def test_mkdns_rejects_invalid_server_ip() -> None:
    client = AsyncMock()
    mkdns = MkdnsTool(client)

    result = await mkdns.execute(
        {
            "hostname": "pi5",
            "domain": "example.com",
            "server": "not-an-ip",
        }
    )

    assert result["status"] == "error"
    assert "Invalid IP address" in result["error"]
    client.add_host_override.assert_not_called()


def _offline_client() -> OPNsenseClient:
    """Build an OPNsenseClient that cannot reach the network."""
    config = {"firewall_host": "192.0.2.1", "api_key": "k", "api_secret": "s"}
    with (
        patch.object(OPNsenseClient, "_detect_endpoint", return_value=None),
        patch("opnsense_mcp.utils.api.requests.Session") as sess_cls,
    ):
        sess_cls.return_value = MagicMock()
        return OPNsenseClient(config)


@pytest.mark.asyncio
async def test_search_host_overrides_raises_on_api_error() -> None:
    client = _offline_client()
    client._search_all_rows = AsyncMock(side_effect=RuntimeError("boom"))

    with pytest.raises(RuntimeError):
        await client.search_host_overrides("firecrawl-cache")


@pytest.mark.asyncio
async def test_dns_list_reports_error_on_failed_read() -> None:
    client = AsyncMock()
    client.search_host_overrides.side_effect = RuntimeError("boom")

    result = await DNSTool(client).execute({"search": "firecrawl-cache"})

    assert result["status"] == "error"
    assert "overrides" not in result
    assert "count" not in result


@pytest.mark.asyncio
async def test_lookup_tolerates_override_search_failure() -> None:
    client = _offline_client()
    client.search_arp_table = AsyncMock(return_value=[])
    client.search_ndp_table = AsyncMock(return_value=[])
    client.get_dhcpv4_leases = AsyncMock(return_value=[])
    client.get_dhcpv6_leases = AsyncMock(return_value=[])
    client.resolve_dns_forward = AsyncMock(return_value=[])
    client._search_all_rows = AsyncMock(side_effect=RuntimeError("boom"))

    result = await client.resolve_host_info("firecrawl-cache")

    client._search_all_rows.assert_awaited()
    assert result["input"] == "firecrawl-cache"
    assert result["dns_forward_ips"] == []
    assert result["ip"] is None
