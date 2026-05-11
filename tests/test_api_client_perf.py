"""Tests for persistent requests.Session in OPNsenseClient."""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from opnsense_mcp.utils.api import OPNsenseClient


@pytest.fixture
def client_config():
    return {
        "firewall_host": "192.0.2.1",
        "api_key": "testkey",
        "api_secret": "testsecret",
    }


def test_client_uses_persistent_session(client_config):
    """OPNsenseClient must hold a requests.Session instance."""
    with (
        patch("opnsense_mcp.utils.api.requests.Session") as mock_session_cls,
        patch.object(OPNsenseClient, "_detect_endpoint", return_value=None),
    ):
        mock_session_cls.return_value = MagicMock()
        client = OPNsenseClient(client_config)
        mock_session_cls.assert_called_once()
        assert client.session is mock_session_cls.return_value


async def test_make_request_uses_session(client_config):
    """_make_request must call session.request, not the module-level requests.request."""
    with (
        patch("opnsense_mcp.utils.api.requests.Session") as mock_session_cls,
        patch.object(OPNsenseClient, "_detect_endpoint", return_value=None),
    ):
        mock_session = MagicMock()
        mock_session.request.return_value = MagicMock(
            status_code=200, json=lambda: {"ok": True}
        )
        mock_session_cls.return_value = mock_session
        client = OPNsenseClient(client_config)
        await client._make_request("GET", "/api/test")
        mock_session.request.assert_called_once()


def test_init_does_not_probe_endpoints_via_http(client_config):
    """__init__ must not make any HTTP requests to detect the log endpoint."""
    with patch("opnsense_mcp.utils.api.requests.Session") as mock_session_cls:
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        OPNsenseClient(client_config)
        mock_session.get.assert_not_called()


async def test_lazy_endpoint_detects_on_first_call_and_caches(client_config):
    """Endpoint probe runs once on first get_firewall_logs call; not on second."""
    with patch("opnsense_mcp.utils.api.requests.Session") as mock_session_cls:
        mock_session = MagicMock()
        mock_session.get.return_value = MagicMock(status_code=200)
        mock_session.request.return_value = MagicMock(status_code=200, json=list)
        mock_session_cls.return_value = mock_session
        client = OPNsenseClient(client_config)

        # No HTTP at init
        mock_session.get.assert_not_called()

        # First call triggers probe
        await client.get_firewall_logs()
        assert mock_session.get.call_count == 1

        # Second call must NOT re-probe
        await client.get_firewall_logs()
        assert mock_session.get.call_count == 1, (
            "Probe must be cached after first detection"
        )


async def test_get_arp_table_uses_session_not_pyopnsense(client_config):
    """get_arp_table must use the shared session, not pyopnsense diag_client."""
    with (
        patch("opnsense_mcp.utils.api.requests.Session") as mock_session_cls,
        patch.object(OPNsenseClient, "_detect_endpoint", return_value=None),
    ):
        mock_session = MagicMock()
        mock_session.request.return_value = MagicMock(
            status_code=200,
            json=lambda: [
                {"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.1", "intf": "em0"}
            ],
        )
        mock_session_cls.return_value = mock_session
        client = OPNsenseClient(client_config)
        result = await client.get_arp_table()
        assert len(result) == 1
        mock_session.request.assert_called_once()


async def test_search_dhcpv4_leases_posts_search_phrase(client_config):
    """search_dhcpv4_leases must POST searchPhrase rather than GET all leases."""
    with (
        patch("opnsense_mcp.utils.api.requests.Session") as mock_session_cls,
        patch.object(OPNsenseClient, "_detect_endpoint", return_value=None),
    ):
        mock_session = MagicMock()
        mock_session.request.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "rows": [
                    {
                        "address": "10.0.0.5",
                        "mac": "aa:bb:cc:dd:ee:ff",
                        "hostname": "myhost",
                    }
                ]
            },
        )
        mock_session_cls.return_value = mock_session
        client = OPNsenseClient(client_config)
        result = await client.search_dhcpv4_leases("myhost")
        assert len(result) == 1
        call_args = mock_session.request.call_args
        assert call_args[0][0] == "POST"
        assert call_args[1].get("json", {}).get("searchPhrase") == "myhost"


async def test_dhcp_tool_uses_search_when_query_given(client_config):
    """DHCPTool.execute uses search_dhcpv4/v6_leases (not get_*) when search is set."""
    from opnsense_mcp.tools.dhcp import DHCPTool

    mock_client = MagicMock()
    mock_client.search_dhcpv4_leases = AsyncMock(
        return_value=[
            {"address": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "myhost"}
        ]
    )
    mock_client.search_dhcpv6_leases = AsyncMock(return_value=[])
    mock_client.get_dhcpv4_leases = AsyncMock()
    mock_client.get_dhcpv6_leases = AsyncMock()
    tool = DHCPTool(mock_client)
    result = await tool.execute({"search": "myhost"})
    mock_client.search_dhcpv4_leases.assert_called_once_with("myhost")
    mock_client.get_dhcpv4_leases.assert_not_called()
    assert result["status"] == "success"


async def test_dhcp_tool_uses_get_when_no_query(client_config):
    """DHCPTool.execute falls back to get_dhcpv4/v6_leases when search is empty."""
    from opnsense_mcp.tools.dhcp import DHCPTool

    mock_client = MagicMock()
    mock_client.get_dhcpv4_leases = AsyncMock(return_value=[])
    mock_client.get_dhcpv6_leases = AsyncMock(return_value=[])
    mock_client.search_dhcpv4_leases = AsyncMock()
    mock_client.search_dhcpv6_leases = AsyncMock()
    tool = DHCPTool(mock_client)
    await tool.execute({})
    mock_client.get_dhcpv4_leases.assert_called_once()
    mock_client.search_dhcpv4_leases.assert_not_called()
    mock_client.search_dhcpv6_leases.assert_not_called()


async def test_make_request_fails_fast_without_retry_sleep(client_config):
    """_make_request must not sleep before failing — no retry delay on error."""
    with (
        patch("opnsense_mcp.utils.api.requests.Session") as mock_session_cls,
        patch.object(OPNsenseClient, "_detect_endpoint", return_value=None),
    ):
        mock_session = MagicMock()
        mock_session.request.side_effect = Exception("connection refused")
        mock_session_cls.return_value = mock_session
        client = OPNsenseClient(client_config)
        start = time.monotonic()
        with pytest.raises(Exception):  # noqa: B017
            await client._make_request("GET", "/api/test")
        elapsed = time.monotonic() - start
        assert elapsed < 0.5, (
            f"Request took {elapsed:.2f}s — retry sleep still present?"
        )


async def test_default_timeout_is_5_seconds(client_config):
    """Default request timeout must be 5 seconds."""
    with (
        patch("opnsense_mcp.utils.api.requests.Session") as mock_session_cls,
        patch.object(OPNsenseClient, "_detect_endpoint", return_value=None),
    ):
        mock_session = MagicMock()
        mock_session.request.return_value = MagicMock(status_code=200, json=dict)
        mock_session_cls.return_value = mock_session
        client = OPNsenseClient(client_config)
        await client._make_request("GET", "/api/test")
        call_kwargs = mock_session.request.call_args[1]
        assert call_kwargs.get("timeout") == 5
