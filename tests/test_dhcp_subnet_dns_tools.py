"""Tests for DHCP subnet DNS MCP tools."""

from unittest.mock import AsyncMock

import pytest

from opnsense_mcp.tools.dhcp_subnet_dns import (
    ListDhcpSubnetDnsTool,
    SetDhcpSubnetDnsTool,
)


@pytest.fixture
def mock_client() -> AsyncMock:
    """Create a mock OPNsense client."""
    client = AsyncMock()
    client.list_dhcp_subnet_dns = AsyncMock(
        return_value={
            "backend": "dnsmasq",
            "scope": {"interface": "opt2", "subnet": "10.0.2.0/24"},
            "ipv4": ["10.0.10.5"],
            "ipv6": [],
        }
    )
    client.set_dhcp_subnet_dns = AsyncMock(
        return_value={
            "status": "success",
            "backend": "dnsmasq",
            "family": "ipv4",
            "before": ["10.0.10.5"],
            "after": ["10.0.10.4"],
            "applied": True,
        }
    )
    return client


@pytest.mark.asyncio
async def test_list_tool_requires_scope(mock_client: AsyncMock) -> None:
    tool = ListDhcpSubnetDnsTool(mock_client)
    result = await tool.execute({})
    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_list_tool_returns_servers(mock_client: AsyncMock) -> None:
    tool = ListDhcpSubnetDnsTool(mock_client)
    result = await tool.execute({"interface": "opt2"})
    assert result["status"] == "success"
    assert result["ipv4"] == ["10.0.10.5"]
    mock_client.list_dhcp_subnet_dns.assert_awaited_once_with(
        subnet=None,
        interface="opt2",
    )


@pytest.mark.asyncio
async def test_set_tool_calls_client(mock_client: AsyncMock) -> None:
    tool = SetDhcpSubnetDnsTool(mock_client)
    result = await tool.execute(
        {
            "interface": "opt2",
            "family": "ipv4",
            "dns_server": "10.0.10.4",
        }
    )
    assert result["status"] == "success"
    mock_client.set_dhcp_subnet_dns.assert_awaited_once_with(
        subnet=None,
        interface="opt2",
        family="ipv4",
        dns_server="10.0.10.4",
        dns_servers=None,
        slot=None,
    )
