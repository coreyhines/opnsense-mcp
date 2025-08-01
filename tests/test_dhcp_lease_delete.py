"""Tests for DHCP lease deletion tool."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from opnsense_mcp.tools.dhcp_lease_delete import DHCPLeaseDeleteTool


class TestDHCPLeaseDeleteTool:
    """Test cases for DHCPLeaseDeleteTool."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock OPNsense client."""
        client = MagicMock()
        client.get_dhcpv4_leases = AsyncMock()
        client.get_dhcpv6_leases = AsyncMock()
        client._make_request = AsyncMock()
        return client

    @pytest.fixture
    def tool(self, mock_client):
        """Create a DHCPLeaseDeleteTool instance."""
        return DHCPLeaseDeleteTool(mock_client)

    def test_normalize_mac(self, tool):
        """Test MAC address normalization."""
        # Test various MAC formats
        assert tool._normalize_mac("aa:bb:cc:dd:ee:ff") == "aa:bb:cc:dd:ee:ff"
        assert tool._normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
        assert tool._normalize_mac("aabbccddeeff") == "aa:bb:cc:dd:ee:ff"
        assert tool._normalize_mac("aa.bb.cc.dd.ee.ff") == "aa:bb:cc:dd:ee:ff"

    def test_find_lease_by_criteria_ip(self, tool):
        """Test finding leases by IP address."""
        leases = [
            {"ip": "192.168.1.100", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "test1"},
            {"ip": "192.168.1.101", "mac": "bb:cc:dd:ee:ff:aa", "hostname": "test2"},
        ]

        matches = tool._find_lease_by_criteria(leases, ip="192.168.1.100")
        assert len(matches) == 1
        assert matches[0]["ip"] == "192.168.1.100"

    def test_find_lease_by_criteria_mac(self, tool):
        """Test finding leases by MAC address."""
        leases = [
            {"ip": "192.168.1.100", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "test1"},
            {"ip": "192.168.1.101", "mac": "bb:cc:dd:ee:ff:aa", "hostname": "test2"},
        ]

        matches = tool._find_lease_by_criteria(leases, mac="AA-BB-CC-DD-EE-FF")
        assert len(matches) == 1
        assert matches[0]["mac"] == "aa:bb:cc:dd:ee:ff"

    def test_find_lease_by_criteria_hostname(self, tool):
        """Test finding leases by hostname."""
        leases = [
            {"ip": "192.168.1.100", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "test1"},
            {"ip": "192.168.1.101", "mac": "bb:cc:dd:ee:ff:aa", "hostname": "test2"},
        ]

        matches = tool._find_lease_by_criteria(leases, hostname="TEST1")
        assert len(matches) == 1
        assert matches[0]["hostname"] == "test1"

    @pytest.mark.asyncio
    async def test_execute_delete_by_ip(self, tool, mock_client):
        """Test deleting lease by IP address."""
        # Mock lease data
        mock_client.get_dhcpv4_leases.return_value = [
            {"ip": "192.168.1.100", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "test1"}
        ]
        mock_client.get_dhcpv6_leases.return_value = []
        mock_client._make_request.return_value = {"status": "success"}

        result = await tool.execute({"ip": "192.168.1.100"})

        assert result["status"] == "success"
        assert len(result["deleted_leases"]) == 1
        assert result["deleted_leases"][0]["ip"] == "192.168.1.100"
        assert result["total_deleted"] == 1

        # Verify API calls
        mock_client._make_request.assert_called_once_with(
            "POST", "/api/dhcpv4/leases/del_lease", ip="192.168.1.100"
        )

    @pytest.mark.asyncio
    async def test_execute_delete_by_mac(self, tool, mock_client):
        """Test deleting lease by MAC address."""
        # Mock lease data
        mock_client.get_dhcpv4_leases.return_value = [
            {"ip": "192.168.1.100", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "test1"}
        ]
        mock_client.get_dhcpv6_leases.return_value = []
        mock_client._make_request.return_value = {"status": "success"}

        result = await tool.execute({"mac": "AA-BB-CC-DD-EE-FF"})

        assert result["status"] == "success"
        assert len(result["deleted_leases"]) == 1
        assert result["deleted_leases"][0]["mac"] == "aa:bb:cc:dd:ee:ff"

    @pytest.mark.asyncio
    async def test_execute_delete_by_hostname(self, tool, mock_client):
        """Test deleting lease by hostname."""
        # Mock lease data
        mock_client.get_dhcpv4_leases.return_value = [
            {"ip": "192.168.1.100", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "test1"}
        ]
        mock_client.get_dhcpv6_leases.return_value = []
        mock_client._make_request.return_value = {"status": "success"}

        result = await tool.execute({"hostname": "test1"})

        assert result["status"] == "success"
        assert len(result["deleted_leases"]) == 1
        assert result["deleted_leases"][0]["hostname"] == "test1"

    @pytest.mark.asyncio
    async def test_execute_no_matches(self, tool, mock_client):
        """Test when no leases match the criteria."""
        mock_client.get_dhcpv4_leases.return_value = []
        mock_client.get_dhcpv6_leases.return_value = []

        result = await tool.execute({"ip": "192.168.1.999"})

        assert result["status"] == "no_matches"
        assert len(result["deleted_leases"]) == 0
        assert result["total_deleted"] == 0

    @pytest.mark.asyncio
    async def test_execute_no_parameters(self, tool):
        """Test when no parameters are provided."""
        result = await tool.execute({})

        assert result["status"] == "error"
        assert "Must provide hostname, ip, or mac parameter" in result["error"]

    @pytest.mark.asyncio
    async def test_execute_no_client(self):
        """Test when no client is available."""
        tool = DHCPLeaseDeleteTool(None)
        result = await tool.execute({"ip": "192.168.1.100"})

        assert result["status"] == "error"
        assert "No client available" in result["error"]

    @pytest.mark.asyncio
    async def test_execute_api_error(self, tool, mock_client):
        """Test handling of API errors."""
        mock_client.get_dhcpv4_leases.return_value = [
            {"ip": "192.168.1.100", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "test1"}
        ]
        mock_client.get_dhcpv6_leases.return_value = []
        mock_client._make_request.side_effect = Exception("API Error")

        result = await tool.execute({"ip": "192.168.1.100"})

        assert result["status"] == "error"
        assert len(result["errors"]) == 1
        assert "API Error" in result["errors"][0]

    def test_get_dummy_data(self, tool):
        """Test dummy data generation."""
        data = tool._get_dummy_data()

        assert data["status"] == "success"
        assert len(data["deleted_leases"]) == 1
        assert data["total_deleted"] == 1
        assert "search_criteria" in data
