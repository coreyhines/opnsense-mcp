#!/usr/bin/env python3
"""
Comprehensive test suite for all OPNsense MCP tools.

This test verifies that all MCP tools can be imported and executed successfully,
returning sample results to validate functionality.
"""

import importlib
import logging
import sys
from pathlib import Path

import pytest

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


class TestAllMCPTools:
    """Test suite for all MCP tools."""

    @pytest.fixture(scope="class")
    def mock_client(self):
        """Create a mock OPNsense client for testing."""
        from opnsense_mcp.utils.mock_api import MockOPNsenseClient

        workspace_root = Path(__file__).parent.parent
        mock_data_path = workspace_root / "examples" / "mock_data"
        config = {"development": {"mock_data_path": str(mock_data_path)}}
        return MockOPNsenseClient(config)

    @pytest.fixture(scope="class")
    def tool_definitions(self):
        """Define all available MCP tools."""
        return [
            ("SystemTool", "opnsense_mcp.tools.system"),
            ("ARPTool", "opnsense_mcp.tools.arp"),
            ("DHCPTool", "opnsense_mcp.tools.dhcp"),
            ("LLDPTool", "opnsense_mcp.tools.lldp"),
            ("InterfaceTool", "opnsense_mcp.tools.interface"),
            ("InterfaceListTool", "opnsense_mcp.tools.interface_list"),
            ("FirewallTool", "opnsense_mcp.tools.firewall"),
            ("FwRulesTool", "opnsense_mcp.tools.fw_rules"),
            ("FirewallLogsTool", "opnsense_mcp.tools.firewall_logs"),
            ("MkfwRuleTool", "opnsense_mcp.tools.mkfw_rule"),
            ("RmfwRuleTool", "opnsense_mcp.tools.rmfw_rule"),
        ]

    def test_tool_imports(self, tool_definitions: list[tuple[str, str]]) -> None:
        """Test that all tools can be imported successfully."""
        for class_name, module_path in tool_definitions:
            module = importlib.import_module(module_path)
            tool_class = getattr(module, class_name)
            assert tool_class is not None
            logger.info(f"✅ {class_name} imported successfully")

    @pytest.mark.asyncio
    async def test_system_tool(self, mock_client) -> None:
        """Test SystemTool execution."""
        from opnsense_mcp.tools.system import SystemTool

        tool = SystemTool(mock_client)
        result = await tool.execute({})

        assert isinstance(result, dict)
        assert "cpu_usage" in result
        assert "memory_usage" in result
        logger.info("✅ SystemTool executed successfully")

    @pytest.mark.asyncio
    async def test_arp_tool(self, mock_client) -> None:
        """Test ARPTool execution."""
        from opnsense_mcp.tools.arp import ARPTool

        tool = ARPTool(mock_client)
        result = await tool.execute({})

        assert isinstance(result, dict)
        assert "status" in result
        logger.info("✅ ARPTool executed successfully")

    @pytest.mark.asyncio
    async def test_dhcp_tool(self, mock_client) -> None:
        """Test DHCPTool execution."""
        from opnsense_mcp.tools.dhcp import DHCPTool

        tool = DHCPTool(mock_client)
        result = await tool.execute({})

        assert isinstance(result, dict)
        assert "status" in result
        logger.info("✅ DHCPTool executed successfully")

    @pytest.mark.asyncio
    async def test_lldp_tool(self, mock_client) -> None:
        """Test LLDPTool execution."""
        from opnsense_mcp.tools.lldp import LLDPTool

        tool = LLDPTool(mock_client)
        result = await tool.execute({})

        assert isinstance(result, dict)
        assert "status" in result
        logger.info("✅ LLDPTool executed successfully")

    @pytest.mark.asyncio
    async def test_interface_tool(self, mock_client) -> None:
        """Test InterfaceTool execution."""
        from opnsense_mcp.tools.interface import InterfaceTool

        tool = InterfaceTool(mock_client)
        result = await tool.execute({})

        assert isinstance(result, dict)
        assert "status" in result
        logger.info("✅ InterfaceTool executed successfully")

    @pytest.mark.asyncio
    async def test_interface_list_tool(self, mock_client) -> None:
        """Test InterfaceListTool execution."""
        from opnsense_mcp.tools.interface_list import InterfaceListTool

        tool = InterfaceListTool(mock_client)
        result = await tool.execute({})

        assert isinstance(result, dict)
        assert "status" in result
        logger.info("✅ InterfaceListTool executed successfully")

    @pytest.mark.asyncio
    async def test_fw_rules_tool(self, mock_client) -> None:
        """Test FwRulesTool execution."""
        from opnsense_mcp.tools.fw_rules import FwRulesTool

        tool = FwRulesTool(mock_client)
        result = await tool.execute({})

        assert isinstance(result, dict)
        logger.info("✅ FwRulesTool executed successfully")

    @pytest.mark.asyncio
    async def test_firewall_logs_tool(self, mock_client) -> None:
        """Test FirewallLogsTool execution."""
        from opnsense_mcp.tools.firewall_logs import FirewallLogsTool

        tool = FirewallLogsTool(mock_client)
        result = await tool.execute({})

        assert isinstance(result, dict)
        logger.info("✅ FirewallLogsTool executed successfully")

    def test_action_tools_schema(self) -> None:
        """Test that action tools have proper schemas."""
        from opnsense_mcp.tools.mkfw_rule import MkfwRuleTool
        from opnsense_mcp.tools.rmfw_rule import RmfwRuleTool

        # These are action tools, test their schema definitions
        mkfw_tool = MkfwRuleTool(None)
        rmfw_tool = RmfwRuleTool(None)

        assert hasattr(mkfw_tool, "name")
        assert hasattr(rmfw_tool, "name")
        logger.info("✅ Action tools have proper schemas")


if __name__ == "__main__":
    # Run tests directly if executed as a script
    pytest.main([__file__, "-v"])
