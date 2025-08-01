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
            ("PacketCaptureTool2", "opnsense_mcp.tools.packet_capture"),
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

    @pytest.mark.asyncio
    async def test_packet_capture_tool_import_and_initialization(self) -> None:
        """Test PacketCaptureTool2 can be imported and initialized."""
        from opnsense_mcp.tools.packet_capture import PacketCaptureTool2

        # Test that the tool can be imported and instantiated
        tool = PacketCaptureTool2()
        assert tool is not None
        assert hasattr(tool, "execute")
        assert hasattr(tool, "_detect_mcp_server_issues")
        assert hasattr(tool, "_auto_correct_issues")
        logger.info("✅ PacketCaptureTool2 imported and initialized successfully")

    def test_packet_capture_process_detection_logic(self) -> None:
        """Test that the process detection logic works correctly."""
        import subprocess
        import sys

        from opnsense_mcp.tools.packet_capture import PacketCaptureTool2

        tool = PacketCaptureTool2()
        
        # Test the process detection method
        issues = tool._detect_mcp_server_issues()
        
        # The detection should not incorrectly report the server as not running
        # when we're actually running the test (which means the server is running)
        if "OPNsense MCP server is not running" in issues.get("issues", []):
            # This would indicate the broken logic we just fixed
            pytest.fail("Process detection logic is broken - incorrectly reporting server as not running")
        
        logger.info("✅ Packet capture process detection logic working correctly")

    @pytest.mark.asyncio
    async def test_packet_capture_diagnose_action(self) -> None:
        """Test the diagnose action of PacketCaptureTool2."""
        from opnsense_mcp.tools.packet_capture import PacketCaptureTool2

        tool = PacketCaptureTool2()
        result = await tool.execute({"action": "diagnose"})
        
        assert isinstance(result, dict)
        assert "status" in result
        assert "initial_issues" in result
        assert "auto_corrections" in result
        assert "issues_after_correction" in result
        
        # The diagnose action should not report the server as not running
        # when we're actually running tests
        initial_issues = result.get("initial_issues", {}).get("issues", [])
        if "OPNsense MCP server is not running" in initial_issues:
            pytest.fail("Diagnose action incorrectly reports server as not running")
        
        logger.info("✅ Packet capture diagnose action working correctly")

    def test_packet_capture_parameter_validation(self) -> None:
        """Test parameter validation in PacketCaptureTool2."""
        import asyncio

        from opnsense_mcp.tools.packet_capture import PacketCaptureTool2

        tool = PacketCaptureTool2()
        
        # Test invalid duration
        async def test_invalid_duration():
            result = await tool.execute({
                "action": "start",
                "duration": -1,
                "interface": "wan"
            })
            assert result["status"] == "error"
            assert "Invalid duration" in result["error"]
        
        # Test invalid count
        async def test_invalid_count():
            result = await tool.execute({
                "action": "start",
                "count": 0,
                "interface": "wan"
            })
            assert result["status"] == "error"
            assert "Invalid count" in result["error"]
        
        # Test invalid mode
        async def test_invalid_mode():
            result = await tool.execute({
                "action": "start",
                "mode": "invalid",
                "interface": "wan"
            })
            assert result["status"] == "error"
            assert "Invalid mode" in result["error"]
        
        # Run the async tests
        asyncio.run(test_invalid_duration())
        asyncio.run(test_invalid_count())
        asyncio.run(test_invalid_mode())
        
        logger.info("✅ Packet capture parameter validation working correctly")


if __name__ == "__main__":
    # Run tests directly if executed as a script
    pytest.main([__file__, "-v"])
