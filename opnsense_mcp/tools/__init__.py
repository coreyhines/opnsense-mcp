"""OPNsense MCP tools package."""

from .arp import ARPTool
from .dhcp import DHCPTool
from .dhcp_lease_delete import DHCPLeaseDeleteTool
from .firewall import FirewallTool
from .fw_rules import FwRulesTool
from .get_logs import FirewallLogsTool, GetLogsTool
from .interface import InterfaceTool
from .interface_list import InterfaceListTool
from .lldp import LLDPTool
from .mkfw_rule import MkfwRuleTool
from .packet_capture import PacketCaptureTool2
from .rmfw_rule import RmfwRuleTool
from .system import SystemTool

# Tool registry mapping tool names to their classes
TOOL_CLASSES = {
    "arp": ARPTool,
    "system": SystemTool,
    "dhcp": DHCPTool,
    "dhcp_lease_delete": DHCPLeaseDeleteTool,
    "lldp": LLDPTool,
    "interface": InterfaceTool,
    "interface_list": InterfaceListTool,
    "firewall": FirewallTool,
    "fw_rules": FwRulesTool,
    "get_logs": GetLogsTool,
    "mkfw_rule": MkfwRuleTool,
    "rmfw_rule": RmfwRuleTool,
    "packet_capture": PacketCaptureTool2,
}


async def execute_tool(client, tool_name: str, args: dict) -> dict:
    """Execute a tool with the given arguments."""
    tool_class = TOOL_CLASSES.get(tool_name)
    if not tool_class:
        raise ValueError(f"Tool {tool_name} not found")

    tool = tool_class(client)
    return await tool.execute(args)


__all__ = [
    "TOOL_CLASSES",
    "execute_tool",
    "ARPTool",
    "DHCPTool",
    "DHCPLeaseDeleteTool",
    "FirewallTool",
    "FwRulesTool",
    "GetLogsTool",
    "FirewallLogsTool",
    "InterfaceTool",
    "InterfaceListTool",
    "LLDPTool",
    "MkfwRuleTool",
    "RmfwRuleTool",
    "SystemTool",
    "PacketCaptureTool2",
] + list(TOOL_CLASSES.keys())
