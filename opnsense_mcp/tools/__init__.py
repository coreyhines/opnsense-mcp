"""OPNsense MCP tools package."""

from .arp import ARPTool
from .dhcp import DHCPTool
from .dhcp_lease_delete import DHCPLeaseDeleteTool
from .firewall import FirewallTool
from .fw_rules import FwRulesTool
from .get_logs import FirewallLogsTool, GetLogsTool
from .interface import InterfaceTool
from .interface_health import InterfaceHealthTool
from .interface_list import InterfaceListTool
from .lldp import LLDPTool
from .mkfw_rule import MkfwRuleTool
from .packet_capture import PacketCaptureTool2
from .pf_diagnostics import PfStatesTool, PfStatisticsTool
from .rmfw_rule import RmfwRuleTool
from .system import SystemTool

# The tool registry lives in opnsense_mcp.utils.registry, which both servers
# consume. The partial map and execute_tool that used to sit here covered 16 of
# the tools, was wired to neither server, and shared a name with the real
# registry, so it is gone rather than left as a second answer to the same
# question.


__all__ = [
    "ARPTool",
    "DHCPTool",
    "DHCPLeaseDeleteTool",
    "FirewallTool",
    "FwRulesTool",
    "GetLogsTool",
    "FirewallLogsTool",
    "InterfaceTool",
    "InterfaceListTool",
    "InterfaceHealthTool",
    "LLDPTool",
    "MkfwRuleTool",
    "RmfwRuleTool",
    "SystemTool",
    "PacketCaptureTool2",
    "PfStatesTool",
    "PfStatisticsTool",
]
