"""One source of truth for which tools exist and how they are exposed.

Both servers used to hold their own copy of the tool surface: `server.py` had a
hand-written `tools/list` block and a long `if tool_name == ...` dispatch chain,
`fastmcp_server.py` had a typed wrapper per tool. Nothing kept the two in step,
and the tool surface only stayed consistent because someone remembered to edit
both.

The registry builds the instances once, produces the `tools/list` payload from
each class's own metadata, and dispatches by name. Adding a tool means adding it
to `TOOL_CLASSES`.

Result text is produced here as well, so both transports return the same shape.
"""

from __future__ import annotations

from typing import Any, Protocol

from opnsense_mcp.tools.alias_write import (
    MkAliasTool,
    RmAliasTool,
    SetAliasTool,
    ToggleAliasTool,
)
from opnsense_mcp.tools.aliases import AliasesTool
from opnsense_mcp.tools.arp import ARPTool
from opnsense_mcp.tools.config_backup import (
    DiffConfigBackupsTool,
    DownloadConfigTool,
    ListBackupProvidersTool,
    ListConfigBackupsTool,
    ListSnapshotsTool,
    MkSnapshotTool,
)
from opnsense_mcp.tools.dhcp import DHCPTool
from opnsense_mcp.tools.dhcp_host_move import MoveDhcpHostTool
from opnsense_mcp.tools.dhcp_hosts import ListDhcpHostsTool
from opnsense_mcp.tools.dhcp_lease_delete import DHCPLeaseDeleteTool
from opnsense_mcp.tools.dhcp_subnet_dns import (
    ListDhcpSubnetDnsTool,
    SetDhcpSubnetDnsTool,
)
from opnsense_mcp.tools.dns import DNSTool
from opnsense_mcp.tools.flush_dns import FlushDnsTool
from opnsense_mcp.tools.fw_rules import FwRulesTool
from opnsense_mcp.tools.gateway_status import GatewayStatusTool
from opnsense_mcp.tools.get_logs import GetLogsTool
from opnsense_mcp.tools.interface_health import InterfaceHealthTool
from opnsense_mcp.tools.interface_list import InterfaceListTool
from opnsense_mcp.tools.ipv6_stack import (
    ListLoopbackTool,
    ListNptRulesTool,
    ListVipTool,
    MkLoopbackTool,
    MkNptRuleTool,
    MkVipTool,
    RmNptRuleTool,
    RmVipTool,
    ToggleNptRuleTool,
)
from opnsense_mcp.tools.lldp import LLDPTool
from opnsense_mcp.tools.mk_dhcp_host import MkDhcpHostTool
from opnsense_mcp.tools.mkdns import MkdnsTool
from opnsense_mcp.tools.mkfw_rule import MkfwRuleTool
from opnsense_mcp.tools.packet_capture import PacketCaptureTool2
from opnsense_mcp.tools.pf_diagnostics import PfStatesTool, PfStatisticsTool
from opnsense_mcp.tools.rm_dhcp_host import RmDhcpHostTool
from opnsense_mcp.tools.rmdns import RmdnsTool
from opnsense_mcp.tools.rmfw_rule import RmfwRuleTool
from opnsense_mcp.tools.set_fw_rule import SetFwRuleTool
from opnsense_mcp.tools.ssh_fw_rule import SSHFirewallRuleTool
from opnsense_mcp.tools.system import SystemTool
from opnsense_mcp.tools.toggle_dhcp_range import ToggleDhcpRangeTool
from opnsense_mcp.tools.toggle_fw_rule import ToggleFwRuleTool


class Tool(Protocol):
    """What the registry needs from a tool class."""

    name: str
    description: str
    input_schema: dict[str, Any]

    async def execute(self, args: dict[str, Any]) -> Any: ...


# Every tool exposed by both servers, apart from the traffic shaper, which is
# built separately and passed in (see `build_tools`).
TOOL_CLASSES: tuple[type, ...] = (
    AliasesTool,
    ARPTool,
    DHCPTool,
    DHCPLeaseDeleteTool,
    DiffConfigBackupsTool,
    DNSTool,
    DownloadConfigTool,
    FlushDnsTool,
    FwRulesTool,
    GatewayStatusTool,
    GetLogsTool,
    InterfaceHealthTool,
    InterfaceListTool,
    ListBackupProvidersTool,
    ListConfigBackupsTool,
    ListDhcpHostsTool,
    ListDhcpSubnetDnsTool,
    ListLoopbackTool,
    ListNptRulesTool,
    ListSnapshotsTool,
    ListVipTool,
    LLDPTool,
    MkDhcpHostTool,
    MkdnsTool,
    MkAliasTool,
    MkfwRuleTool,
    MkLoopbackTool,
    MkNptRuleTool,
    MkVipTool,
    MkSnapshotTool,
    MoveDhcpHostTool,
    PacketCaptureTool2,
    PfStatesTool,
    PfStatisticsTool,
    RmAliasTool,
    RmDhcpHostTool,
    RmNptRuleTool,
    RmVipTool,
    RmdnsTool,
    RmfwRuleTool,
    SetAliasTool,
    SetDhcpSubnetDnsTool,
    SetFwRuleTool,
    SSHFirewallRuleTool,
    SystemTool,
    ToggleAliasTool,
    ToggleDhcpRangeTool,
    ToggleNptRuleTool,
    ToggleFwRuleTool,
)

# Tools constructed without a client.
_NO_CLIENT: frozenset[str] = frozenset({"packet_capture"})


def build_tools(client: Any, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """Instantiate every registered tool, keyed by tool name.

    ``extra`` merges in tools built elsewhere, currently the traffic shaper set,
    which takes construction arguments the registry does not model.
    """
    tools: dict[str, Any] = {}
    for cls in TOOL_CLASSES:
        name = cls.name
        tools[name] = cls() if name in _NO_CLIENT else cls(client)
    if extra:
        tools.update(extra)
    return tools


def list_tools_payload(tools: dict[str, Any]) -> list[dict[str, Any]]:
    """The `tools/list` result, taken from each tool's own metadata."""
    return [
        {
            "name": name,
            "description": getattr(tool, "description", name),
            "inputSchema": getattr(
                tool,
                "input_schema",
                {"type": "object", "properties": {}, "required": []},
            ),
        }
        for name, tool in tools.items()
    ]


async def dispatch(tools: dict[str, Any], name: str, arguments: dict[str, Any]) -> Any:
    """Run a tool by name.

    Raises ``KeyError`` when the name is unknown so callers can map it to their
    own not-found response.
    """
    return await tools[name].execute(arguments)
