# opnsense_mcp/fastmcp_server.py
"""FastMCP-based server supporting Streamable HTTP, SSE, and stdio transports."""

from __future__ import annotations

from fastmcp import FastMCP

from opnsense_mcp.server import get_opnsense_client
from opnsense_mcp.tools.aliases import AliasesTool
from opnsense_mcp.tools.arp import ARPTool
from opnsense_mcp.tools.dhcp import DHCPTool
from opnsense_mcp.tools.dhcp_host_move import MoveDhcpHostTool
from opnsense_mcp.tools.dhcp_hosts import ListDhcpHostsTool
from opnsense_mcp.tools.dhcp_lease_delete import DHCPLeaseDeleteTool
from opnsense_mcp.tools.dhcp_subnet_dns import (
    ListDhcpSubnetDnsTool,
    SetDhcpSubnetDnsTool,
)
from opnsense_mcp.tools.dns import DNSTool
from opnsense_mcp.tools.firewall_logs import FirewallLogsTool
from opnsense_mcp.tools.flush_dns import FlushDnsTool
from opnsense_mcp.tools.fw_rules import FwRulesTool
from opnsense_mcp.tools.gateway_status import GatewayStatusTool
from opnsense_mcp.tools.interface_list import InterfaceListTool
from opnsense_mcp.tools.lldp import LLDPTool
from opnsense_mcp.tools.mk_dhcp_host import MkDhcpHostTool
from opnsense_mcp.tools.mkdns import MkdnsTool
from opnsense_mcp.tools.mkfw_rule import MkfwRuleTool
from opnsense_mcp.tools.packet_capture import PacketCaptureTool2 as PacketCaptureTool
from opnsense_mcp.tools.rm_dhcp_host import RmDhcpHostTool
from opnsense_mcp.tools.rmdns import RmdnsTool
from opnsense_mcp.tools.rmfw_rule import RmfwRuleTool
from opnsense_mcp.tools.set_fw_rule import SetFwRuleTool
from opnsense_mcp.tools.ssh_fw_rule import SSHFirewallRuleTool
from opnsense_mcp.tools.system import SystemTool
from opnsense_mcp.tools.toggle_fw_rule import ToggleFwRuleTool
from opnsense_mcp.utils.env import load_opnsense_env


def build_mcp_server() -> FastMCP:
    """Build and return a configured FastMCP server with all OPNsense tools registered."""
    load_opnsense_env()

    client = get_opnsense_client({})

    arp_tool = ARPTool(client)
    dhcp_tool = DHCPTool(client)
    dhcp_lease_delete_tool = DHCPLeaseDeleteTool(client)
    list_dhcp_subnet_dns_tool = ListDhcpSubnetDnsTool(client)
    set_dhcp_subnet_dns_tool = SetDhcpSubnetDnsTool(client)
    move_dhcp_host_tool = MoveDhcpHostTool(client)
    list_dhcp_hosts_tool = ListDhcpHostsTool(client)
    rm_dhcp_host_tool = RmDhcpHostTool(client)
    mk_dhcp_host_tool = MkDhcpHostTool(client)
    lldp_tool = LLDPTool(client)
    system_tool = SystemTool(client)
    fw_rules_tool = FwRulesTool(client)
    mkfw_rule_tool = MkfwRuleTool(client)
    rmfw_rule_tool = RmfwRuleTool(client)
    interface_list_tool = InterfaceListTool(client)
    packet_capture_tool = PacketCaptureTool()
    ssh_fw_rule_tool = SSHFirewallRuleTool(client)
    dns_tool = DNSTool(client)
    mkdns_tool = MkdnsTool(client)
    rmdns_tool = RmdnsTool(client)
    flush_dns_tool = FlushDnsTool(client)
    toggle_fw_rule_tool = ToggleFwRuleTool(client)
    set_fw_rule_tool = SetFwRuleTool(client)
    aliases_tool = AliasesTool(client)
    gateway_status_tool = GatewayStatusTool(client)
    firewall_logs_tool = FirewallLogsTool(client)

    mcp = FastMCP("opnsense-mcp")

    @mcp.tool()
    async def arp(
        mac: str | None = None,
        ip: str | None = None,
        search: str | None = None,
    ) -> str:
        """Show ARP/NDP table."""
        result = await arp_tool.execute({"mac": mac, "ip": ip, "search": search})
        return str(result)

    @mcp.tool()
    async def dhcp(search: str | None = None) -> str:
        """Show DHCP lease information."""
        result = await dhcp_tool.execute({"search": search})
        return str(result)

    @mcp.tool()
    async def dhcp_lease_delete(
        hostname: str | None = None,
        ip: str | None = None,
        mac: str | None = None,
    ) -> str:
        """Delete DHCP leases by hostname, IP, or MAC address."""
        result = await dhcp_lease_delete_tool.execute(
            {"hostname": hostname, "ip": ip, "mac": mac}
        )
        return str(result)

    @mcp.tool()
    async def list_dhcp_subnet_dns(
        subnet: str | None = None,
        interface: str | None = None,
    ) -> str:
        """List DHCP-provided DNS servers for a subnet scope (dnsmasq or Kea backends)."""
        result = await list_dhcp_subnet_dns_tool.execute(
            {"subnet": subnet, "interface": interface}
        )
        return str(result)

    @mcp.tool()
    async def set_dhcp_subnet_dns(
        family: str,
        subnet: str | None = None,
        interface: str | None = None,
        dns_server: str | None = None,
        dns_servers: list[str] | None = None,
        slot: int | None = None,
    ) -> str:
        """Set DHCP-provided DNS servers for a subnet scope."""
        result = await set_dhcp_subnet_dns_tool.execute(
            {
                "family": family,
                "subnet": subnet,
                "interface": interface,
                "dns_server": dns_server,
                "dns_servers": dns_servers,
                "slot": slot,
            }
        )
        return str(result)

    @mcp.tool()
    async def move_dhcp_host(
        host: str,
        ipv4: str | None = None,
        ipv6: str | None = None,
        new_hostname: str | None = None,
        apply: bool = False,
    ) -> str:
        """Move a DHCP host reservation to a different subnet."""
        result = await move_dhcp_host_tool.execute(
            {
                "host": host,
                "ipv4": ipv4,
                "ipv6": ipv6,
                "new_hostname": new_hostname,
                "apply": apply,
            }
        )
        return str(result)

    @mcp.tool()
    async def list_dhcp_hosts(
        search: str | None = None,
        descr: str | None = None,
        missing_ipv6: bool = False,
    ) -> str:
        """List DHCP static host reservations (dnsmasq)."""
        result = await list_dhcp_hosts_tool.execute(
            {"search": search, "descr": descr, "missing_ipv6": missing_ipv6}
        )
        return str(result)

    @mcp.tool()
    async def rm_dhcp_host(host: str, apply: bool = False) -> str:
        """Remove a DHCP static host reservation (dnsmasq)."""
        result = await rm_dhcp_host_tool.execute({"host": host, "apply": apply})
        return str(result)

    @mcp.tool()
    async def mk_dhcp_host(
        hostname: str,
        mac: str,
        ipv4: str | None = None,
        ipv6: str | None = None,
        descr: str = "",
        domain: str = "",
        apply: bool = False,
    ) -> str:
        """Create a DHCP static host reservation (dnsmasq)."""
        result = await mk_dhcp_host_tool.execute(
            {
                "hostname": hostname,
                "mac": mac,
                "ipv4": ipv4,
                "ipv6": ipv6,
                "descr": descr,
                "domain": domain,
                "apply": apply,
            }
        )
        return str(result)

    @mcp.tool()
    async def lldp() -> str:
        """Show LLDP neighbor table."""
        result = await lldp_tool.execute({})
        return str(result)

    @mcp.tool()
    async def system() -> str:
        """Show system status information."""
        result = await system_tool.execute({})
        return str(result)

    @mcp.tool()
    async def fw_rules(
        interface: str | None = None,
        action: str | None = None,
        enabled: bool | None = None,
        protocol: str | None = None,
    ) -> str:
        """Get firewall rules from the OPNsense Firewall Automation API."""
        result = await fw_rules_tool.execute(
            {
                "interface": interface,
                "action": action,
                "enabled": enabled,
                "protocol": protocol,
            }
        )
        return str(result)

    @mcp.tool()
    async def mkfw_rule(
        description: str,
        interface: str = "lan",
        action: str = "pass",
        protocol: str = "any",
        source_net: str = "any",
        source_port: str = "any",
        destination_net: str = "any",
        destination_port: str = "any",
        direction: str = "in",
        ipprotocol: str = "inet",
        enabled: bool = True,
        gateway: str = "",
        apply: bool = True,
    ) -> str:
        """Create a new firewall rule and optionally apply changes."""
        result = await mkfw_rule_tool.execute(
            {
                "description": description,
                "interface": interface,
                "action": action,
                "protocol": protocol,
                "source_net": source_net,
                "source_port": source_port,
                "destination_net": destination_net,
                "destination_port": destination_port,
                "direction": direction,
                "ipprotocol": ipprotocol,
                "enabled": enabled,
                "gateway": gateway,
                "apply": apply,
            }
        )
        return str(result)

    @mcp.tool()
    async def rmfw_rule(rule_uuid: str, apply: bool = True) -> str:
        """Delete a firewall rule and optionally apply changes."""
        result = await rmfw_rule_tool.execute({"rule_uuid": rule_uuid, "apply": apply})
        return str(result)

    @mcp.tool()
    async def ssh_fw_rule(
        description: str,
        interface: str = "lan",
        action: str = "block",
        protocol: str = "any",
        source_net: str = "any",
        source_port: str = "any",
        destination_net: str = "any",
        destination_port: str = "any",
        direction: str = "in",
        ipprotocol: str = "inet",
        enabled: bool = True,
        apply: bool = True,
    ) -> str:
        """Create firewall rules via SSH (bypasses API issues)."""
        result = await ssh_fw_rule_tool.execute(
            {
                "description": description,
                "interface": interface,
                "action": action,
                "protocol": protocol,
                "source_net": source_net,
                "source_port": source_port,
                "destination_net": destination_net,
                "destination_port": destination_port,
                "direction": direction,
                "ipprotocol": ipprotocol,
                "enabled": enabled,
                "apply": apply,
            }
        )
        return str(result)

    @mcp.tool()
    async def interface_list() -> str:
        """Get available interface names for firewall rules."""
        result = await interface_list_tool.execute({})
        return str(result)

    @mcp.tool()
    async def packet_capture(
        action: str = "start",
        interface: str = "wan",
        filter: str | None = None,
        duration: int = 30,
        count: int | None = None,
        local_path: str | None = None,
        raw: bool = False,
        stream: bool = False,
        preview_bytes: int = 1000,
    ) -> str:
        """Start, stop, or fetch a packet capture file."""
        result = await packet_capture_tool.execute(
            {
                "action": action,
                "interface": interface,
                "filter": filter,
                "duration": duration,
                "count": count,
                "local_path": local_path,
                "raw": raw,
                "stream": stream,
                "preview_bytes": preview_bytes,
            }
        )
        return str(result)

    @mcp.tool()
    async def dns(search: str | None = None) -> str:
        """List Unbound DNS host overrides."""
        result = await dns_tool.execute({"search": search})
        return str(result)

    @mcp.tool()
    async def mkdns(
        hostname: str,
        domain: str,
        server: str,
        description: str = "",
        enabled: bool = True,
    ) -> str:
        """Add a DNS host override in Unbound."""
        result = await mkdns_tool.execute(
            {
                "hostname": hostname,
                "domain": domain,
                "server": server,
                "description": description,
                "enabled": enabled,
            }
        )
        return str(result)

    @mcp.tool()
    async def rmdns(uuid: str) -> str:
        """Delete a DNS host override from Unbound."""
        result = await rmdns_tool.execute({"uuid": uuid})
        return str(result)

    @mcp.tool()
    async def flush_dns(hostname: str | None = None, mode: str = "name") -> str:
        """Flush Unbound DNS cache for a hostname or restart Unbound."""
        result = await flush_dns_tool.execute({"hostname": hostname, "mode": mode})
        return str(result)

    @mcp.tool()
    async def toggle_fw_rule(
        rule_uuid: str,
        enabled: bool,
        apply: bool = True,
    ) -> str:
        """Enable or disable a firewall rule."""
        result = await toggle_fw_rule_tool.execute(
            {"rule_uuid": rule_uuid, "enabled": enabled, "apply": apply}
        )
        return str(result)

    @mcp.tool()
    async def set_fw_rule(
        rule_uuid: str,
        description: str | None = None,
        interface: str | None = None,
        direction: str | None = None,
        ipprotocol: str | None = None,
        protocol: str | None = None,
        source_net: str | None = None,
        source_port: str | None = None,
        destination_net: str | None = None,
        destination_port: str | None = None,
        action: str | None = None,
        enabled: bool | None = None,
        gateway: str | None = None,
        apply: bool = True,
    ) -> str:
        """Edit fields of an existing firewall rule."""
        result = await set_fw_rule_tool.execute(
            {
                "rule_uuid": rule_uuid,
                "description": description,
                "interface": interface,
                "direction": direction,
                "ipprotocol": ipprotocol,
                "protocol": protocol,
                "source_net": source_net,
                "source_port": source_port,
                "destination_net": destination_net,
                "destination_port": destination_port,
                "action": action,
                "enabled": enabled,
                "gateway": gateway,
                "apply": apply,
            }
        )
        return str(result)

    @mcp.tool()
    async def aliases(search: str | None = None) -> str:
        """List firewall aliases (IP groups, port groups, etc)."""
        result = await aliases_tool.execute({"search": search})
        return str(result)

    @mcp.tool()
    async def gateway_status() -> str:
        """Show WAN gateway health (latency, packet loss)."""
        result = await gateway_status_tool.execute({})
        return str(result)

    @mcp.tool()
    async def get_logs(
        limit: int = 500,
        action: str | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        protocol: str | None = None,
    ) -> str:
        """Get firewall logs with optional filtering."""
        result = await firewall_logs_tool.execute(
            {"limit": limit, "action": action, "src_ip": src_ip, "dst_ip": dst_ip, "protocol": protocol}
        )
        return str(result)

    return mcp
