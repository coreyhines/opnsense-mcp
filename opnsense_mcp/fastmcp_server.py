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
from opnsense_mcp.tools.shaper_audit import (
    AuditShaperConfigTool,
    ExplainShaperConfigTool,
)
from opnsense_mcp.tools.shaper_pipes import (
    AddShaperPipeTool,
    DeleteShaperPipeTool,
    GetShaperPipeTool,
    ListShaperPipesTool,
    SetShaperPipeTool,
    ToggleShaperPipeTool,
)
from opnsense_mcp.tools.shaper_presets import ApplyShaperPresetTool
from opnsense_mcp.tools.shaper_queues import (
    AddShaperQueueTool,
    DeleteShaperQueueTool,
    GetShaperQueueTool,
    ListShaperQueuesTool,
    SetShaperQueueTool,
    ToggleShaperQueueTool,
)
from opnsense_mcp.tools.shaper_rules import (
    AddShaperRuleTool,
    DeleteShaperRuleTool,
    GetShaperRuleTool,
    ListShaperRulesTool,
    SetShaperRuleTool,
    ToggleShaperRuleTool,
)
from opnsense_mcp.tools.shaper_service import ApplyShaperTool, ShaperStatisticsTool
from opnsense_mcp.tools.shaper_settings import GetShaperSettingsTool
from opnsense_mcp.tools.shaper_snapshot import RestoreShaperSnapshotTool
from opnsense_mcp.tools.ssh_fw_rule import SSHFirewallRuleTool
from opnsense_mcp.tools.system import SystemTool
from opnsense_mcp.tools.toggle_dhcp_range import ToggleDhcpRangeTool
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
    toggle_dhcp_range_tool = ToggleDhcpRangeTool(client)
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
    list_shaper_pipes_tool = ListShaperPipesTool(client)
    get_shaper_pipe_tool = GetShaperPipeTool(client)
    add_shaper_pipe_tool = AddShaperPipeTool(client)
    set_shaper_pipe_tool = SetShaperPipeTool(client)
    toggle_shaper_pipe_tool = ToggleShaperPipeTool(client)
    delete_shaper_pipe_tool = DeleteShaperPipeTool(client)
    list_shaper_queues_tool = ListShaperQueuesTool(client)
    get_shaper_queue_tool = GetShaperQueueTool(client)
    add_shaper_queue_tool = AddShaperQueueTool(client)
    set_shaper_queue_tool = SetShaperQueueTool(client)
    toggle_shaper_queue_tool = ToggleShaperQueueTool(client)
    delete_shaper_queue_tool = DeleteShaperQueueTool(client)
    list_shaper_rules_tool = ListShaperRulesTool(client)
    get_shaper_rule_tool = GetShaperRuleTool(client)
    add_shaper_rule_tool = AddShaperRuleTool(client)
    set_shaper_rule_tool = SetShaperRuleTool(client)
    toggle_shaper_rule_tool = ToggleShaperRuleTool(client)
    delete_shaper_rule_tool = DeleteShaperRuleTool(client)
    get_shaper_settings_tool = GetShaperSettingsTool(client)
    shaper_statistics_tool = ShaperStatisticsTool(client)
    apply_shaper_tool = ApplyShaperTool(client)
    restore_shaper_snapshot_tool = RestoreShaperSnapshotTool(client)
    apply_shaper_preset_tool = ApplyShaperPresetTool(client)
    audit_shaper_config_tool = AuditShaperConfigTool(client)
    explain_shaper_config_tool = ExplainShaperConfigTool(client)

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
        client_id: str | None = None,
        apply: bool = False,
    ) -> str:
        """Move a DHCP host reservation to a different subnet."""
        result = await move_dhcp_host_tool.execute(
            {
                "host": host,
                "ipv4": ipv4,
                "ipv6": ipv6,
                "new_hostname": new_hostname,
                "client_id": client_id,
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
        client_id: str | None = None,
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
                "client_id": client_id,
                "descr": descr,
                "domain": domain,
                "apply": apply,
            }
        )
        return str(result)

    @mcp.tool()
    async def toggle_dhcp_range(
        enabled: bool,
        interface: str | None = None,
        subnet: str | None = None,
        uuid: str | None = None,
        apply: bool = False,
    ) -> str:
        """Enable or disable a dnsmasq DHCP range on OPNsense."""
        result = await toggle_dhcp_range_tool.execute(
            {
                "enabled": enabled,
                "interface": interface,
                "subnet": subnet,
                "uuid": uuid,
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
            {
                "limit": limit,
                "action": action,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
            }
        )
        return str(result)

    @mcp.tool()
    async def list_shaper_pipes(
        enabled: bool | None = None,
        description: str | None = None,
        row_count: int | None = None,
        fetch_all: bool = True,
    ) -> str:
        """List traffic shaper pipes with optional enabled/description filters."""
        result = await list_shaper_pipes_tool.execute(
            {
                "enabled": enabled,
                "description": description,
                "row_count": row_count,
                "fetch_all": fetch_all,
            }
        )
        return str(result)

    @mcp.tool()
    async def get_shaper_pipe(
        uuid: str | None = None,
        description: str | None = None,
    ) -> str:
        """Get one traffic shaper pipe by uuid or description substring."""
        result = await get_shaper_pipe_tool.execute(
            {"uuid": uuid, "description": description}
        )
        return str(result)

    @mcp.tool()
    async def list_shaper_queues(
        enabled: bool | None = None,
        description: str | None = None,
        row_count: int | None = None,
        fetch_all: bool = True,
    ) -> str:
        """List traffic shaper queues with optional enabled/description filters."""
        result = await list_shaper_queues_tool.execute(
            {
                "enabled": enabled,
                "description": description,
                "row_count": row_count,
                "fetch_all": fetch_all,
            }
        )
        return str(result)

    @mcp.tool()
    async def get_shaper_queue(
        uuid: str | None = None,
        description: str | None = None,
    ) -> str:
        """Get one traffic shaper queue by uuid or description substring."""
        result = await get_shaper_queue_tool.execute(
            {"uuid": uuid, "description": description}
        )
        return str(result)

    @mcp.tool()
    async def list_shaper_rules(
        enabled: bool | None = None,
        description: str | None = None,
        interface: str | None = None,
        row_count: int | None = None,
        fetch_all: bool = True,
    ) -> str:
        """List traffic shaper rules with optional filters."""
        result = await list_shaper_rules_tool.execute(
            {
                "enabled": enabled,
                "description": description,
                "interface": interface,
                "row_count": row_count,
                "fetch_all": fetch_all,
            }
        )
        return str(result)

    @mcp.tool()
    async def get_shaper_rule(
        uuid: str | None = None,
        description: str | None = None,
    ) -> str:
        """Get one traffic shaper rule by uuid or description substring."""
        result = await get_shaper_rule_tool.execute(
            {"uuid": uuid, "description": description}
        )
        return str(result)

    @mcp.tool()
    async def get_shaper_settings() -> str:
        """Get global traffic shaper settings and normalized pipe/queue/rule summary."""
        result = await get_shaper_settings_tool.execute({})
        return str(result)

    @mcp.tool()
    async def shaper_statistics(baseline_id: str | None = None) -> str:
        """Get traffic shaper runtime statistics with structured hints."""
        result = await shaper_statistics_tool.execute({"baseline_id": baseline_id})
        return str(result)

    @mcp.tool()
    async def audit_shaper_config(
        isp_download_mbit: float | None = None,
        isp_upload_mbit: float | None = None,
        wan_line_rate_mbit: float | None = None,
    ) -> str:
        """Audit traffic shaper configuration against best practices."""
        result = await audit_shaper_config_tool.execute(
            {
                "isp_download_mbit": isp_download_mbit,
                "isp_upload_mbit": isp_upload_mbit,
                "wan_line_rate_mbit": wan_line_rate_mbit,
            }
        )
        return str(result)

    @mcp.tool()
    async def explain_shaper_config(include_audit: bool = True) -> str:
        """Explain traffic shaper configuration in plain language."""
        result = await explain_shaper_config_tool.execute(
            {"include_audit": include_audit}
        )
        return str(result)

    @mcp.tool()
    async def add_shaper_pipe(
        description: str,
        bandwidth: int,
        bandwidth_metric: str = "Mbit",
        scheduler: str = "fq_codel",
        enabled: bool = True,
        apply: bool = True,
    ) -> str:
        """Create a traffic shaper pipe."""
        result = await add_shaper_pipe_tool.execute(
            {
                "description": description,
                "bandwidth": bandwidth,
                "bandwidth_metric": bandwidth_metric,
                "scheduler": scheduler,
                "enabled": enabled,
                "apply": apply,
            }
        )
        return str(result)

    @mcp.tool()
    async def set_shaper_pipe(
        uuid: str,
        description: str | None = None,
        bandwidth: int | None = None,
        bandwidth_metric: str | None = None,
        scheduler: str | None = None,
        enabled: bool | None = None,
        apply: bool = True,
    ) -> str:
        """Update a traffic shaper pipe by uuid."""
        result = await set_shaper_pipe_tool.execute(
            {
                "uuid": uuid,
                "description": description,
                "bandwidth": bandwidth,
                "bandwidth_metric": bandwidth_metric,
                "scheduler": scheduler,
                "enabled": enabled,
                "apply": apply,
            }
        )
        return str(result)

    @mcp.tool()
    async def toggle_shaper_pipe(uuid: str, apply: bool = True) -> str:
        """Toggle a traffic shaper pipe enabled state."""
        result = await toggle_shaper_pipe_tool.execute({"uuid": uuid, "apply": apply})
        return str(result)

    @mcp.tool()
    async def delete_shaper_pipe(
        uuid: str,
        confirm: str | None = None,
        apply: bool = True,
    ) -> str:
        """Delete a traffic shaper pipe (confirmation token required)."""
        result = await delete_shaper_pipe_tool.execute(
            {"uuid": uuid, "confirm": confirm, "apply": apply}
        )
        return str(result)

    @mcp.tool()
    async def add_shaper_queue(
        description: str,
        pipe_uuid: str,
        weight: int = 100,
        apply: bool = True,
    ) -> str:
        """Create a traffic shaper queue."""
        result = await add_shaper_queue_tool.execute(
            {
                "description": description,
                "pipe_uuid": pipe_uuid,
                "weight": weight,
                "apply": apply,
            }
        )
        return str(result)

    @mcp.tool()
    async def set_shaper_queue(
        uuid: str,
        description: str | None = None,
        pipe_uuid: str | None = None,
        weight: int | None = None,
        enabled: bool | None = None,
        apply: bool = True,
    ) -> str:
        """Update a traffic shaper queue by uuid."""
        result = await set_shaper_queue_tool.execute(
            {
                "uuid": uuid,
                "description": description,
                "pipe_uuid": pipe_uuid,
                "weight": weight,
                "enabled": enabled,
                "apply": apply,
            }
        )
        return str(result)

    @mcp.tool()
    async def toggle_shaper_queue(uuid: str, apply: bool = True) -> str:
        """Toggle a traffic shaper queue enabled state."""
        result = await toggle_shaper_queue_tool.execute({"uuid": uuid, "apply": apply})
        return str(result)

    @mcp.tool()
    async def delete_shaper_queue(
        uuid: str,
        confirm: str | None = None,
        apply: bool = True,
    ) -> str:
        """Delete a traffic shaper queue (confirmation token required)."""
        result = await delete_shaper_queue_tool.execute(
            {"uuid": uuid, "confirm": confirm, "apply": apply}
        )
        return str(result)

    @mcp.tool()
    async def add_shaper_rule(
        description: str,
        interface: str,
        direction: str,
        target_uuid: str,
        proto: str = "ip",
        apply: bool = True,
    ) -> str:
        """Create a traffic shaper rule."""
        result = await add_shaper_rule_tool.execute(
            {
                "description": description,
                "interface": interface,
                "direction": direction,
                "target_uuid": target_uuid,
                "proto": proto,
                "apply": apply,
            }
        )
        return str(result)

    @mcp.tool()
    async def set_shaper_rule(
        uuid: str,
        description: str | None = None,
        interface: str | None = None,
        direction: str | None = None,
        target_uuid: str | None = None,
        proto: str | None = None,
        enabled: bool | None = None,
        apply: bool = True,
    ) -> str:
        """Update a traffic shaper rule by uuid."""
        result = await set_shaper_rule_tool.execute(
            {
                "uuid": uuid,
                "description": description,
                "interface": interface,
                "direction": direction,
                "target_uuid": target_uuid,
                "proto": proto,
                "enabled": enabled,
                "apply": apply,
            }
        )
        return str(result)

    @mcp.tool()
    async def toggle_shaper_rule(uuid: str, apply: bool = True) -> str:
        """Toggle a traffic shaper rule enabled state."""
        result = await toggle_shaper_rule_tool.execute({"uuid": uuid, "apply": apply})
        return str(result)

    @mcp.tool()
    async def delete_shaper_rule(
        uuid: str,
        confirm: str | None = None,
        apply: bool = True,
    ) -> str:
        """Delete a traffic shaper rule (confirmation token required)."""
        result = await delete_shaper_rule_tool.execute(
            {"uuid": uuid, "confirm": confirm, "apply": apply}
        )
        return str(result)

    @mcp.tool()
    async def apply_shaper() -> str:
        """Apply pending traffic shaper configuration via service/reconfigure."""
        result = await apply_shaper_tool.execute({})
        return str(result)

    @mcp.tool()
    async def restore_shaper_snapshot(
        snapshot_id: str,
        apply: bool = True,
        remove_orphans: bool = False,
    ) -> str:
        """Restore traffic shaper config from a prior snapshot_id.

        Set remove_orphans=true to delete pipes/queues/rules whose UUID is not
        in the snapshot (destructive; default false).
        """
        result = await restore_shaper_snapshot_tool.execute(
            {
                "snapshot_id": snapshot_id,
                "apply": apply,
                "remove_orphans": remove_orphans,
            }
        )
        return str(result)

    @mcp.tool()
    async def apply_shaper_preset(
        download_mbit: float,
        upload_mbit: float,
        preset: str = "bufferbloat_wan",
        wan_interface: str = "wan",
        apply: bool = True,
    ) -> str:
        """Apply bufferbloat_wan preset with FQ-CoDel pipes at 85% ISP rates."""
        result = await apply_shaper_preset_tool.execute(
            {
                "preset": preset,
                "download_mbit": download_mbit,
                "upload_mbit": upload_mbit,
                "wan_interface": wan_interface,
                "apply": apply,
            }
        )
        return str(result)

    return mcp
