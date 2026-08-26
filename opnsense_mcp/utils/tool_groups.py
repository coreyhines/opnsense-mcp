"""Which operations are exposed together, and which stay on their own.

Grouping is a presentation choice made here, not in the tools. Every operation
is still its own class with its own schema and validation; this decides how many
names a client sees.

Grouped where a domain is a resource with verbs: aliases, backups, NPT rules,
VIPs, VLANs, gateways, routes, DHCP hosts, DNS overrides, firewall rules, the
traffic shaper. `action` names the verb, and the model picks the object first.

Left alone where the tools are distinct subjects rather than verbs on one
resource: `arp`, `lldp`, `system`, `interface_list`, `pf_states` and the other
diagnostics have no shared shape, so an `action` enum would group things that
have nothing to do with each other.

Result: 95 names become 30.
"""

from __future__ import annotations

from typing import Any

from opnsense_mcp.utils.grouped_tool import GroupedTool

# group name -> (description, {action: tool name})
#
# Tool names, not classes: the registry has already built the instances, and
# this keeps the mapping readable next to what a caller types.
GROUPS: dict[str, tuple[str, dict[str, str]]] = {
    "alias": (
        "Manage firewall aliases, the named address and port groups rules reference",
        {
            "list": "aliases",
            "create": "mk_alias",
            "update": "set_alias",
            "toggle": "toggle_alias",
            "delete": "rm_alias",
        },
    ),
    "config_backup": (
        "Configuration backups, revision history and boot environment snapshots",
        {
            "providers": "list_backup_providers",
            "list": "list_config_backups",
            "diff": "diff_config_backups",
            "download": "download_config",
            "list_snapshots": "list_snapshots",
            "create_snapshot": "mk_snapshot",
        },
    ),
    "fw_rule": (
        "Manage firewall filter rules",
        {
            "list": "fw_rules",
            "create": "mkfw_rule",
            "update": "set_fw_rule",
            "toggle": "toggle_fw_rule",
            "delete": "rmfw_rule",
        },
    ),
    "dhcp_host": (
        "Manage DHCP static reservations",
        {
            "list": "list_dhcp_hosts",
            "create": "mk_dhcp_host",
            "move": "move_dhcp_host",
            "delete": "rm_dhcp_host",
        },
    ),
    "dhcp_scope": (
        "DHCP leases, ranges and per-subnet DNS",
        {
            "leases": "dhcp",
            "delete_lease": "dhcp_lease_delete",
            "toggle_range": "toggle_dhcp_range",
            "list_dns": "list_dhcp_subnet_dns",
            "set_dns": "set_dhcp_subnet_dns",
        },
    ),
    "dns_override": (
        "Manage Unbound host overrides",
        {
            "list": "dns",
            "create": "mkdns",
            "update": "set_host_override",
            "delete": "rmdns",
            "flush": "flush_dns",
        },
    ),
    "npt": (
        "Manage NPTv6 prefix translation rules",
        {
            "list": "list_npt_rules",
            "create": "mk_npt_rule",
            "toggle": "toggle_npt_rule",
            "delete": "rm_npt_rule",
        },
    ),
    "vip": (
        "Manage interface virtual IPs",
        {
            "list": "list_vip",
            "create": "mk_vip",
            "delete": "rm_vip",
        },
    ),
    "router_advert": (
        "Manage radvd router advertisements",
        {
            "list": "list_router_adverts",
            "update": "set_router_advert",
        },
    ),
    "loopback": (
        "Manage loopback interface devices",
        {
            "list": "list_loopback",
            "create": "mk_loopback",
        },
    ),
    "vlan": (
        "Manage 802.1Q VLAN devices",
        {
            "list": "list_vlans",
            "create": "mk_vlan",
            "delete": "rm_vlan",
        },
    ),
    "gateway": (
        "Manage gateways and read their health",
        {
            "list": "list_gateways",
            "create": "mk_gateway",
            "toggle": "toggle_gateway",
            "status": "gateway_status",
        },
    ),
    "nat_outbound": (
        "Outbound source NAT rules and how they are generated",
        {
            "list": "list_nat_outbound",
            "create": "mk_nat_outbound",
            "toggle": "toggle_nat_outbound",
            "delete": "rm_nat_outbound",
            "mode": "nat_outbound_mode",
        },
    ),
    "route": (
        "Manage static routes",
        {
            "list": "list_routes",
            "create": "mk_route",
            "toggle": "toggle_route",
            "delete": "rm_route",
        },
    ),
    "shaper": (
        "Traffic shaper pipes, queues and rules",
        {
            "list_pipes": "list_shaper_pipes",
            "get_pipe": "get_shaper_pipe",
            "create_pipe": "add_shaper_pipe",
            "update_pipe": "set_shaper_pipe",
            "toggle_pipe": "toggle_shaper_pipe",
            "delete_pipe": "delete_shaper_pipe",
            "list_queues": "list_shaper_queues",
            "get_queue": "get_shaper_queue",
            "create_queue": "add_shaper_queue",
            "update_queue": "set_shaper_queue",
            "toggle_queue": "toggle_shaper_queue",
            "delete_queue": "delete_shaper_queue",
            "list_rules": "list_shaper_rules",
            "get_rule": "get_shaper_rule",
            "create_rule": "add_shaper_rule",
            "update_rule": "set_shaper_rule",
            "toggle_rule": "toggle_shaper_rule",
            "delete_rule": "delete_shaper_rule",
        },
    ),
    "shaper_service": (
        "Apply shaper changes, restore a snapshot, or apply a preset",
        {
            "settings": "get_shaper_settings",
            "apply": "apply_shaper",
            "apply_preset": "apply_shaper_preset",
            "restore_snapshot": "restore_shaper_snapshot",
        },
    ),
    "shaper_audit": (
        "Inspect shaper configuration and throughput",
        {
            "audit": "audit_shaper_config",
            "explain": "explain_shaper_config",
            "statistics": "shaper_statistics",
        },
    ),
}

# Distinct subjects rather than verbs on a shared resource. Grouping these would
# put unrelated things behind one name.
UNGROUPED: frozenset[str] = frozenset(
    {
        "arp",
        "lldp",
        "system",
        "interface_list",
        "interface_health",
        "pf_states",
        "pf_statistics",
        "get_logs",
        "packet_capture",
        "ssh_fw_rule",
        "fw_ping",
        "plan_dns_ula",
        "apply_ula",
    }
)


def build_groups(tools: dict[str, Any]) -> dict[str, Any]:
    """Return the exposed surface: grouped tools plus the ungrouped ones.

    Any tool that is neither grouped nor listed as ungrouped is passed through
    unchanged, so a newly added tool stays reachable until someone decides where
    it belongs.
    """
    exposed: dict[str, Any] = {}
    claimed: set[str] = set()

    for group_name, (description, members) in GROUPS.items():
        resolved = {
            action: tools[tool_name]
            for action, tool_name in members.items()
            if tool_name in tools
        }
        if not resolved:
            continue
        claimed.update(
            tool_name for tool_name in members.values() if tool_name in tools
        )
        exposed[group_name] = GroupedTool(
            name=group_name, description=description, members=resolved
        )

    for tool_name, tool in tools.items():
        if tool_name not in claimed:
            exposed[tool_name] = tool

    return exposed
