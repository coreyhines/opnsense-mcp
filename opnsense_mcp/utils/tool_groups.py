"""Which operations are exposed together, and which stay on their own.

Grouping is a presentation choice made here, not in the tools. Every operation
is still its own class with its own schema and validation; this decides how many
names a client sees.

Groups are subsystems, not resources. An earlier cut grouped per resource and
produced 31 names, which still had `route`, `gateway`, `vip`, `vlan` and
`loopback` sitting next to each other as separate tools: exactly the
near-identical neighbours grouping was meant to remove. Merging by subsystem
instead gives 14.

`arp` and `system` stay top-level. They are the two most frequently called
tools here, usually as a one-line question, so a `diagnostics(action=...)` hop
costs something on every casual lookup and buys nothing.

On size: cutting names is worth much less than it looks. Measured on the
31-name surface, property definitions were 78% of the advertised schema and
names plus wrapper only 5%, so renaming alone moved about 3%. The rest came
from defining the repeated fields once (see `schema_fields`), dropping the
`optional` key no client reads, and not listing the action names in both the
description and the enum. Together: 8,101 to 6,161 tokens, 23%.

The floor is lower than it should be for a reason worth knowing: MCP gives
every tool a complete schema with no cross-tool reference, so `apply` is stored
13 times no matter how canonical its definition is.

Result: 115 operations behind 14 names.
"""

from __future__ import annotations

from typing import Any

from opnsense_mcp.utils.grouped_tool import GroupedTool, strip_dead_keys

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
    "bgp": (
        "FRR BGP: peering state and neighbours. FRR ships disabled, so an "
        "empty result usually means it has not been turned on yet",
        {
            "status": "bgp_status",
            "configure": "set_bgp_global",
            "list_neighbors": "list_bgp_neighbors",
            "create_neighbor": "mk_bgp_neighbor",
            "toggle_neighbor": "toggle_bgp_neighbor",
            "delete_neighbor": "rm_bgp_neighbor",
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
        "Firewall filter rules, and the interface groups a rule can target so "
        "one rule covers several networks",
        {
            "list": "fw_rules",
            "create": "mkfw_rule",
            "update": "set_fw_rule",
            "toggle": "toggle_fw_rule",
            "delete": "rmfw_rule",
            "list_groups": "list_fw_groups",
            "set_group": "set_fw_group",
            "apply": "apply_fw_changes",
        },
    ),
    "dhcp": (
        "DHCP: leases, static reservations, ranges, options and per-subnet DNS",
        {
            "leases": "dhcp",
            "delete_lease": "dhcp_lease_delete",
            "list_hosts": "list_dhcp_hosts",
            "create_host": "mk_dhcp_host",
            "move_host": "move_dhcp_host",
            "delete_host": "rm_dhcp_host",
            "list_ranges": "list_dhcp_ranges",
            "create_range": "mk_dhcp_range",
            "update_range": "set_dhcp_range",
            "toggle_range": "toggle_dhcp_range",
            "delete_range": "rm_dhcp_range",
            "list_options": "list_dhcp_options",
            "set_router": "set_dhcp_router_option",
            "delete_option": "rm_dhcp_option",
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
    "ipv6": (
        "IPv6: NPTv6 prefix translation, virtual IPs, router advertisements, "
        "and planning or applying a ULA conversion",
        {
            "list_npt": "list_npt_rules",
            "create_npt": "mk_npt_rule",
            "toggle_npt": "toggle_npt_rule",
            "delete_npt": "rm_npt_rule",
            "list_vip": "list_vip",
            "create_vip": "mk_vip",
            "delete_vip": "rm_vip",
            "list_adverts": "list_router_adverts",
            "set_advert": "set_router_advert",
            "plan_ula": "plan_dns_ula",
            "apply_ula": "apply_ula",
            "inventory_prefix": "inventory_prefix",
            "apply_dns_plan": "apply_dns_ula",
        },
    ),
    "interface_device": (
        "Create the devices interfaces are built on: 802.1Q VLANs and loopbacks",
        {
            "list_vlans": "list_vlans",
            "create_vlan": "mk_vlan",
            "delete_vlan": "rm_vlan",
            "list_loopback": "list_loopback",
            "create_loopback": "mk_loopback",
            "set_address": "set_interface_address",
            "delete_loopback": "rm_loopback",
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
    "routing": (
        "Static routes and gateways. Note routes use `enabled` and gateways "
        "use `disabled`, so a toggle means the opposite thing on each",
        {
            "list_routes": "list_routes",
            "create_route": "mk_route",
            "toggle_route": "toggle_route",
            "delete_route": "rm_route",
            "list_gateways": "list_gateways",
            "create_gateway": "mk_gateway",
            "toggle_gateway": "toggle_gateway",
            "delete_gateway": "rm_gateway",
            "gateway_status": "gateway_status",
        },
    ),
    "diagnostics": (
        "Read-only views of what the firewall currently sees: neighbours, "
        "interfaces, state table, logs, captures, and reachability",
        {
            "lldp": "lldp",
            "interfaces": "interface_list",
            "interface_health": "interface_health",
            "pf_states": "pf_states",
            "pf_statistics": "pf_statistics",
            "logs": "get_logs",
            "packet_capture": "packet_capture",
            "ping": "fw_ping",
        },
    ),
    "shaper": (
        "Traffic shaper: pipes, queues, rules, and applying or auditing them",
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
            "settings": "get_shaper_settings",
            "apply": "apply_shaper",
            "apply_preset": "apply_shaper_preset",
            "restore_snapshot": "restore_shaper_snapshot",
            "audit": "audit_shaper_config",
            "explain": "explain_shaper_config",
            "statistics": "shaper_statistics",
        },
    ),
}

# `arp` and `system` stay top-level. They are the two most frequently called
# tools here, usually as a one-line question, and putting them behind
# diagnostics(action=...) costs a hop on every casual lookup for no gain.
UNGROUPED: frozenset[str] = frozenset({"arp", "system"})


# tool name -> {the tool's own field: the name the group advertises}
#
# A group consumes `action` to choose the member, so a member with its own
# `action` field can never be given one. That silently made three documented
# parameters unreachable: every rule created through `fw_rule` came out `pass`,
# `list` could not filter by action, and a packet capture could be started but
# neither stopped nor fetched.
#
# Renaming the selector would have been cleaner on paper and broken every
# caller, document and test that says `action=<operation>`. Aliasing the few
# colliding member fields costs one indirection here and nothing at the call
# site. `test_tool_groups_have_no_unaliased_collisions` fails if a new member
# introduces a collision without an entry.
FIELD_ALIASES: dict[str, dict[str, str]] = {
    # The rule's own pass/block/reject value, and the filter over it.
    "mkfw_rule": {"action": "rule_action"},
    "set_fw_rule": {"action": "rule_action"},
    "fw_rules": {"action": "rule_action"},
    # A log filter, not a rule field: kept distinct from rule_action.
    "get_logs": {"action": "log_action"},
    # start / stop / fetch.
    "packet_capture": {"action": "capture_action"},
}


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
            name=group_name,
            description=description,
            members=resolved,
            field_aliases=FIELD_ALIASES,
        )

    for tool_name, tool in tools.items():
        if tool_name not in claimed:
            # Ungrouped tools go out as-is apart from the same dead-key strip a
            # group applies, so the wire format does not depend on whether a
            # tool happens to be grouped.
            exposed[tool_name] = _without_dead_keys(tool)

    return exposed


def _without_dead_keys(tool: Any) -> Any:
    """Drop schema keys no client reads, leaving the tool otherwise untouched."""
    schema = getattr(tool, "input_schema", None)
    if not isinstance(schema, dict):
        return tool
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return tool
    tool.input_schema = {
        **schema,
        "properties": {
            field: strip_dead_keys(spec) if isinstance(spec, dict) else spec
            for field, spec in properties.items()
        },
    }
    return tool
