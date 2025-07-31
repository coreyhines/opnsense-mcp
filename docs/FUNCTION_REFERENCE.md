# OPNsense MCP Server - Function Reference

This document provides a comprehensive reference for all supported functions in the OPNsense MCP Server, what they do, and how to use them effectively.

## Network Discovery & Identification

### `arp` - ARP/NDP Table Information
**Purpose**: Shows the Address Resolution Protocol (ARP) table for IPv4 and Neighbor Discovery Protocol (NDP) table for IPv6, mapping IP addresses to MAC addresses.

**Use Case**: Find which device is using a specific IP address, or what IP a device with a known MAC address has.

**Parameters**:
- `mac` (optional): Filter by MAC address
- `ip` (optional): Filter by IP address  
- `search` (optional): Search by IP/MAC/hostname

**Quick Example**:
```bash
# Find all devices on network
arp

# Find specific device by MAC
arp mac="aa:bb:cc:dd:ee:ff"

# Search for a specific host
arp search="trogdor"
```

**What it returns**: List of devices with IP addresses, MAC addresses, and interface information.

---

### `dhcp` - DHCP Lease Information
**Purpose**: Shows Dynamic Host Configuration Protocol (DHCP) leases - which IP addresses have been assigned to which devices and when they expire.

**Use Case**: Find hostname/device information, track lease expiration, identify unauthorized devices.

**Parameters**:
- `search` (optional): Search by hostname/IP/MAC

**Quick Example**:
```bash
# Show all DHCP leases
dhcp

# Find lease for specific device
dhcp search="morpheus"
```

**What it returns**: Active and expired DHCP leases with hostnames, IP addresses, MAC addresses, and expiration times.

---

### `lldp` - Link Layer Discovery Protocol
**Purpose**: Shows LLDP neighbor information - what network devices are directly connected to each interface.

**Use Case**: Network topology discovery, identifying connected switches, routers, and managed devices.

**Parameters**: None

**Quick Example**:
```bash
# Show all LLDP neighbors
lldp
```

**What it returns**: Connected network devices with their capabilities, management IP addresses, and port information.

---

## System Monitoring

### `system` - System Status and Diagnostics
**Purpose**: Shows OPNsense firewall system status including CPU, memory, disk usage, and uptime.

**Use Case**: Monitor firewall health, check resource utilization, diagnose performance issues.

**Parameters**:
- `action` (optional): "status" (default) or "diagnose_mcp" for MCP server diagnostics

**Quick Example**:
```bash
# Get system status
system

# Diagnose MCP server issues
system action="diagnose_mcp"
```

**What it returns**: CPU usage, memory usage, disk space, uptime, and system health metrics.

---

## Firewall Management

### `fw_rules` - Firewall Rules Inspection
**Purpose**: Shows current firewall rule configuration for analysis and context.

**Use Case**: Understanding current security posture, troubleshooting connectivity issues, auditing rules.

**Parameters**:
- `interface` (optional): Filter by interface (supports partial matching)
- `action` (optional): Filter by action (pass, block, reject)
- `enabled` (optional): Filter by enabled status (true/false)
- `protocol` (optional): Filter by protocol (tcp, udp, icmp, etc.)

**Quick Example**:
```bash
# Show all firewall rules
fw_rules

# Show only blocking rules
fw_rules action="block"

# Show rules for WAN interface
fw_rules interface="wan"
```

**What it returns**: List of firewall rules with their conditions, actions, and descriptions.

---

### `mkfw_rule` - Create Firewall Rules
**Purpose**: Creates new firewall rules to control network traffic.

**Use Case**: Block/allow specific traffic, implement security policies, control access.

**Parameters**:
- `description` (required): Description of the rule
- `interface` (optional): Interface name (default: "lan")
- `action` (optional): pass, block, or reject (default: "pass")
- `protocol` (optional): any, tcp, udp, icmp, etc. (default: "any")
- `source_net` (optional): Source network/IP (default: "any")
- `source_port` (optional): Source port (default: "any")
- `destination_net` (optional): Destination network/IP (default: "any")
- `destination_port` (optional): Destination port (default: "any")
- `direction` (optional): in or out (default: "in")
- `ipprotocol` (optional): inet or inet6 (default: "inet")
- `enabled` (optional): true or false (default: true)
- `apply` (optional): Apply changes immediately (default: true)

**Quick Example**:
```bash
# Block a specific host from accessing web services
mkfw_rule description="Block host from web" action="block" source_net="192.168.1.100" destination_port="80,443"

# Allow SSH from management network
mkfw_rule description="Allow SSH from mgmt" source_net="10.0.1.0/24" destination_port="22"
```

**What it returns**: Success/failure status and rule UUID if created.

---

### `rmfw_rule` - Delete Firewall Rules
**Purpose**: Removes existing firewall rules.

**Use Case**: Clean up obsolete rules, remove temporary blocks, modify security policies.

**Parameters**:
- `rule_uuid` (required): UUID of the rule to delete
- `apply` (optional): Apply changes immediately (default: true)

**Quick Example**:
```bash
# Delete a specific rule
rmfw_rule rule_uuid="12345678-1234-1234-1234-123456789abc"
```

**What it returns**: Success/failure status of the deletion.

---

### `ssh_fw_rule` - SSH-Based Firewall Rule Creation
**Purpose**: Creates firewall rules via SSH, bypassing API limitations.

**Use Case**: When the standard API fails, emergency rule creation, advanced configurations.

**Parameters**: Same as `mkfw_rule` but executed via SSH

**Quick Example**:
```bash
# Create rule via SSH when API fails
ssh_fw_rule description="Emergency block" action="block" source_net="192.168.1.100"
```

**What it returns**: Success/failure status of SSH-based rule creation.

---

## Network Analysis

### `get_logs` - Firewall Log Analysis
**Purpose**: Retrieves and filters firewall logs to analyze network traffic and security events.

**Use Case**: Security monitoring, troubleshooting connectivity issues, traffic analysis.

**Parameters**:
- `limit` (optional): Number of log entries to return
- `action` (optional): Filter by action (pass, block, reject)
- `src_ip` (optional): Filter by source IP address
- `dst_ip` (optional): Filter by destination IP address
- `protocol` (optional): Filter by protocol (tcp, udp, icmp)

**Quick Example**:
```bash
# Show recent blocked traffic
get_logs action="block" limit=50

# Show traffic from specific host
get_logs src_ip="192.168.1.100"

# Show SSH connection attempts
get_logs dst_port="22" protocol="tcp"
```

**What it returns**: Firewall log entries with timestamps, source/destination, actions, and protocols.

---

### `packet_capture` - Live Traffic Capture
**Purpose**: Captures live network packets for detailed traffic analysis and troubleshooting.

**Use Case**: Deep network troubleshooting, security analysis, protocol debugging, traffic inspection.

**Parameters**:
- `action` (optional): start, stop, fetch, or diagnose (default: "start")
- `interface` (optional): Interface to capture on (default: "wan")
- `filter` (optional): BPF filter expression for packet filtering
- `duration` (optional): Duration in seconds (default: 30)
- `count` (optional): Packet count limit
- `stream` (optional): Stream packet data to chat (default: true)
- `preview_bytes` (optional): Number of bytes to preview (default: 1000)
- `raw` (optional): Return raw PCAP file (default: false)
- `local_path` (optional): Local path to save PCAP file

**Quick Example**:
```bash
# Capture 60 seconds of WAN traffic
packet_capture interface="wan" duration=60

# Capture HTTP traffic only
packet_capture interface="lan" filter="port 80 or port 443" duration=30

# Capture specific host traffic
packet_capture filter="host 192.168.1.100" count=100
```

**What it returns**: Real-time packet analysis with source/destination information, protocols, and traffic patterns.

---

## Network Configuration

### `interface_list` - Available Interfaces
**Purpose**: Lists all available network interfaces that can be used with other tools.

**Use Case**: Discovering interface names for firewall rules, packet captures, and monitoring.

**Parameters**: None

**Quick Example**:
```bash
# Show all interfaces
interface_list
```

**What it returns**: List of available interfaces with their names and descriptions.

---

## Complex Query Examples

The MCP server is designed to handle complex queries that combine multiple functions. Here are examples of how the AI agent interprets and resolves multi-step questions:

### "What is morpheus doing on the network?"

**Agent Resolution Process**:
1. **Identify the device**: `dhcp search="morpheus"` and `arp search="morpheus"`
2. **Get network details**: Extract IP address, MAC address, interface location
3. **Analyze current activity**: `get_logs src_ip="<morpheus_ip>"` and `get_logs dst_ip="<morpheus_ip>"`
4. **Live traffic analysis**: `packet_capture interface="<appropriate_interface>" filter="host <morpheus_ip>"`
5. **Correlation**: Combine DHCP lease info, ARP entries, firewall logs, and live packet data

**Expected Result**: Complete picture of morpheus including:
- Current IP address and lease status
- MAC address and physical interface location
- Recent network connections and blocked attempts
- Live traffic patterns and protocols in use
- Security events and policy violations

### "Is there suspicious traffic on the network?"

**Agent Resolution Process**:
1. **System health check**: `system` to check firewall status
2. **Review security logs**: `get_logs action="block"` to see what's being blocked
3. **Analyze traffic patterns**: `packet_capture` on WAN and key internal interfaces
4. **Check for unauthorized devices**: `dhcp` and `arp` to identify unknown devices
5. **Protocol analysis**: Look for unusual protocols, port scans, or data exfiltration patterns

**Expected Result**: Security assessment including:
- List of blocked connection attempts
- Unknown or unauthorized devices
- Unusual traffic patterns or protocols
- Potential security threats and recommendations

### "Why can't device X reach service Y?"

**Agent Resolution Process**:
1. **Device identification**: `dhcp search="X"` and `arp search="X"`
2. **Network path analysis**: Determine source interface and network
3. **Firewall rule analysis**: `fw_rules` filtered by source/destination
4. **Traffic inspection**: `packet_capture` with appropriate filters
5. **Log correlation**: `get_logs` for related source/destination traffic

**Expected Result**: Troubleshooting report including:
- Device network location and status
- Applicable firewall rules and their effects
- Live traffic analysis showing blocked/allowed packets
- Specific recommendations for resolution

---

## Best Practices

### Efficient Querying
- Use specific filters to reduce data volume
- Combine related queries (e.g., DHCP + ARP for device identification)
- Use packet capture judiciously - it can generate large amounts of data

### Security Considerations
- Review firewall logs regularly for security events
- Use packet capture to verify security policy effectiveness
- Monitor for unauthorized devices via DHCP/ARP analysis

### Troubleshooting Workflow
1. Start with device identification (DHCP/ARP)
2. Check system status and interface health
3. Review relevant firewall rules
4. Analyze historical logs
5. Use packet capture for real-time analysis
6. Correlate findings across all data sources

### Performance Tips
- Use time-limited packet captures (30-300 seconds)
- Apply BPF filters to focus on relevant traffic
- Limit log queries with appropriate filters
- Monitor system resources during intensive operations

---

## Integration with AI Agents

The OPNsense MCP Server is designed to work seamlessly with AI agents that can:

- **Interpret natural language queries** and translate them into appropriate function calls
- **Correlate data across multiple functions** to provide comprehensive answers
- **Suggest follow-up actions** based on discovered information
- **Provide security recommendations** based on traffic and log analysis
- **Automate routine monitoring tasks** using scheduled queries

The agent automatically handles the complexity of multi-step queries, allowing users to ask high-level questions and receive detailed, actionable responses.
