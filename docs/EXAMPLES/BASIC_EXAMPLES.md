# Basic Examples - OPNsense MCP Server

> **Simple, common use cases to get you started with AI-powered network management**

This guide provides basic examples that demonstrate fundamental capabilities of the OPNsense MCP Server. These examples are perfect for new users who want to understand what's possible and how to interact with their network using natural language.

## 🔍 Network Discovery Examples

### **Find All Devices on the Network**

**User Query**: "Show me all devices on the network"

**What the AI does**: Uses `arp` and `dhcp` tools to provide a comprehensive device list

**Example Response**:
```
ARP Table Results:
- 192.168.1.1 (aa:bb:cc:dd:ee:ff) - Deciso B.V. - Interface: ax0 - Permanent
- 192.168.1.33 (11:22:33:44:55:66) - Mojo Networks, Inc. - Interface: ax0 - Expires: 1200s
- 192.168.1.64 (aa:bb:cc:dd:ee:ff) - Mojo Networks, Inc. - Interface: ax0 - Expires: 875s
- 192.168.1.69 (d5:5c:e3:36:87:0e) - Arista Network, Inc. - Interface: ax0 - Expires: 928s

VLAN 2 Devices:
- 10.0.2.10 (aa:bb:cc:dd:ee:ff) - Raspberry Pi Trading Ltd - Interface: ax0_vlan2 - Expires: 1195s
- 10.0.2.175 (ad:2e:b5:d9:75:c8) - Private - Hostname: coreymbp - Expires: 1152s
- 10.0.2.1 (aa:bb:cc:dd:ee:ff) - Deciso B.V. - Interface: ax0_vlan2 - Permanent
```

### **Find a Specific Device**

**User Query**: "Find my laptop"

**What the AI does**: Searches DHCP leases and ARP table for devices matching "laptop"

**Example Response**:
```
Device Found:
- IP Address: 192.168.1.100
- MAC Address: aa:bb:cc:dd:ee:ff
- Hostname: coreymbp
- Interface: ax0 (Wired LAN)
- DHCP Lease: Active until 2024-12-15 14:30:00
- Manufacturer: Apple, Inc.
```

### **Show Network Topology**

**User Query**: "Show me LLDP neighbors"

**What the AI does**: Uses `lldp` tool to display connected network devices

**Example Response**:
```
LLDP Neighbor Table:
- Interface: igb3
  - Neighbor: Arista Networks Switch
  - MAC: aa:bb:cc:dd:ee:ff
  - IP: 10.0.9.246
  - Port: Ethernet1/1
  - System: Arista-DCS-7050S-64

- Interface: ax0
  - Neighbor: Mojo Networks AP
  - MAC: 11:22:33:44:55:66
  - IP: 192.168.1.33
  - Port: eth0
  - System: Mojo-AP-1234
```

## 📊 System Monitoring Examples

### **Check System Status**

**User Query**: "What's the system status?"

**What the AI does**: Uses `system` tool to show firewall health and performance

**Example Response**:
```
System Status:
- Hostname: fw.example.com
- OPNsense Version: OPNsense 25.7-amd64
- Kernel: FreeBSD 14.3-RELEASE-p1
- Uptime: 12 days, 3 hours, 45 minutes
- CPU Usage: 15%
- Memory Usage: 65%
- Status: Online and operational
```

### **Check Interface Status**

**User Query**: "Show me interface status"

**What the AI does**: Uses `interface_list` tool to show all available interfaces

**Example Response**:
```
Available Interfaces:
- ax0 (LAN) - Status: UP - IP: 192.168.1.1/24
- ax1 (WAN) - Status: UP - IP: 203.0.113.91/24
- ax0_vlan2 (VLAN2) - Status: UP - IP: 10.0.2.1/24
- ax0_vlan3 (VLAN3) - Status: UP - IP: 10.0.3.1/24
- ax0_vlan4 (VLAN4) - Status: UP - IP: 10.0.4.1/24
```

## 🛡️ Firewall Management Examples

### **Show Current Firewall Rules**

**User Query**: "Show me firewall rules"

**What the AI does**: Uses `fw_rules` tool to display current firewall configuration

**Example Response**:
```
Firewall Rules Summary:
- Total Rules: 45
- Active Rules: 42
- Disabled Rules: 3

Key Rules:
1. Default allow LAN to any (Rule #1) - ACTIVE
2. Block IoT Internet Access (Rule #15) - ACTIVE
3. Allow Guest WiFi (Rule #23) - ACTIVE
4. Block P2P Traffic (Rule #31) - ACTIVE
5. Allow Management Network (Rule #42) - ACTIVE
```

### **Create a Simple Firewall Rule**

**User Query**: "Block traffic from 192.168.1.100"

**What the AI does**: Uses `mkfw_rule` tool to create a blocking rule

**Example Response**:
```
Firewall Rule Created:
- Description: Block traffic from 192.168.1.100
- Action: Block
- Interface: LAN
- Protocol: Any
- Source: 192.168.1.100
- Destination: Any
- Direction: In
- Status: Enabled and applied
- Rule UUID: 12345678-1234-1234-1234-123456789abc
```

### **Delete a Firewall Rule**

**User Query**: "Delete the rule blocking 192.168.1.100"

**What the AI does**: Uses `rmfw_rule` tool to remove the specified rule

**Example Response**:
```
Firewall Rule Deleted:
- Rule UUID: 12345678-1234-1234-1234-123456789abc
- Description: Block traffic from 192.168.1.100
- Status: Successfully removed and applied
```

## 🔬 Traffic Analysis Examples

### **Show Recent Firewall Logs**

**User Query**: "Show me recent firewall logs"

**What the AI does**: Uses `get_logs` tool to display recent firewall activity

**Example Response**:
```
Recent Firewall Logs (Last 5 entries):
1. 2025-07-31T08:26:01-05:00 - BLOCK - UDP - 10.0.7.3:123 → 10.0.2.3:123 - Interface: ax0_vlan7 - Rule: Default deny / state violation rule
2. 2025-07-31T08:25:58-05:00 - BLOCK - TCP - 203.0.113.148:53497 → 203.0.113.91:56539 - Interface: ax1 - Rule: Default deny / state violation rule
3. 2025-07-31T08:25:57-05:00 - BLOCK - TCP - 203.0.113.58:40462 → 203.0.113.91:795 - Interface: ax1 - Rule: Default deny / state violation rule
4. 2025-07-31T08:25:53-05:00 - BLOCK - TCP - 203.0.113.148:53497 → 203.0.113.91:56506 - Interface: ax1 - Rule: Default deny / state violation rule
5. 2025-07-31T08:25:52-05:00 - BLOCK - UDP - 10.0.7.4:123 → 10.0.2.3:123 - Interface: ax0_vlan7 - Rule: Default deny / state violation rule
```

### **Check DHCP Leases**

**User Query**: "Show me DHCP leases"

**What the AI does**: Uses `dhcp` tool to display active DHCP leases

**Example Response**:
```
DHCP Leases:
Active Leases:
- 192.168.1.100 - aa:bb:cc:dd:ee:ff - coreymbp - Expires: 2024-12-15 14:30:00
- 192.168.1.101 - 11:22:33:44:55:66 - morpheus - Expires: 2024-12-15 15:45:00
- 192.168.1.102 - aa:bb:cc:dd:ee:ff - trogdor - Expires: 2024-12-15 16:20:00

Expired Leases:
- 192.168.1.103 - aa:bb:cc:dd:ee:ff - guest-laptop - Expired: 2024-12-15 10:15:00
```

## 🔍 Search and Filter Examples

### **Search for a Specific Device**

**User Query**: "Find devices with MAC address aa:bb:cc:dd:ee:ff"

**What the AI does**: Uses `arp` tool with MAC filter

**Example Response**:
```
Device Found:
- IP Address: 192.168.1.100
- MAC Address: aa:bb:cc:dd:ee:ff
- Interface: ax0
- Hostname: coreymbp
- Manufacturer: Apple, Inc.
- Expires: 1200s
```

### **Search by IP Address**

**User Query**: "What device is using 192.168.1.100?"

**What the AI does**: Uses `arp` tool with IP filter

**Example Response**:
```
Device Details:
- IP Address: 192.168.1.100
- MAC Address: aa:bb:cc:dd:ee:ff
- Interface: ax0
- Hostname: coreymbp
- Manufacturer: Apple, Inc.
- DHCP Status: Active lease until 2024-12-15 14:30:00
```

## 🚀 Getting Started Tips

### **Start Simple**
Begin with basic queries like:
- "Show me all devices on the network"
- "What's the system status?"
- "Show me firewall rules"

### **Be Specific**
Instead of "Check the network," try:
- "Show me devices on VLAN 2"
- "Check if 192.168.1.100 is online"
- "Show me recent blocked connections"

### **Use Natural Language**
The AI understands conversational queries:
- "What's happening with my network?"
- "Is everything working okay?"
- "Show me any problems"

### **Combine Information**
Ask for comprehensive views:
- "Show me all devices and their current status"
- "What's the system health and recent activity?"
- "Give me a network overview"

## 📚 Next Steps

Once you're comfortable with these basic examples:

1. **Try Complex Queries**: See [Complex Examples](COMPLEX_EXAMPLES.md) for advanced scenarios
2. **Explore All Tools**: Review the [Function Reference](../REFERENCE/FUNCTION_REFERENCE.md)
3. **Customize Your Setup**: Learn about different integration options in the [Getting Started Guide](../GETTING_STARTED.md)

## 💡 Pro Tips

- **Use specific IP addresses** when you know them
- **Mention interface names** for targeted queries
- **Ask for explanations** when you don't understand the results
- **Combine multiple queries** for comprehensive analysis
- **Use the AI's suggestions** for follow-up questions 
