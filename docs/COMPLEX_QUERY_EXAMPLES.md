# Complex Query Examples - OPNsense MCP Server

This document demonstrates how the OPNsense MCP Server and AI agents work together to handle sophisticated network management queries that require multiple function calls and data correlation.

## Understanding the AI Agent's Workflow

The AI agent automatically:
1. **Parses natural language queries** into specific technical requirements
2. **Plans multi-step workflows** using available MCP functions
3. **Executes functions in parallel** when possible for efficiency
4. **Correlates data** from different sources to provide comprehensive answers
5. **Provides actionable recommendations** based on the analysis

---

## Real-World Scenarios

### Scenario 1: "What is morpheus doing on the network?"

**User Query**: "What is morpheus doing on the network?"

**AI Agent Analysis Process**:

#### Step 1: Device Identification
```bash
# Agent executes in parallel:
dhcp search="morpheus"
arp search="morpheus"
```

**Sample Results**:
- **DHCP**: `morpheus` → IP: `10.0.2.150`, MAC: `52:54:00:12:34:56`, Lease expires: 2024-12-15 14:30:00
- **ARP**: IP: `10.0.2.150` → MAC: `52:54:00:12:34:56`, Interface: `ax0_vlan2` (Wired LAN)

#### Step 2: Historical Activity Analysis
```bash
# Agent executes in parallel:
get_logs src_ip="10.0.2.150" limit=100
get_logs dst_ip="10.0.2.150" limit=100
fw_rules interface="lan"
```

**Sample Results**:
- **Outbound Traffic**: 45 HTTPS connections to various websites, 12 SSH connections to internal servers
- **Inbound Traffic**: 3 SSH sessions from management network, HTTP responses
- **Applicable Rules**: Allow SSH from mgmt network, allow web traffic, block P2P

#### Step 3: Live Traffic Analysis
```bash
# Agent executes targeted packet capture:
packet_capture interface="ax0_vlan2" filter="host 10.0.2.150" duration=60 count=200
```

**Sample Results**:
- **Active Connections**: SSH session to `10.0.1.5:22`, HTTPS to `api.github.com:443`
- **Traffic Volume**: 2.3 MB/min outbound, 450 KB/min inbound
- **Protocols**: 75% HTTPS, 20% SSH, 5% DNS

#### AI Agent's Comprehensive Response:

> **morpheus Network Activity Summary**
> 
> **Device Details:**
> - **Location**: Wired LAN (VLAN2) via interface ax0_vlan2
> - **IP Address**: 10.0.2.150 (DHCP lease active until Dec 15, 2:30 PM)
> - **MAC Address**: 52:54:00:12:34:56
> 
> **Current Activity:**
> - **Active SSH session** to internal server 10.0.1.5 (likely development/admin work)
> - **GitHub API interaction** via HTTPS (development activity)
> - **Low-volume steady traffic** indicating interactive use
> 
> **Recent Patterns (last 24h):**
> - **45 web connections** to development and documentation sites
> - **12 SSH sessions** to internal infrastructure
> - **No blocked connections** - all traffic within policy
> 
> **Security Assessment**: ✅ **Normal behavior** - consistent with development workstation usage patterns

---

### Scenario 2: "Is there suspicious traffic on the network?"

**User Query**: "Is there suspicious traffic on the network?"

**AI Agent Analysis Process**:

#### Step 1: System Health Check
```bash
system
```

**Sample Results**:
- CPU: 15%, Memory: 65%, Uptime: 12 days
- All interfaces operational

#### Step 2: Security Event Analysis
```bash
# Agent executes in parallel:
get_logs action="block" limit=200
get_logs protocol="icmp" limit=50
fw_rules action="block"
```

**Sample Results**:
- **Blocked Traffic**: 23 attempts from external IPs to SSH (port 22)
- **ICMP Traffic**: Normal ping responses, no scanning patterns
- **Active Block Rules**: 15 rules blocking known malicious IPs

#### Step 3: Device Inventory Check
```bash
# Agent executes in parallel:
dhcp
arp
lldp
```

**Sample Results**:
- **DHCP Leases**: 12 known devices, all with recognized hostnames
- **ARP Table**: No unknown MAC addresses in trusted VLANs
- **LLDP**: All expected network equipment present

#### Step 4: Traffic Pattern Analysis
```bash
# Agent executes parallel captures on key interfaces:
packet_capture interface="wan" filter="not port 53 and not port 443" duration=120 count=500
packet_capture interface="ax0_vlan81" filter="port 53" duration=60 count=100
```

**Sample Results**:
- **WAN Traffic**: Normal web browsing patterns, no bulk data transfers
- **DNS Traffic**: All queries going to configured DoH servers (✅ privacy protection active)
- **No suspicious patterns**: No port scans, DDoS attempts, or data exfiltration

#### AI Agent's Comprehensive Response:

> **Network Security Assessment**
> 
> **🔒 Security Status: GOOD**
> 
> **Threat Activity:**
> - **23 SSH brute-force attempts** from external IPs (all blocked ✅)
> - **No internal threats detected**
> - **No unauthorized devices** found on trusted networks
> 
> **Privacy Protection:**
> - **DNS over HTTPS active** on all internal VLANs ✅
> - **No DNS leaks detected** in guest/solar networks ✅
> - **Normal encrypted traffic patterns** observed
> 
> **Recommendations:**
> - SSH brute-force activity is normal and being blocked effectively
> - Consider fail2ban for repeat offenders
> - Current security posture is effective

---

### Scenario 3: "Why can't my IoT device reach the internet?"

**User Query**: "My smart thermostat can't connect to the internet. It's supposed to be on the IoT VLAN."

**AI Agent Analysis Process**:

#### Step 1: Device Identification
```bash
# Agent searches across all discovery methods:
dhcp search="thermostat"
arp search="192.168.100"  # assuming IoT VLAN range
lldp  # check for unexpected device connections
```

**Sample Results**:
- **DHCP**: No lease found for "thermostat"
- **ARP**: Device found at 192.168.100.15 with MAC `aa:bb:cc:dd:ee:10`
- **LLDP**: No direct connections (normal for wireless IoT)

#### Step 2: Network Path Analysis
```bash
# Agent checks IoT VLAN configuration:
fw_rules interface="iot"
interface_list
```

**Sample Results**:
- **IoT Interface**: `ax0_vlan100` configured
- **Firewall Rules**: Block inter-VLAN, allow DNS/NTP/HTTPS outbound

#### Step 3: Traffic Analysis
```bash
# Agent captures traffic from the IoT device:
packet_capture interface="ax0_vlan100" filter="host 192.168.100.15" duration=60
get_logs src_ip="192.168.100.15" dst_ip="192.168.100.15"
```

**Sample Results**:
- **Outbound Attempts**: HTTPS to `api.nest.com` - **BLOCKED**
- **DNS Queries**: Working correctly
- **Firewall Logs**: Rule "Block IoT to Internet" blocking HTTPS traffic

#### Step 4: Rule Investigation
```bash
# Agent examines specific blocking rule:
fw_rules interface="iot" action="block"
```

**Sample Results**:
- **Blocking Rule Found**: "Block IoT Internet Access" created 2024-12-10
- **Rule Details**: Blocks all outbound traffic except DNS/NTP

#### AI Agent's Comprehensive Response:

> **IoT Device Connectivity Issue Diagnosed**
> 
> **Device Details:**
> - **Found**: 192.168.100.15 on IoT VLAN (ax0_vlan100)
> - **MAC Address**: aa:bb:cc:dd:ee:10
> - **DHCP Status**: ⚠️ **No hostname lease** (device may be using static IP)
> 
> **Root Cause:**
> - **Firewall rule "Block IoT Internet Access"** is preventing HTTPS connections
> - **DNS and NTP work** correctly (device can resolve names and sync time)
> - **HTTPS to api.nest.com blocked** by security policy
> 
> **Solutions:**
> 1. **Create specific allow rule** for nest.com API endpoints
> 2. **Modify existing rule** to allow specific IoT cloud services
> 3. **Consider IoT whitelist approach** instead of blanket blocking
> 
> **Recommended Action:**
> ```bash
> mkfw_rule description="Allow Nest API access" interface="iot" action="pass" 
>           destination_net="api.nest.com" destination_port="443" protocol="tcp"
> ```

---

### Scenario 4: "Check what's happening with the guest network"

**User Query**: "The guest WiFi seems slow today. Can you check what's happening?"

**AI Agent Analysis Process**:

#### Step 1: Guest Network Overview
```bash
# Agent gathers guest network information:
dhcp search="guest"
arp ip="10.0.4"  # guest VLAN range
interface_list
```

**Sample Results**:
- **Active Guests**: 8 devices on 10.0.4.0/24
- **Interface**: ax0_vlan4guest_wifi
- **Devices**: Mix of phones, laptops, tablets

#### Step 2: Traffic Volume Analysis
```bash
# Agent captures and analyzes guest traffic:
packet_capture interface="ax0_vlan4guest_wifi" duration=120 count=1000
get_logs src_ip="10.0.4" limit=200
```

**Sample Results**:
- **High Volume Device**: 10.0.4.23 consuming 15 MB/min
- **Traffic Type**: Video streaming (YouTube, Netflix)
- **Other Devices**: Normal web browsing (< 1 MB/min each)

#### Step 3: Bandwidth and Performance Analysis
```bash
# Agent examines system performance:
system
fw_rules interface="guest"
```

**Sample Results**:
- **Firewall CPU**: 8% (normal)
- **Guest Rules**: Rate limiting: 10 Mbps per device
- **Quality of Service**: Guest traffic deprioritized

#### AI Agent's Comprehensive Response:

> **Guest Network Performance Analysis**
> 
> **Current Status:**
> - **8 active devices** on guest VLAN (10.0.4.0/24)
> - **Total guest traffic**: ~20 MB/min
> - **Firewall performance**: Normal (8% CPU)
> 
> **Performance Issue Identified:**
> - **Device 10.0.4.23** consuming 75% of guest bandwidth
> - **Activity**: Heavy video streaming (YouTube/Netflix)
> - **Impact**: Other guests experiencing reduced speeds
> 
> **Quality of Service Status:**
> - **Rate limiting active**: 10 Mbps per device ✅
> - **Traffic prioritization**: Guest traffic correctly deprioritized ✅
> 
> **Recommendations:**
> 1. Current rate limiting is working as designed
> 2. Consider reducing per-device limit to 5 Mbps for more fair sharing
> 3. Guest network performance is normal given the streaming activity

---

## Data Correlation Patterns

### Device Identification Workflow
1. **Primary**: DHCP lease lookup by hostname
2. **Secondary**: ARP table search by IP/MAC
3. **Tertiary**: Firewall log correlation
4. **Validation**: Cross-reference all sources for consistency

### Security Analysis Workflow
1. **Reactive**: Analyze firewall logs for blocked traffic
2. **Proactive**: Live packet capture for anomaly detection
3. **Contextual**: Compare against firewall rules and policies
4. **Comprehensive**: System health and performance impact assessment

### Troubleshooting Workflow
1. **Identification**: Locate device in network topology
2. **Path Analysis**: Trace network path and applicable rules
3. **Traffic Inspection**: Examine actual vs. expected traffic
4. **Root Cause**: Identify specific blocking/routing issues
5. **Solution**: Provide specific configuration changes

---

## Advanced Query Types

### Time-Based Analysis
- **"What happened to the network around 2 PM yesterday?"**
- **"Show me traffic patterns for the last hour"**
- **"Which devices were most active this morning?"**

### Comparative Analysis
- **"Compare current traffic to last week"**
- **"Which VLAN has the most blocked traffic?"**
- **"Show differences in DNS usage between networks"**

### Predictive Monitoring
- **"Monitor for any new devices joining the network"**
- **"Alert if any device starts using unusual protocols"**
- **"Watch for DNS leak patterns in DoH networks"**

### Security-Focused Queries
- **"Find any devices bypassing the firewall rules"**
- **"Detect port scanning attempts"**
- **"Identify devices with suspicious traffic patterns"**

---

## Best Practices for Complex Queries

### For Users
1. **Be specific about scope**: "guest network" vs. "entire network"
2. **Include timeframes**: "in the last hour" vs. "today"
3. **Mention relevant context**: "after the rule change" or "since the update"

### For AI Agents
1. **Start broad, then narrow**: System overview → specific device analysis
2. **Correlate across functions**: Always cross-reference DHCP + ARP + Logs
3. **Provide actionable output**: Include specific commands or recommendations
4. **Consider performance impact**: Use time limits and filters appropriately

### For Network Administrators
1. **Monitor query patterns**: Understanding what users ask helps improve rule documentation
2. **Optimize for common queries**: Pre-filter logs and organize rules for typical workflows
3. **Maintain naming conventions**: Consistent device hostnames improve query accuracy
