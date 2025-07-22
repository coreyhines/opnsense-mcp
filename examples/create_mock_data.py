#!/usr/bin/env python3
"""
Mock data script for MCP server development testing.

Creates example data files for development mode.
"""

import json
from datetime import datetime, timedelta
from pathlib import Path

# Current directory
current_dir = Path(__file__).parent.resolve()
mock_data_dir = current_dir / "mock_data"

# Create mock data directory if it doesn't exist
if not mock_data_dir.exists():
    mock_data_dir.mkdir(parents=True)

# Create system status mock data
system_status = {
    "cpu_usage": 15.5,
    "memory_usage": 45.2,
    "filesystem_usage": {"/": 32.5, "/var": 18.2, "/boot": 5.7},
    "uptime": "5 days, 12:34:56",
    "versions": {
        "opnsense": "23.7.3",
        "kernel": "13.2-RELEASE-p1",
        "php": "8.2.9",
        "python": "3.9.16",
    },
    "temperature": {"cpu0": "45°C", "cpu1": "48°C"},
}

# Create ARP table mock data
arp_data = {
    "entries": [
        {
            "ip": "192.168.1.10",
            "mac": "00:11:22:33:44:55",
            "interface": "igb0",
            "hostname": "desktop-pc.local",
            "expiry": "1200",
            "manufacturer": "Intel Corporate",
            "static": False,
        },
        {
            "ip": "192.168.1.20",
            "mac": "aa:bb:cc:dd:ee:ff",
            "interface": "igb0",
            "hostname": "laptop.local",
            "expiry": "1150",
            "manufacturer": "Apple, Inc.",
            "static": False,
        },
        {
            "ip": "192.168.1.1",
            "mac": "00:aa:bb:cc:dd:ee",
            "interface": "igb0",
            "hostname": "router.local",
            "expiry": "permanent",
            "manufacturer": "Netgear",
            "static": True,
        },
    ],
    "count": 3,
    "status": "success",
}

# Create interface data mock
interface_data = {
    "interfaces": [
        {
            "name": "igb0",
            "description": "WAN",
            "status": "up",
            "addresses": [
                {"address": "203.0.113.1", "netmask": "24", "type": "ipv4"},
                {"address": "2001:db8::1", "netmask": "64", "type": "ipv6"},
            ],
            "media": "Ethernet autoselect (1000baseT <full-duplex>)",
            "mtu": 1500,
        },
        {
            "name": "igb1",
            "description": "LAN",
            "status": "up",
            "addresses": [
                {"address": "192.168.1.1", "netmask": "24", "type": "ipv4"},
                {"address": "fd00::1", "netmask": "64", "type": "ipv6"},
            ],
            "media": "Ethernet autoselect (1000baseT <full-duplex>)",
            "mtu": 1500,
        },
    ],
    "status": "success",
}

# Create firewall rules mock data
firewall_data = {
    "rules": [
        {
            "id": "1",
            "sequence": 1,
            "description": "Allow LAN to WAN",
            "interface": "lan",
            "protocol": "any",
            "source": {"net": "lan", "port": "any"},
            "destination": {"net": "wan", "port": "any"},
            "action": "pass",
            "enabled": True,
            "gateway": "",
            "direction": "out",
            "ipprotocol": "inet",
        },
        {
            "id": "2",
            "sequence": 2,
            "description": "Block WAN to LAN",
            "interface": "wan",
            "protocol": "any",
            "source": {"net": "wan", "port": "any"},
            "destination": {"net": "lan", "port": "any"},
            "action": "block",
            "enabled": True,
            "gateway": "",
            "direction": "in",
            "ipprotocol": "inet",
        },
    ],
    "count": 2,
    "status": "success",
}

# Create firewall logs mock data
# Generate realistic firewall logs for the past hour
now = datetime.now()
firewall_logs = []
events = [
    {
        "interface": "WAN",
        "action": "block",
        "protocol": "tcp",
        "src_ip": "203.0.113.100",
        "src_port": 12345,
        "dst_ip": "192.168.1.10",
        "dst_port": 22,
        "description": "SSH connection attempt blocked",
    },
    {
        "interface": "LAN",
        "action": "pass",
        "protocol": "tcp",
        "src_ip": "192.168.1.20",
        "src_port": 54321,
        "dst_ip": "8.8.8.8",
        "dst_port": 443,
        "description": "HTTPS traffic allowed",
    },
    {
        "interface": "WAN",
        "action": "block",
        "protocol": "udp",
        "src_ip": "203.0.113.200",
        "src_port": 5060,
        "dst_ip": "192.168.1.1",
        "dst_port": 5060,
        "description": "SIP traffic blocked",
    },
]

# Generate 50 log entries over the past hour
for i in range(50):
    event = events[i % len(events)]
    timestamp = now - timedelta(minutes=i)
    log_entry = {"timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S"), **event}
    firewall_logs.append(log_entry)

# Create services mock data
services_data = {
    "services": [
        {
            "id": "dhcpd",
            "name": "DHCP Server",
            "description": "Dynamic Host Configuration Protocol server",
            "status": "running",
            "enabled": True,
        },
        {
            "id": "unbound",
            "name": "Unbound DNS",
            "description": "DNS Resolver",
            "status": "running",
            "enabled": True,
        },
        {
            "id": "openvpn",
            "name": "OpenVPN Server",
            "description": "Virtual Private Network server",
            "status": "stopped",
            "enabled": False,
        },
    ],
    "status": "success",
    "total": 3,
}

# Define files to write
mock_files = {
    "system_status.json": system_status,
    "arp_table.json": arp_data,
    "interfaces.json": interface_data,
    "firewall_rules.json": firewall_data,
    "services.json": services_data,
    "firewall_logs.json": {"logs": firewall_logs, "status": "success"},
}

# Write mock data files
for filename, data in mock_files.items():
    file_path = mock_data_dir / filename
    with Path(file_path).open("w") as f:
        json.dump(data, f, indent=2)
    print(f"Created mock data file: {file_path}")

print(f"\nMock data for development has been created in {mock_data_dir}")
print("You can now use these files with the mock_api option in your config.")
print(
    "Ensure your config has development.mock_api=true and "
    "development.mock_data_path points to this directory."
)
