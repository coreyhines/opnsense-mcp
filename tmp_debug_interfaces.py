#!/usr/bin/env python3

import asyncio
import json
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from opnsense_mcp.utils.api import OPNsenseClient

async def test_interfaces():
    """Test different interface values to see what works"""
    
    # Load configuration
    config = {
        "firewall_host": os.getenv("OPNSENSE_HOST", "192.168.1.1"),
        "api_key": os.getenv("OPNSENSE_API_KEY"),
        "api_secret": os.getenv("OPNSENSE_API_SECRET"),
    }
    
    if not config["api_key"] or not config["api_secret"]:
        print("Error: OPNSENSE_API_KEY and OPNSENSE_API_SECRET environment variables must be set")
        return
    
    print(f"Testing interfaces with host: {config['firewall_host']}")
    
    # Initialize client
    client = OPNsenseClient(config)
    
    # First, let's see what interfaces are available via ARP
    print("\n" + "="*50)
    print("Available interfaces from ARP table:")
    try:
        arp_table = await client.get_arp_table()
        interfaces = set()
        for entry in arp_table:
            if 'intf' in entry:
                interfaces.add(entry['intf'])
        print(f"Found interfaces: {sorted(interfaces)}")
    except Exception as e:
        print(f"Error getting ARP table: {e}")
    
    # Base working rule
    base_rule = {
        "description": "Test Interface Values",
        "source_net": "10.0.2.58",
        "protocol": "ICMP",
        "destination_net": "any"
    }
    
    # Test different interface values
    interface_tests = [
        "lan",
        "LAN", 
        "wan",
        "WAN",
        "",  # empty string
        "any",
        "opt1",
        "em0",
        "igb0",
        "vtnet0",
        "ax0_vlan2",  # from our ARP results
    ]
    
    for interface in interface_tests:
        print(f"\n{'='*50}")
        print(f"Testing interface: '{interface}'")
        
        rule_data = {**base_rule, "interface": interface}
        print(f"Rule data: {json.dumps(rule_data, indent=2)}")
        
        try:
            response = await client.add_firewall_rule(rule_data)
            print(f"✅ SUCCESS: {json.dumps(response, indent=2)}")
        except Exception as e:
            print(f"❌ FAILED: {str(e)}")
    
    # Test without interface field at all
    print(f"\n{'='*50}")
    print("Testing without interface field:")
    print(f"Rule data: {json.dumps(base_rule, indent=2)}")
    
    try:
        response = await client.add_firewall_rule(base_rule)
        print(f"✅ SUCCESS: {json.dumps(response, indent=2)}")
    except Exception as e:
        print(f"❌ FAILED: {str(e)}")

if __name__ == "__main__":
    asyncio.run(test_interfaces()) 
