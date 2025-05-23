#!/usr/bin/env python3

import asyncio
import json
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from opnsense_mcp.utils.api import OPNsenseClient

async def test_field_combinations():
    """Test different field combinations to find what's causing the error"""
    
    # Load configuration
    config = {
        "firewall_host": os.getenv("OPNSENSE_HOST", "192.168.1.1"),
        "api_key": os.getenv("OPNSENSE_API_KEY"),
        "api_secret": os.getenv("OPNSENSE_API_SECRET"),
    }
    
    if not config["api_key"] or not config["api_secret"]:
        print("Error: OPNSENSE_API_KEY and OPNSENSE_API_SECRET environment variables must be set")
        return
    
    print(f"Testing field combinations with host: {config['firewall_host']}")
    
    # Initialize client
    client = OPNsenseClient(config)
    
    # Base working rule
    base_rule = {
        "description": "Test Field Combinations",
        "source_net": "10.0.2.58",
        "protocol": "ICMP",
        "destination_net": "any"
    }
    
    # Test cases - progressively add fields
    test_cases = [
        ("Base (working)", base_rule),
        ("+ interface", {**base_rule, "interface": "lan"}),
        ("+ action", {**base_rule, "interface": "lan", "action": "block"}),
        ("+ enabled", {**base_rule, "interface": "lan", "action": "block", "enabled": "1"}),
        ("+ direction", {**base_rule, "interface": "lan", "action": "block", "enabled": "1", "direction": "in"}),
        ("+ ipprotocol", {**base_rule, "interface": "lan", "action": "block", "enabled": "1", "direction": "in", "ipprotocol": "inet"}),
    ]
    
    for test_name, rule_data in test_cases:
        print(f"\n{'='*50}")
        print(f"Testing: {test_name}")
        print(f"Rule data: {json.dumps(rule_data, indent=2)}")
        
        try:
            response = await client.add_firewall_rule(rule_data)
            print(f"✅ SUCCESS: {json.dumps(response, indent=2)}")
        except Exception as e:
            print(f"❌ FAILED: {str(e)}")

if __name__ == "__main__":
    asyncio.run(test_field_combinations()) 
