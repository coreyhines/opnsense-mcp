#!/usr/bin/env python3

import asyncio
import json
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from opnsense_mcp.utils.api import OPNsenseClient

async def debug_add_firewall_rule():
    """Debug the add_firewall_rule method specifically"""
    
    # Load configuration
    config = {
        "firewall_host": os.getenv("OPNSENSE_HOST", "192.168.1.1"),
        "api_key": os.getenv("OPNSENSE_API_KEY"),
        "api_secret": os.getenv("OPNSENSE_API_SECRET"),
    }
    
    if not config["api_key"] or not config["api_secret"]:
        print("Error: OPNSENSE_API_KEY and OPNSENSE_API_SECRET environment variables must be set")
        return
    
    print(f"Testing add_firewall_rule with host: {config['firewall_host']}")
    
    # Initialize client
    client = OPNsenseClient(config)
    
    # Test the exact same request that worked in our direct test
    rule_data = {
        "description": "Test API Rule Minimal",
        "source_net": "10.0.2.58",
        "protocol": "ICMP",
        "destination_net": "any"
    }
    
    print(f"\nTesting add_firewall_rule with data:")
    print(json.dumps(rule_data, indent=2))
    
    try:
        # Call the add_firewall_rule method directly
        response = await client.add_firewall_rule(rule_data)
        
        print(f"\n✅ SUCCESS: add_firewall_rule returned:")
        print(json.dumps(response, indent=2))
        
    except Exception as e:
        print(f"\n❌ EXCEPTION in add_firewall_rule: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(debug_add_firewall_rule()) 
