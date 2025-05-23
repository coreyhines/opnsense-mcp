#!/usr/bin/env python3

import asyncio
import json
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from opnsense_mcp.utils.api import OPNsenseClient
from opnsense_mcp.tools.mkfw_rule import MkfwRuleTool, FirewallRuleSpec

async def debug_mkfw_tool():
    """Debug the MkfwRuleTool to see what data it's generating"""
    
    # Load configuration
    config = {
        "firewall_host": os.getenv("OPNSENSE_HOST", "192.168.1.1"),
        "api_key": os.getenv("OPNSENSE_API_KEY"),
        "api_secret": os.getenv("OPNSENSE_API_SECRET"),
    }
    
    if not config["api_key"] or not config["api_secret"]:
        print("Error: OPNSENSE_API_KEY and OPNSENSE_API_SECRET environment variables must be set")
        return
    
    print(f"Testing MkfwRuleTool with host: {config['firewall_host']}")
    
    # Initialize client and tool
    client = OPNsenseClient(config)
    mkfw_tool = MkfwRuleTool(client)
    
    # Test parameters
    test_params = {
        "description": "Test API Rule - Debug",
        "action": "block",
        "protocol": "icmp",
        "source_net": "10.0.2.58",
        "destination_net": "any",
        # Don't specify interface - let it use the default (empty string)
        "apply": False
    }
    
    print(f"\nInput parameters:")
    print(json.dumps(test_params, indent=2))
    
    # Create rule spec to see what it generates
    try:
        rule_spec = FirewallRuleSpec(**test_params)
        print(f"\n✅ FirewallRuleSpec created successfully:")
        print(f"  description: {rule_spec.description}")
        print(f"  action: {rule_spec.action}")
        print(f"  protocol: {rule_spec.protocol}")
        print(f"  source_net: {rule_spec.source_net}")
        print(f"  destination_net: {rule_spec.destination_net}")
        print(f"  interface: {rule_spec.interface}")
        print(f"  enabled: {rule_spec.enabled}")
        
        # Build rule data like the tool does
        rule_data = {
            "description": rule_spec.description,
            "interface": rule_spec.interface,
            "action": rule_spec.action,
            "protocol": rule_spec.protocol.upper(),
            "source_net": rule_spec.source_net,
            "destination_net": rule_spec.destination_net,
            "enabled": "1" if rule_spec.enabled else "0",
            "direction": rule_spec.direction,
            "ipprotocol": rule_spec.ipprotocol,
        }
        
        print(f"\n✅ Generated rule_data:")
        print(json.dumps(rule_data, indent=2))
        
        # Test this rule data directly with add_firewall_rule
        print(f"\nTesting rule_data with add_firewall_rule...")
        response = await client.add_firewall_rule(rule_data)
        print(f"✅ SUCCESS: {json.dumps(response, indent=2)}")
        
        # Also test the actual MkfwRuleTool
        print(f"\nTesting with actual MkfwRuleTool...")
        mkfw_tool = MkfwRuleTool(client)
        tool_response = await mkfw_tool.execute(test_params)
        print(f"Tool response: {json.dumps(tool_response, indent=2)}")
        
    except Exception as e:
        print(f"\n❌ EXCEPTION: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(debug_mkfw_tool()) 
