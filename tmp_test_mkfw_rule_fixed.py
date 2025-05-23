#!/usr/bin/env python3

import asyncio
import json
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from opnsense_mcp.utils.api import OPNsenseClient
from opnsense_mcp.tools.mkfw_rule import MkfwRuleTool

async def test_mkfw_rule():
    """Test the mkfw_rule tool with the fixed API endpoints"""
    
    # Load configuration
    config = {
        "firewall_host": os.getenv("OPNSENSE_HOST", "192.168.1.1"),
        "api_key": os.getenv("OPNSENSE_API_KEY"),
        "api_secret": os.getenv("OPNSENSE_API_SECRET"),
    }
    
    if not config["api_key"] or not config["api_secret"]:
        print("Error: OPNSENSE_API_KEY and OPNSENSE_API_SECRET environment variables must be set")
        return
    
    print(f"Testing mkfw_rule with host: {config['firewall_host']}")
    
    # Initialize client and tool
    client = OPNsenseClient(config)
    mkfw_tool = MkfwRuleTool(client)
    
    # Test case: Block ICMP from morpheus to pi3.freeblizz.com
    test_params = {
        "description": "Test API Rule - Block morpheus ICMP to pi3",
        "action": "block",
        "protocol": "icmp",
        "source_net": "10.0.2.58",  # morpheus IP
        "destination_net": "any",  # Use "any" instead of hostname
        # Don't specify interface - let it use the default (empty string)
        "apply": False  # Don't apply immediately for testing
    }
    
    print(f"\nTesting rule creation with parameters:")
    print(json.dumps(test_params, indent=2))
    
    try:
        result = await mkfw_tool.execute(test_params)
        print(f"\nResult:")
        print(json.dumps(result, indent=2))
        
        if result.get("status") == "success":
            print(f"\n✅ SUCCESS: Rule created with UUID: {result.get('rule_uuid')}")
            
            # If we got a UUID, try to apply the changes
            if result.get("rule_uuid") and not result.get("applied"):
                print("\nTesting apply changes...")
                apply_result = await client.apply_firewall_changes()
                print(f"Apply result: {json.dumps(apply_result, indent=2)}")
                
        else:
            print(f"\n❌ FAILED: {result.get('error', 'Unknown error')}")
            
    except Exception as e:
        print(f"\n❌ EXCEPTION: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_mkfw_rule()) 
