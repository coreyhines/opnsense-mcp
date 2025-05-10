#!/usr/bin/env python3
"""
OPNsense MCP API Interactive Tester

This script provides an interactive environment for testing the enhanced OPNsense MCP API.
It's designed to be used within an IDE or development environment for quick API exploration.
"""

import os
import sys
import json
import asyncio
import argparse
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
import yaml

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class APITester:
    """Interactive API tester class"""
    
    def __init__(self, config_path):
        """Initialize tester with config"""
        self.config = self._load_config(config_path)
        self.client = None
        self.tools = {}
    
    def _load_config(self, config_path):
        """Load configuration from file"""
        try:
            path = Path(config_path)
            if not path.exists():
                logger.error(f"Config file not found: {config_path}")
                sys.exit(1)
                
            if path.suffix in ['.yaml', '.yml']:
                with open(path, 'r') as f:
                    return yaml.safe_load(f)
            else:
                with open(path, 'r') as f:
                    return json.load(f)
                    
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            sys.exit(1)
    
    async def setup(self):
        """Initialize API client and tools"""
        try:
            # Import API client
            from mcp_server.utils.api_new import OPNsenseClient
            self.client = OPNsenseClient(self.config['opnsense'])
            logger.info(f"Connected to OPNsense at {self.config['opnsense']['firewall_host']}")
            
            # Import all tools
            self.tools = await self._load_tools()
            logger.info(f"Loaded {len(self.tools)} API tools")
        except Exception as e:
            logger.error(f"Failed to initialize API client: {e}")
            sys.exit(1)
    
    async def _load_tools(self) -> Dict[str, Any]:
        """Load all available API tools"""
        tools = {}
        
        # Define available tools and their modules
        tool_map = {
            "system": ("SystemTool", "mcp_server.tools.system_new"),
            "arp": ("ARPTool", "mcp_server.tools.arp_new"),
            "interface": ("InterfaceTool", "mcp_server.tools.interface_new"),
            "firewall": ("FirewallTool", "mcp_server.tools.firewall_new"),
            "service": ("ServiceTool", "mcp_server.tools.service_new"),
            "vpn": ("VPNTool", "mcp_server.tools.vpn_new"),
            "dns": ("DNSTool", "mcp_server.tools.dns_new"),
            "traffic": ("TrafficShaperTool", "mcp_server.tools.traffic_new"),
            "ids": ("IDSTool", "mcp_server.tools.ids_new"),
            "certificate": ("CertificateTool", "mcp_server.tools.certificate_new"),
        }
        
        # Try to import and initialize each tool
        for name, (class_name, module_path) in tool_map.items():
            try:
                module = __import__(module_path, fromlist=[class_name])
                tool_class = getattr(module, class_name)
                tools[name] = tool_class(self.client)
                logger.debug(f"Loaded tool: {name}")
            except (ImportError, AttributeError) as e:
                logger.warning(f"Could not load tool {name}: {e}")
        
        return tools
    
    async def execute_tool(self, tool_name: str, action: str, **params) -> Dict[str, Any]:
        """Execute a specific tool action with parameters"""
        if tool_name not in self.tools:
            raise ValueError(f"Unknown tool: {tool_name}")
        
        # Prepare parameters
        tool_params = {"action": action}
        tool_params.update(params)
        
        logger.info(f"Executing {tool_name}.{action} with {params}")
        result = await self.tools[tool_name].execute(tool_params)
        return result
    
    async def interactive(self):
        """Run an interactive session"""
        print("\n===== OPNsense MCP API Interactive Tester =====\n")
        print(f"Connected to: {self.config['opnsense']['firewall_host']}")
        print(f"Available tools: {', '.join(self.tools.keys())}")
        
        while True:
            try:
                print("\n" + "-" * 50)
                tool_name = input("Enter tool name (or 'quit' to exit): ")
                
                if tool_name.lower() in ['quit', 'exit', 'q']:
                    break
                
                if tool_name not in self.tools:
                    print(f"Unknown tool: {tool_name}")
                    print(f"Available tools: {', '.join(self.tools.keys())}")
                    continue
                
                # Get action and parameters
                action = input("Enter action: ")
                params_str = input("Enter parameters as JSON (or empty for none): ")
                
                # Parse parameters
                params = {}
                if params_str.strip():
                    try:
                        params = json.loads(params_str)
                    except json.JSONDecodeError:
                        print("Invalid JSON parameters. Please try again.")
                        continue
                
                # Execute tool
                result = await self.execute_tool(tool_name, action, **params)
                
                # Print result
                print("\nResult:")
                print(json.dumps(result, indent=2))
                
            except KeyboardInterrupt:
                print("\nExiting...")
                break
            except Exception as e:
                print(f"Error: {e}")

async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='OPNsense MCP API Interactive Tester')
    parser.add_argument('--config', type=str, default='./examples/mcp.json',
                       help='Path to configuration file (JSON or YAML)')
    parser.add_argument('--tool', type=str, help='Specific tool to test')
    parser.add_argument('--action', type=str, help='Action to perform (requires --tool)')
    parser.add_argument('--params', type=str, help='Parameters as JSON string (requires --tool and --action)')
    
    args = parser.parse_args()
    
    # Initialize tester
    tester = APITester(args.config)
    await tester.setup()
    
    # If tool and action are specified, run that specific command
    if args.tool and args.action:
        params = {}
        if args.params:
            try:
                params = json.loads(args.params)
            except json.JSONDecodeError:
                logger.error("Invalid JSON parameters")
                sys.exit(1)
                
        result = await tester.execute_tool(args.tool, args.action, **params)
        print(json.dumps(result, indent=2))
        
    else:
        # Otherwise run interactive mode
        await tester.interactive()

if __name__ == "__main__":
    asyncio.run(main())
