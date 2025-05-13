#!/usr/bin/env python3
"""
Standalone command-line tool for testing OPNsense API functionality directly.
This provides a simple interface for testing key API functions.
"""

import os
import sys
import asyncio
import argparse
import logging
import ssl
import requests
import json
import base64
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class OPNsenseAPIError(Exception):
    """Base API error for OPNsense"""
    pass

class OPNsenseClient:
    """Simplified OPNsense API client for testing"""
    def __init__(self, config):
        self.api_key = config['api_key']
        self.api_secret = config['api_secret']
        self.host = config['firewall_host']
        self.base_url = f"https://{self.host}"
        self.api_url = f"{self.base_url}/api"
        
        # Configure SSL context to ignore verification
        ssl._create_default_https_context = ssl._create_unverified_context
        
        # Setup session for requests
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'Authorization': f'Basic {self._get_basic_auth()}',
            'Content-Type': 'application/json'
        })
        
        # Suppress insecure warnings
        from urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    
    def _get_basic_auth(self):
        """Create basic auth header from api key and secret"""
        auth_str = f"{self.api_key}:{self.api_secret}"
        return base64.b64encode(auth_str.encode()).decode()
    
    async def request(self, method, endpoint, **kwargs):
        """Make a request to the API"""
        if not endpoint.startswith('/api'):
            endpoint = f"/api{endpoint}"
            
        url = f"{self.base_url}{endpoint}"
        
        try:
            logger.debug(f"Making {method} request to {url}")
            response = self.session.request(method, url, **kwargs)
            
            # Check for HTTP errors
            response.raise_for_status()
            
            # Check for API errors in 200 responses
            if response.status_code == 200:
                try:
                    data = response.json()
                    if isinstance(data, dict) and data.get('result') == 'failed':
                        error_msg = data.get('message', 'Unknown API error')
                        raise OPNsenseAPIError(f"API error: {error_msg}")
                    return data
                except json.JSONDecodeError:
                    if response.text:
                        return response.text
                    return {}
                    
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            raise OPNsenseAPIError(f"Request failed: {e}")
    
    async def get_system_status(self):
        """Get system status information"""
        try:
            # Get core system status
            status = await self.request('GET', '/api/core/system/status')
            
            if not isinstance(status, dict) or 'data' not in status:
                raise OPNsenseAPIError("Invalid system status response format")
                
            data = status.get('data', {})
            
            # Extract status information
            result = {
                'cpu_usage': 0.0,
                'memory_usage': 0.0,
                'filesystem_usage': {},
                'uptime': '',
                'versions': {
                    'opnsense': '',
                    'kernel': ''
                },
                'temperature': {},
            }
            
            # Extract CPU usage
            if 'cpu' in data:
                cpu_info = data['cpu']
                if isinstance(cpu_info, dict) and 'used' in cpu_info:
                    result['cpu_usage'] = float(cpu_info['used'].rstrip('%'))
            
            # Extract memory usage
            if 'memory' in data:
                mem_info = data['memory']
                if isinstance(mem_info, dict) and 'used' in mem_info:
                    result['memory_usage'] = float(mem_info['used'].rstrip('%'))
            
            # Extract filesystem usage
            if 'filesystems' in data:
                for fs in data['filesystems']:
                    if isinstance(fs, dict):
                        mount = fs.get('mountpoint', '')
                        used = fs.get('used_percent', '0').rstrip('%')
                        result['filesystem_usage'][mount] = float(used)
            
            # Extract version information
            result['uptime'] = data.get('uptime', '')
            result['versions']['opnsense'] = data.get('version', '')
            result['versions']['kernel'] = data.get('kernel', '')
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to get system status: {e}")
            raise OPNsenseAPIError(f"Failed to get system status: {e}")
    
    async def get_arp_table(self):
        """Get ARP table entries"""
        try:
            # Get ARP table entries
            arp_data = await self.request('GET', '/api/diagnostics/interface/get_arp')
            
            if not isinstance(arp_data, list):
                raise OPNsenseAPIError("Invalid ARP table response format")
                
            # Process ARP entries
            entries = []
            for entry in arp_data:
                try:
                    arp_entry = {
                        'ip': entry.get('ip', ''),
                        'mac': entry.get('mac', ''),
                        'interface': entry.get('intf', ''),
                        'hostname': entry.get('hostname', ''),
                        'expiry': entry.get('expires', ''),
                        'manufacturer': entry.get('manufacturer', ''),
                    }
                    entries.append(arp_entry)
                except Exception as e:
                    logger.warning(f"Error processing ARP entry: {e}")
                    continue
                
            return {
                "entries": entries,
                "count": len(entries),
                "status": "success"
            }
            
        except Exception as e:
            logger.error(f"Failed to get ARP table: {e}")
            raise OPNsenseAPIError(f"Failed to get ARP table: {e}")

def load_config(config_path):
    """Load configuration from YAML file"""
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            return config
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        sys.exit(1)

async def test_system_status(client):
    """Test system status functionality"""
    logger.info("Testing system status...")
    
    result = await client.get_system_status()
    
    # Format and display the results
    print("\n=== SYSTEM STATUS ===\n")
    print(f"CPU Usage:      {result['cpu_usage']}%")
    print(f"Memory Usage:   {result['memory_usage']}%")
    print(f"OPNsense Version: {result['versions']['opnsense']}")
    print(f"Uptime:         {result['uptime']}")
    
    print("\nFilesystem Usage:")
    for mount, usage in result['filesystem_usage'].items():
        print(f"  {mount}: {usage}%")
    
    # Pretty print the complete JSON for reference
    print("\nComplete System Status Data:")
    print(json.dumps(result, indent=2))
    
    return result

async def test_arp_table(client):
    """Test ARP table functionality"""
    logger.info("Testing ARP table...")
    
    result = await client.get_arp_table()
    
    # Format and display the results
    print(f"\n=== ARP TABLE ({result['count']} entries) ===\n")
    print(f"{'IP Address':<18} {'MAC Address':<18} {'Interface':<12} {'Hostname':<30}")
    print("-" * 80)
    
    for entry in result['entries']:
        print(f"{entry['ip']:<18} {entry['mac']:<18} {entry['interface']:<12} {entry['hostname']:<30}")
    
    # Pretty print the complete JSON for reference
    print("\nComplete ARP Table Data:")
    print(json.dumps(result, indent=2))
    
    return result

async def main():
    parser = argparse.ArgumentParser(description='Test OPNsense API functionality')
    parser.add_argument('--config', type=str, default='vars/key.yaml', help='Path to config file')
    parser.add_argument('function', choices=['system', 'arp'], help='Function to test')
    args = parser.parse_args()
    
    # Resolve config path
    if not os.path.isabs(args.config):
        config_path = os.path.join(os.path.dirname(__file__), args.config)
    else:
        config_path = args.config
    
    if not os.path.exists(config_path):
        logger.error(f"Config file not found: {config_path}")
        sys.exit(1)
    
    config = load_config(config_path)
    # Make sure the config has the expected format
    if not all(k in config for k in ['api_key', 'api_secret', 'firewall_host']):
        logger.error("Config file must contain 'api_key', 'api_secret', and 'firewall_host' fields")
        sys.exit(1)
    
    # Initialize API client
    client = OPNsenseClient(config)
    
    # Execute the specified function
    if args.function == 'system':
        await test_system_status(client)
    elif args.function == 'arp':
        await test_arp_table(client)

if __name__ == "__main__":
    asyncio.run(main())
