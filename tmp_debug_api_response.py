#!/usr/bin/env python3

import requests
import json
import os
import base64
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def test_api_directly():
    """Test the OPNsense API directly to see exact responses"""
    
    # Configuration
    host = os.getenv("OPNSENSE_HOST", "192.168.1.1")
    api_key = os.getenv("OPNSENSE_API_KEY")
    api_secret = os.getenv("OPNSENSE_API_SECRET")
    
    if not api_key or not api_secret:
        print("Error: OPNSENSE_API_KEY and OPNSENSE_API_SECRET environment variables must be set")
        return
    
    # Create auth header
    auth_str = f"{api_key}:{api_secret}"
    auth_header = base64.b64encode(auth_str.encode()).decode()
    headers = {
        "Authorization": f"Basic {auth_header}",
        "Content-Type": "application/json"
    }
    
    base_url = f"https://{host}"
    
    print(f"Testing API endpoints on {host}")
    print("=" * 50)
    
    # Test 1: Search existing rules
    print("\n1. Testing searchRule endpoint...")
    try:
        url = f"{base_url}/api/firewall/filter/searchRule"
        params = {"current": 1, "rowCount": 10}
        response = requests.get(url, headers=headers, params=params, verify=False, timeout=10)
        print(f"Status: {response.status_code}")
        print(f"Headers: {dict(response.headers)}")
        print(f"Response: {response.text[:500]}...")
    except Exception as e:
        print(f"Error: {e}")
    
    # Test 2: Try addRule with minimal data
    print("\n2. Testing addRule endpoint with minimal data...")
    try:
        url = f"{base_url}/api/firewall/filter/addRule"
        
        # Minimal rule data based on documentation
        rule_data = {
            "rule": {
                "description": "Test API Rule Minimal",
                "source_net": "10.0.2.58",
                "protocol": "ICMP",
                "destination_net": "any"
            }
        }
        
        print(f"Sending data: {json.dumps(rule_data, indent=2)}")
        
        response = requests.post(url, headers=headers, json=rule_data, verify=False, timeout=10)
        print(f"Status: {response.status_code}")
        print(f"Headers: {dict(response.headers)}")
        print(f"Response: {response.text}")
        
        # Try to parse as JSON
        try:
            json_resp = response.json()
            print(f"JSON Response: {json.dumps(json_resp, indent=2)}")
        except:
            print("Response is not valid JSON")
            
    except Exception as e:
        print(f"Error: {e}")
    
    # Test 3: Try with even more minimal data
    print("\n3. Testing addRule with absolute minimal data...")
    try:
        url = f"{base_url}/api/firewall/filter/addRule"
        
        # Absolute minimal rule data
        rule_data = {
            "rule": {
                "description": "Test Minimal"
            }
        }
        
        print(f"Sending data: {json.dumps(rule_data, indent=2)}")
        
        response = requests.post(url, headers=headers, json=rule_data, verify=False, timeout=10)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")
        
        try:
            json_resp = response.json()
            print(f"JSON Response: {json.dumps(json_resp, indent=2)}")
        except:
            print("Response is not valid JSON")
            
    except Exception as e:
        print(f"Error: {e}")
    
    # Test 4: Check if we can access the filter controller at all
    print("\n4. Testing filter controller access...")
    try:
        url = f"{base_url}/api/firewall/filter/get"
        response = requests.get(url, headers=headers, verify=False, timeout=10)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text[:200]}...")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_api_directly() 
