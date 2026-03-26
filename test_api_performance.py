#!/usr/bin/env python3
"""
Quick API performance test to verify ARP performance improvements.
"""

import asyncio
import sys
import time
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))

from opnsense_mcp.server import get_opnsense_client
from opnsense_mcp.tools.arp import ARPTool


async def test_api_performance():
    """Test API performance directly."""
    print("Testing OPNsense API performance...")

    client = get_opnsense_client({})

    # Test ARP table fetch
    print("\n1. Testing ARP table fetch...")
    start = time.time()
    try:
        result = await client.get_arp_table()
        end = time.time()
        print(f"   ARP table: {end - start:.2f}s - {len(result)} entries")
    except Exception as e:
        print(f"   ARP table FAILED: {e}")

    # Test NDP table fetch
    print("\n2. Testing NDP table fetch...")
    start = time.time()
    try:
        result = await client.get_ndp_table()
        end = time.time()
        print(f"   NDP table: {end - start:.2f}s - {len(result)} entries")
    except Exception as e:
        print(f"   NDP table FAILED: {e}")

    # Test ARP tool without search
    print("\n3. Testing ARP tool (no search)...")
    arp_tool = ARPTool(client)
    start = time.time()
    try:
        result = await arp_tool.execute({})
        end = time.time()
        arp_count = len(result.get("arp", []))
        ndp_count = len(result.get("ndp", []))
        print(
            f"   ARP tool: {end - start:.2f}s - {arp_count} ARP, {ndp_count} NDP entries"
        )
    except Exception as e:
        print(f"   ARP tool FAILED: {e}")

    # Test ARP tool with search (if we have entries)
    if arp_count > 0:
        print("\n4. Testing ARP tool with search query...")
        # Get first IP from results for testing
        first_ip = result.get("arp", [{}])[0].get("ip", "")
        if first_ip:
            start = time.time()
            try:
                search_result = await arp_tool.execute({"search": first_ip})
                end = time.time()
                search_arp_count = len(search_result.get("arp", []))
                search_ndp_count = len(search_result.get("ndp", []))
                print(
                    f"   ARP tool (search): {end - start:.2f}s - {search_arp_count} ARP, {search_ndp_count} NDP entries"
                )
            except Exception as e:
                print(f"   ARP tool search FAILED: {e}")


if __name__ == "__main__":
    asyncio.run(test_api_performance())
