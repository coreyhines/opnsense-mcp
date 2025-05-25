#!/usr/bin/env python3
"""Script to check if our firewall rule is still active."""

import traceback

from opnsense_mcp.utils.api import OPNsenseClient


def main() -> None:
    """Check if our firewall rule is still active and display its details."""
    try:
        print("Initializing OPNsense client...")
        client = OPNsenseClient()

        print("Getting firewall rules...")
        rules = client.get_firewall_rules()
        print(f"Retrieved {len(rules)} rules")

        # Look for our specific rule
        target_uuid = "9e7f7743-436f-46a4-b6af-6e25dc2f9e3c"
        print(f"Looking for rule with UUID: {target_uuid}")

        found_rule = False
        for rule in rules:
            rule_uuid = rule.get("uuid", "")
            if rule_uuid == target_uuid:
                found_rule = True
                print("\n✅ FOUND OUR RULE!")
                print(f"Description: {rule.get('description', 'N/A')}")
                print(f"Interface: {rule.get('interface', 'N/A')}")
                print(f"Direction: {rule.get('direction', 'N/A')}")
                print(f"Action: {rule.get('action', 'N/A')}")
                print(f"Protocol: {rule.get('protocol', 'N/A')}")
                print(f"Source: {rule.get('source', 'N/A')}")
                print(f"Destination: {rule.get('destination', 'N/A')}")
                print(f"Enabled: {rule.get('enabled', 'N/A')}")
                break

        if not found_rule:
            print(f"\n❌ Rule {target_uuid} NOT FOUND")
            print(f"\nCurrent rules ({len(rules)} total):")
            for i, rule in enumerate(rules):
                print(f"  {i + 1}. UUID: {rule.get('uuid', 'N/A')}")
                print(f"     Description: {rule.get('description', 'N/A')}")
                print(f"     Interface: {rule.get('interface', 'N/A')}")
                print(f"     Action: {rule.get('action', 'N/A')}")
                print()

    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()


if __name__ == "__main__":
    main()
