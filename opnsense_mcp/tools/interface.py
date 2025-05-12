#!/usr/bin/env python3

import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


class InterfaceTool:
    def __init__(self, client):
        self.client = client

    async def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute interface configuration actions"""
        try:
            # Validate parameters
            if not isinstance(params, dict):
                raise ValueError("Invalid parameters: expected dictionary")

            action = params.get("action", "list")
            if action not in ["list", "get"]:
                raise ValueError(
                    f"Invalid action: {action}. Supported actions are 'list' and 'get'"
                )

            # Handle list action
            if action == "list":
                try:
                    # Get both ARP and NDP data for more complete interface list
                    arp_data = await self.client.get_arp_table()
                    ndp_data = await self.client.get_ndp_table()

                    # Combine interface information from both sources
                    interfaces = set()
                    for entry in arp_data + ndp_data:
                        if "intf" in entry:
                            interfaces.add(entry["intf"])

                    # Format interface data with status and IP information
                    interface_list = []
                    for intf in interfaces:
                        intf_data = {
                            "name": intf,
                            "status": "active",
                            "ipv4_neighbors": [
                                e for e in arp_data if e.get("intf") == intf
                            ],
                            "ipv6_neighbors": [
                                e for e in ndp_data if e.get("intf") == intf
                            ],
                        }
                        interface_list.append(intf_data)

                    return {"interfaces": interface_list, "status": "success"}

                except Exception as e:
                    logger.error(f"Failed to list interfaces: {str(e)}")
                    raise RuntimeError(f"Failed to list interfaces: {str(e)}")

            # Handle get action
            elif action == "get":
                interface_name = params.get("interface")
                if not interface_name:
                    raise ValueError("Missing interface parameter for 'get' action")

                try:
                    # Get interface details from both ARP and NDP tables
                    arp_data = await self.client.get_arp_table()
                    ndp_data = await self.client.get_ndp_table()

                    # Collect all entries for the requested interface
                    ipv4_entries = [
                        e for e in arp_data if e.get("intf") == interface_name
                    ]
                    ipv6_entries = [
                        e for e in ndp_data if e.get("intf") == interface_name
                    ]

                    if ipv4_entries or ipv6_entries:
                        return {
                            "interface": {
                                "name": interface_name,
                                "status": "active",
                                "ipv4_neighbors": ipv4_entries,
                                "ipv6_neighbors": ipv6_entries,
                            },
                            "status": "success",
                        }
                    else:
                        raise ValueError(
                            f"Interface {interface_name} not found or has no "
                            f"active neighbors"
                        )

                except Exception as e:
                    logger.error(f"Failed to get interface {interface_name}: {str(e)}")
                    raise RuntimeError(f"Failed to get interface details: {str(e)}")

        except ValueError as e:
            logger.warning(f"Validation error in interface tool: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in interface tool: {str(e)}")
            raise RuntimeError(f"Interface tool error: {str(e)}")

        except Exception as e:
            raise RuntimeError(f"Failed to execute interface action: {e}")
