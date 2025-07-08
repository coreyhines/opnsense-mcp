#!/usr/bin/env python3

import logging
from typing import Any

logger = logging.getLogger(__name__)


class InterfaceTool:
    def __init__(self, client) -> None:
        self.client = client

    def _validate_params(self, params: dict[str, Any]) -> None:
        """Validate input parameters."""
        if not isinstance(params, dict):
            raise TypeError("Invalid parameters: expected dictionary")

    def _validate_action(self, action: str) -> None:
        """Validate action parameter."""
        if action not in ["list", "get"]:
            raise ValueError(
                f"Invalid action: {action}. Supported actions are 'list' and 'get'"
            )

    def _validate_interface_param(self, interface_name: str | None) -> None:
        """Validate interface parameter for get action."""
        if not interface_name:
            raise ValueError("Missing interface parameter for 'get' action")

    def _raise_interface_not_found(self, interface_name: str) -> None:
        """Raise error for interface not found."""
        raise ValueError(
            f"Interface {interface_name} not found or has no active neighbors"
        )

    async def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        """Execute interface configuration actions."""
        try:
            # Validate parameters
            self._validate_params(params)

            action = params.get("action", "list")
            self._validate_action(action)

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

                except Exception as e:
                    logger.exception("Failed to list interfaces")
                    raise RuntimeError(f"Failed to list interfaces: {str(e)}") from e
                else:
                    return {"interfaces": interface_list, "status": "success"}

            # Handle get action
            elif action == "get":
                interface_name = params.get("interface")
                self._validate_interface_param(interface_name)

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

                    if not (ipv4_entries or ipv6_entries):
                        self._raise_interface_not_found(interface_name)

                except Exception as e:
                    logger.exception(f"Failed to get interface {interface_name}")
                    raise RuntimeError(
                        f"Failed to get interface details: {str(e)}"
                    ) from e
                else:
                    return {
                        "interface": {
                            "name": interface_name,
                            "status": "active",
                            "ipv4_neighbors": ipv4_entries,
                            "ipv6_neighbors": ipv6_entries,
                        },
                        "status": "success",
                    }

        except ValueError as e:
            logger.warning(f"Validation error in interface tool: {str(e)}")
            raise
        except Exception as e:
            logger.exception("Unexpected error in interface tool")
            raise RuntimeError(f"Interface tool error: {str(e)}") from e
