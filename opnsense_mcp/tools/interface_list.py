#!/usr/bin/env python3

import logging
from typing import Any

logger = logging.getLogger(__name__)


class InterfaceListTool:
    """Tool for getting available firewall interface names."""

    def __init__(self, client):
        self.client = client

    async def execute(self, params: dict[str, Any] = None) -> dict[str, Any]:
        """
        Get available interface names for firewall rules.

        Returns:
        - interfaces: Dict mapping interface keys to display names
        - success: Operation success status

        """
        try:
            logger.info("Fetching firewall interface list...")

            # Get the interface list from OPNsense
            interface_data = await self.client.get_firewall_interface_list()

            if not interface_data:
                return {
                    "error": "No interface data returned from OPNsense",
                    "interfaces": {},
                    "status": "error",
                }

            # Extract interface mappings
            interfaces = {}
            if isinstance(interface_data, dict):
                # Common response formats from OPNsense
                if "interfaces" in interface_data:
                    interfaces = interface_data["interfaces"]
                elif "data" in interface_data:
                    interfaces = interface_data["data"]
                else:
                    # The response itself might be the interface dict
                    interfaces = interface_data

            logger.info(f"Retrieved {len(interfaces)} interfaces")

            return {
                "interfaces": interfaces,
                "total_count": len(interfaces),
                "status": "success",
            }

        except Exception as e:
            logger.exception("Failed to get interface list")
            return {
                "error": f"Failed to get interface list: {e}",
                "interfaces": {},
                "status": "error",
            }
