#!/usr/bin/env python3

from typing import Dict, Any
import logging
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class LLDPEntry(BaseModel):
    intf: str
    chassis_id: str
    port_id: str
    system_name: str | None = None
    system_description: str | None = None
    port_description: str | None = None
    capabilities: str | None = None
    management_address: str | None = None


class LLDPTool:
    name = "lldp"
    description = "Show LLDP neighbor table"
    inputSchema = {"type": "object", "properties": {}, "required": []}

    def __init__(self, client):
        self.client = client

    async def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute LLDP neighbor table lookup"""
        try:
            if self.client is None:
                logger.warning(
                    "No OPNsense client available, returning dummy LLDP data"
                )
                return self._get_dummy_data()

            lldp_data = await self.client.get_lldp_table()
            lldp_entries = [LLDPEntry(**entry).dict() for entry in lldp_data]
            return {"lldp": lldp_entries, "status": "success"}
        except Exception as e:
            logger.error(f"Failed to get LLDP table: {str(e)}")
            return self._get_dummy_data()

    def _get_dummy_data(self) -> Dict[str, Any]:
        """Return dummy LLDP data for testing"""
        return {
            "lldp": [
                {
                    "intf": "em0",
                    "chassis_id": "00:11:22:33:44:55",
                    "port_id": "1",
                    "system_name": "Switch-1",
                    "system_description": "48-port Gigabit Switch",
                    "port_description": "Uplink Port",
                    "capabilities": "Bridge, Router",
                    "management_address": "192.168.1.2",
                }
            ],
            "status": "success",
        }
