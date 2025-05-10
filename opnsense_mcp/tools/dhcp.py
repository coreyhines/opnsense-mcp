#!/usr/bin/env python3

from typing import Dict, Any
import logging
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class DHCPLease(BaseModel):
    ip: str
    mac: str
    hostname: str | None = None
    start: str | None = None
    end: str | None = None
    online: bool | None = None
    lease_type: str | None = None
    description: str | None = None


class DHCPTol:
    name = "dhcp"
    description = "Show DHCPv4 lease table"
    inputSchema = {"type": "object", "properties": {}, "required": []}

    def __init__(self, client):
        self.client = client

    async def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute DHCP lease table lookup"""
        try:
            if self.client is None:
                logger.warning(
                    "No OPNsense client available, returning dummy DHCP data"
                )
                return self._get_dummy_data()
            leases = await self.client.get_dhcpv4_leases()
            lease_entries = [DHCPLease(**entry).dict() for entry in leases]
            return {"dhcp": lease_entries, "status": "success"}
        except Exception as e:
            logger.error(f"Failed to get DHCP lease table: {str(e)}")
            return self._get_dummy_data()

    def _get_dummy_data(self):
        return {
            "dhcp": [
                {
                    "ip": "192.168.1.100",
                    "mac": "00:11:22:33:44:55",
                    "hostname": "dummy-client",
                    "start": "2025-01-01T00:00:00",
                    "end": "2025-01-01T12:00:00",
                    "online": True,
                    "lease_type": "dynamic",
                    "description": "Dummy lease entry",
                }
            ],
            "status": "dummy",
        }
