#!/usr/bin/env python3

from typing import Dict, Any, List
from pydantic import BaseModel


class FirewallEndpoint(BaseModel):
    """Model for firewall rule endpoint (source/destination)"""

    net: str
    port: str


class FirewallRule(BaseModel):
    """Model for firewall rule data"""

    id: str
    sequence: int
    description: str
    interface: str
    protocol: str
    source: FirewallEndpoint
    destination: FirewallEndpoint
    action: str
    enabled: bool
    gateway: str = ""
    direction: str = "in"
    ipprotocol: str = "inet"


class FirewallTool:
    def __init__(self, client):
        self.client = client

    async def execute(self, params: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        """Execute firewall rules lookup"""
        try:
            # Get rules from OPNsense
            rules = await self.client.get_firewall_rules()

            return {
                "rules": [FirewallRule(**rule).dict() for rule in rules],
                "status": "success",
            }
        except Exception as e:
            raise RuntimeError(f"Failed to get firewall rules: {e}")
