#!/usr/bin/env python3

from typing import Dict, Any, List
from pydantic import BaseModel

class FirewallEndpoint(BaseModel):
    net: str
    port: str

class FirewallRule(BaseModel):
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

class FwRulesTool:
    def __init__(self, client):
        self.client = client

    async def execute(self, params: Dict[str, Any] = None) -> Dict[str, List[Dict[str, Any]]]:
        """Return the current firewall rule set as a list of dicts."""
        try:
            rules = await self.client.get_firewall_rules()
            return {
                "rules": [FirewallRule(**rule).dict() for rule in rules],
                "status": "success",
            }
        except Exception as e:
            return {"error": f"Failed to get firewall rules: {e}", "status": "error"} 
