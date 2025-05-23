#!/usr/bin/env python3

from typing import Dict, Any, Optional
from pydantic import BaseModel, validator
import logging

logger = logging.getLogger(__name__)

class FirewallRuleSpec(BaseModel):
    """Model for firewall rule creation specification"""
    description: str
    interface: str = "lan"
    action: str = "pass"  # pass, block, reject
    protocol: str = "any"  # any, tcp, udp, icmp, etc.
    source_net: str = "any"
    source_port: str = "any"
    destination_net: str = "any" 
    destination_port: str = "any"
    direction: str = "in"  # in, out
    ipprotocol: str = "inet"  # inet, inet6
    enabled: bool = True
    gateway: str = ""
    
    @validator('action')
    def validate_action(cls, v):
        allowed = ['pass', 'block', 'reject']
        if v.lower() not in allowed:
            raise ValueError(f'Action must be one of: {allowed}')
        return v.lower()
    
    @validator('direction')
    def validate_direction(cls, v):
        allowed = ['in', 'out']
        if v.lower() not in allowed:
            raise ValueError(f'Direction must be one of: {allowed}')
        return v.lower()
    
    @validator('ipprotocol')
    def validate_ipprotocol(cls, v):
        allowed = ['inet', 'inet6']
        if v.lower() not in allowed:
            raise ValueError(f'IP protocol must be one of: {allowed}')
        return v.lower()

class MkfwRuleTool:
    def __init__(self, client):
        self.client = client
    
    async def execute(self, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Create a new firewall rule and apply changes.
        
        Parameters:
        - description: Description of the rule (required)
        - interface: Interface name (default: "lan")
        - action: pass, block, or reject (default: "pass")
        - protocol: any, tcp, udp, icmp, etc. (default: "any")
        - source_net: Source network/IP (default: "any")
        - source_port: Source port (default: "any")
        - destination_net: Destination network/IP (default: "any")
        - destination_port: Destination port (default: "any")
        - direction: in or out (default: "in")
        - ipprotocol: inet or inet6 (default: "inet")
        - enabled: true or false (default: true)
        - gateway: Gateway to use (default: "")
        - apply: Whether to apply changes immediately (default: true)
        """
        try:
            if params is None:
                params = {}
            
            # Validate required parameter
            if not params.get("description"):
                return {
                    "error": "Description is required for firewall rules",
                    "status": "error"
                }
            
            # Create and validate rule specification
            try:
                rule_spec = FirewallRuleSpec(**params)
            except Exception as e:
                return {
                    "error": f"Invalid rule parameters: {e}",
                    "status": "error"
                }
            
            # Build rule data for OPNsense API - simplified to match documentation
            rule_data = {
                "description": rule_spec.description,
                "interface": rule_spec.interface,
                "action": rule_spec.action,
                "protocol": rule_spec.protocol.upper(),  # Documentation shows uppercase
                "source_net": rule_spec.source_net,
                "destination_net": rule_spec.destination_net,
                "enabled": "1" if rule_spec.enabled else "0",
                "direction": rule_spec.direction,
                "ipprotocol": rule_spec.ipprotocol,
            }
            
            # Only add optional fields if they're not defaults
            if rule_spec.source_port != "any":
                rule_data["source_port"] = rule_spec.source_port
            if rule_spec.destination_port != "any":
                rule_data["destination_port"] = rule_spec.destination_port
            if rule_spec.gateway:
                rule_data["gateway"] = rule_spec.gateway
            
            logger.info(f"Creating firewall rule: {rule_spec.description}")
            logger.debug(f"Rule data: {rule_data}")
            
            # Create the rule
            result = await self.client.add_firewall_rule(rule_data)
            
            if result.get("result") != "success":
                return {
                    "error": f"Failed to create rule: {result}",
                    "status": "error"
                }
            
            rule_uuid = result.get("uuid")
            logger.info(f"Successfully created rule with UUID: {rule_uuid}")
            
            # Apply changes if requested (default: true)
            apply_changes = params.get("apply", True)
            if apply_changes:
                logger.info("Applying firewall changes...")
                apply_result = await self.client.apply_firewall_changes()
                
                if apply_result.get("result") != "success":
                    return {
                        "error": f"Rule created but failed to apply changes: {apply_result}",
                        "rule_uuid": rule_uuid,
                        "status": "partial_success"
                    }
                
                logger.info("Successfully applied firewall changes")
                
                return {
                    "rule_uuid": rule_uuid,
                    "revision": apply_result.get("revision"),
                    "description": rule_spec.description,
                    "interface": rule_spec.interface,
                    "action": rule_spec.action,
                    "applied": True,
                    "status": "success"
                }
            else:
                return {
                    "rule_uuid": rule_uuid,
                    "description": rule_spec.description,
                    "interface": rule_spec.interface,
                    "action": rule_spec.action,
                    "applied": False,
                    "status": "success",
                    "note": "Rule created but not applied. Use apply_firewall_changes() to activate."
                }
                
        except Exception as e:
            logger.error(f"Failed to create firewall rule: {e}")
            return {
                "error": f"Failed to create firewall rule: {e}",
                "status": "error"
            } 
