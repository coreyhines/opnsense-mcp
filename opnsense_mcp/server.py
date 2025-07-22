#!/usr/bin/env python3
"""OPNsense MCP Server - Main entry point for the MCP server."""

import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from opnsense_mcp.tools.arp import ARPTool
from opnsense_mcp.tools.dhcp import DHCPTool
from opnsense_mcp.tools.fw_rules import FwRulesTool
from opnsense_mcp.tools.get_logs import GetLogsTool
from opnsense_mcp.tools.interface_list import InterfaceListTool
from opnsense_mcp.tools.lldp import LLDPTool
from opnsense_mcp.tools.mkfw_rule import MkfwRuleTool
from opnsense_mcp.tools.rmfw_rule import RmfwRuleTool
from opnsense_mcp.tools.system import SystemTool
from opnsense_mcp.utils.api import OPNsenseClient
from opnsense_mcp.utils.mock_api import MockOPNsenseClient

logger = logging.getLogger(__name__)

# Load environment variables from ~/.opnsense-env by default
load_dotenv(str(Path("~/.opnsense-env").expanduser()))


def get_opnsense_client(config: dict[str, Any]) -> OPNsenseClient:
    """Get an OPNsense client instance based on environment variables."""
    host = os.getenv("OPNSENSE_FIREWALL_HOST")  # Use correct env var name
    api_key = os.getenv("OPNSENSE_API_KEY")
    api_secret = os.getenv("OPNSENSE_API_SECRET")
    ssl_verify = os.getenv("OPNSENSE_SSL_VERIFY", "false").lower() == "true"

    if host and api_key and api_secret:
        logger.info("Using real OPNsense client")
        return OPNsenseClient(
            {
                "firewall_host": host,
                "api_key": api_key,
                "api_secret": api_secret,
                "verify_ssl": ssl_verify,
            }
        )
    logger.warning("No OPNsense credentials found, using mock client")
    workspace_root = Path(__file__).parent.parent
    mock_data_path = workspace_root / "examples" / "mock_data"
    config = {"development": {"mock_data_path": str(mock_data_path)}}
    return MockOPNsenseClient(config)


def format_log_response(logs: list, msg_id: int | None = None) -> dict[str, Any]:
    """Format logs into an MCP protocol response."""
    log_entries = []
    for log in logs:
        description = f"{log.action.upper()} {log.protocol} "
        description += f"{log.src_ip}:{log.src_port} -> "
        description += f"{log.dst_ip}:{log.dst_port}"
        if log.description:
            description += f" ({log.description})"

        log_entries.append(
            {
                "text": description,
                "type": "text",
                "timestamp": log.timestamp.isoformat(),
                "metadata": {
                    "src_ip": log.src_ip,
                    "dst_ip": log.dst_ip,
                    "action": log.action,
                    "protocol": log.protocol,
                },
            }
        )

    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": {"content": log_entries},
    }


async def handle_message(
    message: dict[str, Any],
    firewall_logs: GetLogsTool,
    arp_tool: ARPTool,
    dhcp_tool: DHCPTool,
    lldp_tool: LLDPTool,
    system_tool: SystemTool,
    fw_rules_tool: FwRulesTool,
    mkfw_rule_tool: MkfwRuleTool,
    rmfw_rule_tool: RmfwRuleTool,
    interface_list_tool: InterfaceListTool,
) -> dict[str, Any] | None:
    """Handle incoming MCP messages and route them to appropriate tools."""
    method = message.get("method")
    msg_id = message.get("id")

    # Forgiving protocolVersion handling
    if method == "initialize":
        protocol_version = message.get("params", {}).get("protocolVersion")
        if not protocol_version or protocol_version == "undefined":
            protocol_version = "2024-11-05"
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": protocol_version,
                "serverInfo": {"name": "opnsense-mcp", "version": "1.0.0"},
                "capabilities": {"tools": {"listChanged": False}},
            },
        }

    # Handle notifications/initialized to prevent red indicator
    if method == "notifications/initialized" and msg_id is None:
        # Do not respond to notifications (no id)
        return None

    # Support both tools/list and ListOfferings
    if method in ("tools/list", "ListOfferings"):
        tools = [
            {
                "name": "get_logs",
                "description": "Get firewall logs with optional filtering",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "limit": {"type": "number", "optional": True},
                        "action": {"type": "string", "optional": True},
                        "src_ip": {"type": "string", "optional": True},
                        "dst_ip": {"type": "string", "optional": True},
                        "protocol": {"type": "string", "optional": True},
                    },
                    "required": [],
                },
            },
            {
                "name": "arp",
                "description": "Show ARP/NDP table",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "mac": {
                            "type": "string",
                            "description": "Filter by MAC address",
                            "optional": True,
                        },
                        "ip": {
                            "type": "string",
                            "description": "Filter by IP address",
                            "optional": True,
                        },
                        "search": {
                            "type": "string",
                            "description": ("Targeted search by IP/MAC/hostname"),
                            "optional": True,
                        },
                    },
                    "required": [],
                },
            },
            {
                "name": "dhcp",
                "description": "Show DHCP lease information",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "search": {
                            "type": "string",
                            "description": ("Search by hostname/IP/MAC"),
                            "optional": True,
                        },
                    },
                    "required": [],
                },
            },
            {
                "name": "lldp",
                "description": "Show LLDP neighbor table",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": [],
                },
            },
            {
                "name": "system",
                "description": "Show system status information",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": [],
                },
            },
            {
                "name": "fw_rules",
                "description": (
                    "Get the current firewall rule set for context and reasoning"
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "interface": {
                            "type": "string",
                            "description": (
                                "Filter by interface name "
                                "(supports partial matching and groups)"
                            ),
                            "optional": True,
                        },
                        "action": {
                            "type": "string",
                            "description": (
                                "Filter by action (pass, block, reject, etc.)"
                            ),
                            "optional": True,
                        },
                        "enabled": {
                            "type": "boolean",
                            "description": "Filter by enabled status",
                            "optional": True,
                        },
                        "protocol": {
                            "type": "string",
                            "description": (
                                "Filter by protocol (tcp, udp, icmp, etc.)"
                            ),
                            "optional": True,
                        },
                    },
                    "required": [],
                },
            },
            {
                "name": "mkfw_rule",
                "description": (
                    "Create a new firewall rule and optionally apply changes"
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "description": {
                            "type": "string",
                            "description": ("Description of the rule (required)"),
                        },
                        "interface": {
                            "type": "string",
                            "description": "Interface name (default: 'lan')",
                            "optional": True,
                        },
                        "action": {
                            "type": "string",
                            "description": ("pass, block, or reject (default: 'pass')"),
                            "optional": True,
                        },
                        "protocol": {
                            "type": "string",
                            "description": (
                                "any, tcp, udp, icmp, etc. (default: 'any')"
                            ),
                            "optional": True,
                        },
                        "source_net": {
                            "type": "string",
                            "description": ("Source network/IP (default: 'any')"),
                            "optional": True,
                        },
                        "source_port": {
                            "type": "string",
                            "description": "Source port (default: 'any')",
                            "optional": True,
                        },
                        "destination_net": {
                            "type": "string",
                            "description": ("Destination network/IP (default: 'any')"),
                            "optional": True,
                        },
                        "destination_port": {
                            "type": "string",
                            "description": "Destination port (default: 'any')",
                            "optional": True,
                        },
                        "direction": {
                            "type": "string",
                            "description": "in or out (default: 'in')",
                            "optional": True,
                        },
                        "ipprotocol": {
                            "type": "string",
                            "description": "inet or inet6 (default: 'inet')",
                            "optional": True,
                        },
                        "enabled": {
                            "type": "boolean",
                            "description": "true or false (default: true)",
                            "optional": True,
                        },
                        "gateway": {
                            "type": "string",
                            "description": "Gateway to use (default: '')",
                            "optional": True,
                        },
                        "apply": {
                            "type": "boolean",
                            "description": (
                                "Whether to apply changes immediately (default: true)"
                            ),
                            "optional": True,
                        },
                    },
                    "required": ["description"],
                },
            },
            {
                "name": "rmfw_rule",
                "description": ("Delete a firewall rule and optionally apply changes"),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "rule_uuid": {
                            "type": "string",
                            "description": ("UUID of the rule to delete (required)"),
                        },
                        "apply": {
                            "type": "boolean",
                            "description": (
                                "Whether to apply changes immediately (default: true)"
                            ),
                            "optional": True,
                        },
                    },
                    "required": ["rule_uuid"],
                },
            },
            {
                "name": "interface_list",
                "description": "Get available interface names for firewall rules",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": [],
                },
            },
        ]
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": tools}}

    # Support both tools/call and tool/call
    if method in ("tools/call", "tool/call"):
        params = message.get("params", {})
        if not params:
            # For tool/call, some clients may use top-level keys
            params = message
        tool_name = params.get("name") or params.get("tool") or ""
        arguments = params.get("arguments") or params.get("args") or {}
        if tool_name == "arp":
            result = await arp_tool.execute(arguments)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"content": [{"type": "text", "text": str(result)}]},
            }
        if tool_name == "dhcp":
            result = await dhcp_tool.execute(arguments)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"content": [{"type": "text", "text": str(result)}]},
            }
        if tool_name == "get_logs":
            logs = await firewall_logs.get_logs(
                limit=arguments.get("limit", 500),
                action=arguments.get("action"),
                src_ip=arguments.get("src_ip"),
                dst_ip=arguments.get("dst_ip"),
                protocol=arguments.get("protocol"),
            )
            return format_log_response(logs, msg_id)
        if tool_name == "lldp":
            result = await lldp_tool.execute(arguments)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"content": [{"type": "text", "text": str(result)}]},
            }
        if tool_name == "system":
            result = await system_tool.execute(arguments)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"content": [{"type": "text", "text": str(result)}]},
            }
        if tool_name == "fw_rules":
            result = await fw_rules_tool.execute(arguments)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"content": [{"type": "text", "text": str(result)}]},
            }
        if tool_name == "mkfw_rule":
            result = await mkfw_rule_tool.execute(arguments)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"content": [{"type": "text", "text": str(result)}]},
            }
        if tool_name == "rmfw_rule":
            result = await rmfw_rule_tool.execute(arguments)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"content": [{"type": "text", "text": str(result)}]},
            }
        if tool_name == "interface_list":
            result = await interface_list_tool.execute(arguments)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"content": [{"type": "text", "text": str(result)}]},
            }
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {
                "code": -32601,
                "message": f"Tool not found: {tool_name}",
            },
        }

    return None


def error_response(
    code: int, message: str, msg_id: str | None = None
) -> dict[str, Any]:
    """Create a JSON-RPC error response."""
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {
            "code": code,
            "message": message,
        },
    }


def main() -> None:
    """Run the MCP server main entry point."""
    print("SERVER STARTED", file=sys.stderr)
    # Configure logging
    log_level = os.environ.get("LOG_LEVEL", "INFO")
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        stream=sys.stderr,
    )

    # Initialize client
    client = get_opnsense_client({})

    # Initialize tools
    firewall_logs = GetLogsTool(client)
    arp_tool = ARPTool(client)
    dhcp_tool = DHCPTool(client)
    lldp_tool = LLDPTool(client)
    system_tool = SystemTool(client)
    fw_rules_tool = FwRulesTool(client)
    mkfw_rule_tool = MkfwRuleTool(client)
    rmfw_rule_tool = RmfwRuleTool(client)
    interface_list_tool = InterfaceListTool(client)

    # Handle stdin/stdout communication
    async def process_messages() -> None:
        """Process incoming messages from the MCP client."""
        while True:
            try:
                # Read a line and handle EOF
                line = sys.stdin.readline()
                if not line:
                    break

                # Remove trailing newlines and skip empty lines
                line = line.strip()
                if not line:
                    continue

                # Log raw input for debugging
                logger.debug(f"Raw input line: {line!r}")
                print(f"Received line: {line}", file=sys.stderr)

                # Parse the JSON message
                message = json.loads(line)
                msg_id = message.get("id")
                logger.debug(f"Parsed message: {message}")
                print(f"Parsed message: {message}", file=sys.stderr)

                # Validate required fields
                if "jsonrpc" not in message or message["jsonrpc"] != "2.0":
                    err = error_response(
                        -32600, "Invalid Request: jsonrpc 2.0 required", msg_id
                    )
                    sys.stdout.write(json.dumps(err) + "\n")
                    sys.stdout.flush()
                    continue

                if "method" not in message:
                    err = error_response(
                        -32600, "Invalid Request: method required", msg_id
                    )
                    sys.stdout.write(json.dumps(err) + "\n")
                    sys.stdout.flush()
                    continue

                # Handle the message
                response = await handle_message(
                    message,
                    firewall_logs,
                    arp_tool,
                    dhcp_tool,
                    lldp_tool,
                    system_tool,
                    fw_rules_tool,
                    mkfw_rule_tool,
                    rmfw_rule_tool,
                    interface_list_tool,
                )
                if response is not None:
                    print(
                        f"Writing to stdout: {json.dumps(response)}",
                        file=sys.stderr,
                    )
                    sys.stdout.write(json.dumps(response) + "\n")
                    sys.stdout.flush()
                    logger.debug(f"Sent response: {response}")
                elif msg_id is not None:
                    err = error_response(
                        -32601,
                        f"Method '{message.get('method')}' not found",
                        msg_id,
                    )
                    print(
                        f"Writing to stdout: {json.dumps(err)}",
                        file=sys.stderr,
                    )
                    sys.stdout.write(json.dumps(err) + "\n")
                    sys.stdout.flush()

            except json.JSONDecodeError:
                logger.exception("Invalid JSON")
                err = error_response(-32700, "Parse error")
                sys.stdout.write(json.dumps(err) + "\n")
                sys.stdout.flush()
            except Exception as e:
                logger.exception("Error handling message")
                err_msg = f"Internal error: {str(e)}"
                err = error_response(-32603, err_msg, msg_id)
                sys.stdout.write(json.dumps(err) + "\n")
                sys.stdout.flush()

    print("About to enter message loop", file=sys.stderr)
    asyncio.run(process_messages())


if __name__ == "__main__":
    try:
        main()
    except Exception:
        logger.exception("Fatal error")
        sys.exit(1)
