"""OPNsense MCP tools module."""

import logging

from base_tool import BaseTool
from client import OPNsenseClient
from opnsense_mcp.tools import TOOL_CLASSES

logger = logging.getLogger(__name__)

# Use the same tool registry as opnsense_mcp/tools/__init__.py
TOOLS: dict[str, type[BaseTool]] = TOOL_CLASSES


async def execute_tool(client: OPNsenseClient, tool_name: str, args: dict) -> dict:
    """Execute a tool with the given arguments."""
    logger.debug(f"Executing tool {tool_name} with args {args}")

    # Get the tool class
    tool_class = get_tool(tool_name, client)
    if not tool_class:
        raise ValueError(f"Tool {tool_name} not found")

    # Execute the tool
    try:
        result = await tool_class.execute(args)
        logger.debug(f"Tool {tool_name} execution result: {result}")
        return result
    except Exception:
        logger.exception(f"Error executing tool {tool_name}:")
        raise


def get_tool(name: str, client: OPNsenseClient) -> BaseTool | None:
    """
    Get a tool instance by name.

    Args:
        name: Tool name (with or without prefix)
        client: OPNsense client instance

    Returns:
        BaseTool: Tool instance if found, None otherwise

    """
    # Strip any prefixes (mcp_, opnsense-mcp-local_)
    name = name.replace("mcp_", "").replace("opnsense-mcp-local_", "")

    tool_class = TOOLS.get(name)
    if tool_class is None:
        logger.error(f"Tool not found: {name}")
        return None

    try:
        return tool_class(client)
    except Exception as e:
        logger.exception(f"Error creating tool instance: {e}")
        return None
