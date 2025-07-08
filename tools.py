"""Main tools execution module for the OPNsense MCP server."""

import asyncio
import logging
from typing import Any

from opnsense_mcp.utils.logging import setup_logging
from opnsense_mcp.utils.mock_api import MockOPNsenseClient
from tools.arp import ARPTool

logger = logging.getLogger(__name__)


async def execute_tool(tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
    """
    Execute a tool with given arguments.

    Args:
        tool_name: Name of the tool to execute.
        args: Arguments to pass to the tool.

    Returns:
        Result dictionary from tool execution.

    """
    try:
        # Create mock client for testing
        config = {"development": {"mock_data_path": "./examples/mock_data"}}
        client = MockOPNsenseClient(config)

        if tool_name == "arp":
            tool = ARPTool(client)
        else:
            return {"error": f"Unknown tool: {tool_name}"}

        result = await tool.execute(**args)
        logger.debug(f"Tool {tool_name} execution result: {result}")
        return result
    except Exception:
        logger.exception(f"Error executing tool {tool_name}:")
        return {"error": f"Tool execution failed: {tool_name}"}


async def main() -> None:
    """Main entry point for tools execution."""
    # Setup logging
    setup_logging()

    # Example usage
    result = await execute_tool("arp", {"search": "test"})
    print(f"Result: {result}")


if __name__ == "__main__":
    asyncio.run(main())
