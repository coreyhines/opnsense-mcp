"""Firewall alias listing tool for OPNsense."""

import logging
from typing import Any

from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)


class AliasesTool:
    """Tool for listing firewall aliases (IP groups, port groups, etc)."""

    name = "aliases"
    description = "List firewall aliases (IP groups, port groups, etc)"
    input_schema = {
        "type": "object",
        "properties": {
            "search": {
                "type": "string",
                "description": "Filter by alias name, type, or content",
                "optional": True,
            },
        },
        "required": [],
    }

    def __init__(self, client: OPNsenseClient | None) -> None:
        """
        Initialize the aliases listing tool.

        Args:
            client: OPNsense client instance for API communication.

        """
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        List firewall aliases with optional filtering.

        Args:
            params: Optional dict with 'search' key.

        Returns:
            Dictionary containing aliases and count.

        """
        if params is None:
            params = {}

        if not self.client:
            return {"status": "error", "error": "No client available"}

        try:
            search = params.get("search", "")
            aliases = await self.client.search_aliases(search)
            return {
                "aliases": aliases,
                "count": len(aliases),
                "status": "success",
            }
        except Exception as e:
            logger.exception("Failed to list firewall aliases")
            return {"status": "error", "error": str(e)}
