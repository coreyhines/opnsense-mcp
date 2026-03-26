"""Unbound DNS host override listing tool for OPNsense."""

import logging
from typing import Any

from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)


class DNSTool:
    """Tool for listing Unbound DNS host overrides."""

    name = "dns"
    description = "List Unbound DNS host overrides"
    input_schema = {
        "type": "object",
        "properties": {
            "search": {
                "type": "string",
                "description": "Filter by hostname, IP, or description",
                "optional": True,
            },
        },
        "required": [],
    }

    def __init__(self, client: OPNsenseClient | None) -> None:
        """
        Initialize the DNS listing tool.

        Args:
            client: OPNsense client instance for API communication.

        """
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        List Unbound DNS host overrides with optional filtering.

        Args:
            params: Optional dict with 'search' key.

        Returns:
            Dictionary containing host overrides and count.

        """
        if params is None:
            params = {}

        if not self.client:
            return {"status": "error", "error": "No client available"}

        try:
            search = params.get("search", "")
            overrides = await self.client.search_host_overrides(search)
            return {
                "overrides": overrides,
                "count": len(overrides),
                "status": "success",
            }
        except Exception as e:
            logger.exception("Failed to list DNS host overrides")
            return {"status": "error", "error": str(e)}
