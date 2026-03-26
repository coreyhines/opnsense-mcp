"""Unbound DNS host override deletion tool for OPNsense."""

import logging
from typing import Any

from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)


class RmdnsTool:
    """Tool for deleting Unbound DNS host overrides."""

    name = "rmdns"
    description = "Delete a DNS host override from Unbound"
    input_schema = {
        "type": "object",
        "properties": {
            "uuid": {
                "type": "string",
                "description": "UUID of the host override to delete (from dns tool output)",
            },
        },
        "required": ["uuid"],
    }

    def __init__(self, client: OPNsenseClient | None) -> None:
        """
        Initialize the DNS deletion tool.

        Args:
            client: OPNsense client instance for API communication.

        """
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Delete a DNS host override by UUID and reload Unbound.

        Args:
            params: Dict with 'uuid' key.

        Returns:
            Dictionary containing the deleted UUID and status.

        """
        if params is None:
            params = {}

        if not self.client:
            return {"status": "error", "error": "No client available"}

        uuid = params.get("uuid", "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}

        try:
            result = await self.client.del_host_override(uuid)

            if result.get("result") not in ("deleted", "ok", 1):
                return {
                    "status": "error",
                    "error": f"Delete failed: {result}",
                }

            await self.client.reconfigure_unbound()

            return {
                "uuid": uuid,
                "applied": True,
                "status": "success",
            }
        except Exception as e:
            logger.exception("Failed to delete DNS host override")
            return {"status": "error", "error": str(e)}
