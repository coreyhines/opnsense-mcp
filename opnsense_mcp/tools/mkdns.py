"""Unbound DNS host override creation tool for OPNsense."""

import logging
from typing import Any

from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)


class MkdnsTool:
    """Tool for adding Unbound DNS host overrides."""

    name = "mkdns"
    description = "Add a DNS host override in Unbound"
    input_schema = {
        "type": "object",
        "properties": {
            "hostname": {
                "type": "string",
                "description": "Hostname (without domain, e.g. 'myserver')",
            },
            "domain": {
                "type": "string",
                "description": "Domain (e.g. 'local' or 'example.com')",
            },
            "server": {
                "type": "string",
                "description": "IP address this hostname resolves to",
            },
            "description": {
                "type": "string",
                "description": "Optional description",
                "optional": True,
            },
            "enabled": {
                "type": "boolean",
                "description": "Whether the override is active (default: true)",
                "optional": True,
            },
        },
        "required": ["hostname", "domain", "server"],
    }

    def __init__(self, client: OPNsenseClient | None) -> None:
        """
        Initialize the DNS creation tool.

        Args:
            client: OPNsense client instance for API communication.

        """
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Add a new DNS host override and reload Unbound.

        Args:
            params: Dict with hostname, domain, server, and optional fields.

        Returns:
            Dictionary containing the created override UUID and status.

        """
        if params is None:
            params = {}

        if not self.client:
            return {"status": "error", "error": "No client available"}

        hostname = params.get("hostname", "").strip()
        domain = params.get("domain", "").strip()
        server = params.get("server", "").strip()

        if not hostname or not domain or not server:
            return {
                "status": "error",
                "error": "hostname, domain, and server are required",
            }

        try:
            result = await self.client.add_host_override(
                hostname=hostname,
                domain=domain,
                server=server,
                description=params.get("description", ""),
                enabled=params.get("enabled", True),
            )

            uuid = result.get("uuid", "")
            if not uuid:
                return {
                    "status": "error",
                    "error": f"API did not return a UUID: {result}",
                }

            await self.client.reconfigure_unbound()

            return {
                "uuid": uuid,
                "hostname": hostname,
                "domain": domain,
                "server": server,
                "applied": True,
                "status": "success",
            }
        except Exception as e:
            logger.exception("Failed to add DNS host override")
            return {"status": "error", "error": str(e)}
