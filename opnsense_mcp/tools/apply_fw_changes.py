"""Apply staged firewall filter changes.

Every fw_rule write takes `apply`, and staging is the default. Until this tool
existed, a change staged with `apply=false` had no documented way to be applied
over MCP: the guidance told callers to "use apply_firewall_changes()", which is
a client method, not a tool, and not a member of the `fw_rule` group. The only
workaround was to issue a second write with `apply=true`.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)


class ApplyFwChangesTool:
    """Load staged firewall filter changes into the running ruleset."""

    name = "apply_fw_changes"
    description = (
        "Apply staged firewall filter changes, loading every rule written with "
        "apply=false into the running ruleset"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {},
        "required": [],
    }

    def __init__(self, client: OPNsenseClient | None) -> None:
        """Store the OPNsense client."""
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Apply the staged filter, reporting whether it loaded."""
        if not self.client:
            return {"status": "error", "error": "No client available", "applied": False}

        try:
            result = await self.client.apply_firewall_changes()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to apply firewall changes")
            return {"status": "error", "error": str(exc), "applied": False}

        return {"status": "success", "applied": True, "result": result}
