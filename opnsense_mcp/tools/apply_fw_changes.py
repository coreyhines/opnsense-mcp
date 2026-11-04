"""Apply staged firewall filter changes.

Every fw_rule write takes `apply`, and staging is the default. Until this tool
existed, a change staged with `apply=false` had no documented way to be applied
over MCP: the guidance told callers to "use apply_firewall_changes()", which is
a client method, not a tool, and not a member of the `fw_rule` group. The only
workaround was to issue a second write with `apply=true`.

The filter apply does not load alias tables. An alias created with
`apply=false` stayed at zero entries through a later filter apply, so a rule
referencing it matched nothing while reporting applied (agent-fence #4). Aliases
are reconfigured first so the rules load against populated tables.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from opnsense_mcp.tools.alias_write import ENDPOINTS as ALIAS_ENDPOINTS
from opnsense_mcp.utils.apply import ApplyError, run_apply

if TYPE_CHECKING:
    from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)


class ApplyFwChangesTool:
    """Load staged aliases and firewall filter changes into the running ruleset."""

    name = "apply_fw_changes"
    description = (
        "Apply staged firewall changes: reload alias tables, then load every "
        "rule written with apply=false into the running ruleset. Aliases staged "
        "with apply=false hold no entries until this runs"
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
        """Reload aliases, then apply the staged filter, reporting each."""
        if not self.client:
            return {"status": "error", "error": "No client available", "applied": False}

        # Independent of the filter apply: a failed alias reload still leaves
        # staged rules worth loading, and the result says which half failed.
        aliases_applied, alias_error = True, ""
        try:
            await run_apply(self.client, ALIAS_ENDPOINTS["reconfigure"])
        except ApplyError as exc:
            logger.warning("Alias reconfigure failed: %s", exc)
            aliases_applied, alias_error = False, str(exc)

        try:
            result = await self.client.apply_firewall_changes()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to apply firewall changes")
            out: dict[str, Any] = {
                "status": "error",
                "error": str(exc),
                "applied": False,
                "aliases_applied": aliases_applied,
            }
            if alias_error:
                out["alias_error"] = alias_error
            return out

        out = {
            "status": "success" if aliases_applied else "error",
            "applied": True,
            "aliases_applied": aliases_applied,
            "result": result,
        }
        if alias_error:
            out["alias_error"] = alias_error
        return out
