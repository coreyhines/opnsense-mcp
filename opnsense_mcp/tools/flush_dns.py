"""Unbound DNS cache flush tool for OPNsense."""

from __future__ import annotations

import logging
import re
import shlex
from typing import TYPE_CHECKING, Any

from opnsense_mcp.utils.ssh_client import OPNsenseSSHClient

if TYPE_CHECKING:
    from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)

_UNBOUND_CONTROL = "/usr/local/sbin/unbound-control"


class FlushDnsTool:
    """Flush Unbound DNS cache entries after host override changes."""

    name = "flush_dns"
    description = (
        "Flush Unbound DNS cache for a hostname (SSH unbound-control) or restart "
        "Unbound (API) to clear all cached answers"
    )
    input_schema = {
        "type": "object",
        "properties": {
            "hostname": {
                "type": "string",
                "description": (
                    "FQDN to flush from cache (e.g. headroom.freeblizz.com). "
                    "Required when mode=name."
                ),
                "optional": True,
            },
            "mode": {
                "type": "string",
                "description": (
                    "name: flush one hostname via unbound-control (default); "
                    "restart: restart Unbound via API (clears full cache)"
                ),
                "optional": True,
            },
        },
        "required": [],
    }

    def __init__(self, client: OPNsenseClient | None) -> None:
        self.client = client
        self._ssh = OPNsenseSSHClient(client)

    def _validate_hostname(self, hostname: str) -> str | None:
        host = hostname.strip().rstrip(".")
        if not host or not _HOSTNAME_RE.match(host):
            return None
        return host

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if params is None:
            params = {}

        if not self.client:
            return {"status": "error", "error": "No client available"}

        mode = str(params.get("mode", "name")).strip().lower() or "name"
        if mode not in {"name", "restart"}:
            return {
                "status": "error",
                "error": "mode must be 'name' or 'restart'",
            }

        if mode == "restart":
            try:
                result = await self.client.restart_unbound()
                return {
                    "status": "success",
                    "mode": "restart",
                    "applied": True,
                    "result": result,
                }
            except Exception as e:
                logger.exception("Failed to restart Unbound")
                return {"status": "error", "error": str(e), "mode": "restart"}

        hostname = str(params.get("hostname", "")).strip()
        validated = self._validate_hostname(hostname)
        if not validated:
            return {
                "status": "error",
                "error": "hostname must be a valid FQDN when mode=name",
                "mode": "name",
            }

        command = f"{_UNBOUND_CONTROL} flush {shlex.quote(validated)}"
        ssh_result = self._ssh.execute_command(command)
        if ssh_result.get("success"):
            return {
                "status": "success",
                "mode": "name",
                "hostname": validated,
                "applied": True,
                "command": command,
                "stdout": ssh_result.get("stdout", ""),
            }

        return {
            "status": "error",
            "mode": "name",
            "hostname": validated,
            "error": ssh_result.get("stderr") or "unbound-control flush failed",
            "command": command,
            "exit_code": ssh_result.get("exit_code"),
            "hint": "Retry with mode=restart to clear full Unbound cache via API",
        }
