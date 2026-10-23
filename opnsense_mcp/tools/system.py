"""System status monitoring tool for OPNsense."""

import logging
from typing import Any

from pydantic import BaseModel

from opnsense_mcp.build_info import get_build_info
from opnsense_mcp.utils.api import OPNsenseClient
from opnsense_mcp.utils.deploy_probe import runtime_paths_report
from opnsense_mcp.utils.mock_api import MockOPNsenseClient

logger = logging.getLogger(__name__)


class SystemStatus(BaseModel):
    """Model for system status information."""

    hostname: str | None = None
    version: str | None = None
    uptime: str | None = None
    load_average: list[float] | None = None
    cpu_usage: float | None = None
    memory_usage: float | None = None
    disk_usage: dict[str, Any] | None = None
    temperature: dict[str, Any] | None = None


def client_kind(client: object) -> str:
    """Return "mock" for the fixture-backed client, "live" for anything else."""
    return "mock" if isinstance(client, MockOPNsenseClient) else "live"


class SystemTool:
    """Tool for retrieving system status information from OPNsense."""

    name = "system"
    description = "Show system status information"
    input_schema = {
        "properties": {
            "action": {
                "description": (
                    "'status' (default) or 'diagnose_mcp'. diagnose_mcp is "
                    "read-only: it reports issues and suggested fixes and "
                    "runs none of them."
                ),
                "enum": ["status", "diagnose_mcp"],
                "type": "string",
            },
        },
        "required": [],
        "type": "object",
    }

    def __init__(self, client: OPNsenseClient | None) -> None:
        """
        Initialize the system tool.

        Args:
            client: OPNsense client instance for API communication.

        """
        self.client = client

    async def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        """
        Execute system status check or diagnostics.

        Args:
            params: Execution parameters. Can include:
                - action: "status" (default) or "diagnose_mcp"

        Returns:
            Dictionary containing system status information or diagnostic results.

        """
        action = params.get("action", "status")

        if action == "diagnose_mcp":
            return await self.diagnose_mcp_server()

        try:
            if not self.client:
                return {"status": "error", "error": "No client available", "system": {}}

            # Get basic system information
            system_info = await self.client.get_system_status()

            # Try to get additional health data if available
            health_data = {}
            try:
                # Use public method if available, otherwise basic info
                if hasattr(self.client, "get_system_health"):
                    health_data = await self.client.get_system_health()
                else:
                    # Fallback to basic system info
                    health_data = system_info.get("data", {})
            except Exception as health_error:
                logger.warning(f"Could not retrieve health data: {health_error}")
                health_data = {}

            # Combine system info and health data
            combined_status = {**system_info, **health_data}

            return {
                "status": "success",
                # Mock data is shaped like the firewall's, so without this a
                # caller could not tell fixture output from live state (#99).
                "client": client_kind(self.client),
                "system": combined_status,
                "mcp_server": {
                    **get_build_info(),
                    # Our own runtime paths, judged at call time. A broken
                    # path is a finding to report here, never a reason to
                    # fail the call: `system` is the tool someone calls to
                    # find out what is wrong. Before this, the only way to
                    # learn a deployed backup directory was broken was to
                    # attempt a download and read the error.
                    "runtime_paths": runtime_paths_report(),
                },
            }

        except Exception as e:
            logger.exception("Failed to get system status")
            return {
                "status": "error",
                "error": str(e),
                "client": client_kind(self.client),
                "system": {},
            }

    async def diagnose_mcp_server(self) -> dict[str, Any]:
        """Diagnose MCP server issues and suggest fixes, changing nothing.

        This used to run ``./mcp_start.sh``, ``python3 -m venv .venv`` and
        ``pip install`` as "auto-corrections" from a status tool (#93). The
        only subprocess left is ``pgrep``, which reads the process table.
        """
        import subprocess  # nosec B404 — read-only pgrep only
        from pathlib import Path

        issues = []
        solutions = []

        try:
            result = subprocess.run(
                ["pgrep", "-f", "opnsense_mcp/server.py"],
                capture_output=True,
                text=True,
                timeout=5,
            )  # nosec B603 B607 — hardcoded command, no user input
            if result.returncode != 0:
                issues.append("OPNsense MCP server is not running")
                solutions.append("Restart the MCP server using: ./mcp_start.sh")
        except Exception as e:
            issues.append(f"Could not check MCP server status: {e}")

        if not (Path.cwd() / ".venv").exists():
            issues.append("Virtual environment (.venv) is missing")
            solutions.append("Recreate virtual environment: uv sync")

        try:
            import dotenv  # noqa: F401
            import paramiko  # noqa: F401
        except ImportError as e:
            issues.append(f"Missing dependency: {e}")
            solutions.append("Install dependencies: uv sync")

        if self.client is None:
            issues.append("No OPNsense client available")
            solutions.append("Check OPNSENSE_* credentials and firewall connectivity")

        return {
            "status": "healthy" if not issues else "needs_attention",
            "issues": issues,
            "solutions": solutions,
            "summary": f"Found {len(issues)} issues",
        }
