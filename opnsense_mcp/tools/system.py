"""System status monitoring tool for OPNsense."""

import logging
from typing import Any

from pydantic import BaseModel

from opnsense_mcp.utils.api import OPNsenseClient

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


class SystemTool:
    """Tool for retrieving system status information from OPNsense."""

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

            return {"status": "success", "system": combined_status}

        except Exception as e:
            logger.exception("Failed to get system status")
            return {"status": "error", "error": str(e), "system": {}}

    async def diagnose_mcp_server(self) -> dict[str, Any]:
        """Diagnose MCP server issues and provide solutions."""
        import subprocess
        import time
        from pathlib import Path

        issues = []
        solutions = []
        corrections = []

        # Check if MCP server process is running
        try:
            result = subprocess.run(
                ["pgrep", "-f", "opnsense_mcp/server.py"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                issues.append("OPNsense MCP server is not running")
                solutions.append("Restart the MCP server using: ./mcp_start.sh")

                # Try to auto-restart
                try:
                    subprocess.run(
                        ["./mcp_start.sh"],
                        cwd=Path.cwd(),
                        timeout=10,
                        capture_output=True,
                    )
                    corrections.append("Attempted to restart MCP server")
                    time.sleep(2)
                except Exception as e:
                    issues.append(f"Failed to restart MCP server: {e}")
        except Exception as e:
            issues.append(f"Could not check MCP server status: {e}")

        # Check virtual environment
        venv_path = Path.cwd() / ".venv"
        if not venv_path.exists():
            issues.append("Virtual environment (.venv) is missing")
            solutions.append("Recreate virtual environment: python3 -m venv .venv")

            # Try to auto-recreate
            try:
                subprocess.run(
                    ["python3", "-m", "venv", ".venv"],
                    cwd=Path.cwd(),
                    timeout=30,
                    capture_output=True,
                )
                corrections.append("Recreated virtual environment")
            except Exception as e:
                issues.append(f"Failed to recreate virtual environment: {e}")

        # Check dependencies
        try:
            import dotenv
            import paramiko
        except ImportError as e:
            issues.append(f"Missing dependency: {e}")
            solutions.append("Install dependencies: pip install -r requirements.txt")

            # Try to auto-install
            try:
                subprocess.run(
                    [
                        "source",
                        ".venv/bin/activate",
                        "&&",
                        "pip",
                        "install",
                        "-r",
                        "requirements.txt",
                    ],
                    cwd=Path.cwd(),
                    shell=True,
                    timeout=60,
                    capture_output=True,
                )
                corrections.append("Installed dependencies")
            except Exception as e:
                issues.append(f"Failed to install dependencies: {e}")

        # Check SSH connectivity
        try:
            client = self._get_client()
            client.close()
        except Exception as e:
            issues.append(f"SSH connection failed: {e}")
            solutions.append("Check SSH configuration and firewall connectivity")

        return {
            "status": "healthy" if len(issues) == 0 else "needs_attention",
            "issues": issues,
            "solutions": solutions,
            "auto_corrections": corrections,
            "summary": f"Found {len(issues)} issues, applied {len(corrections)} auto-corrections",
        }
