#!/usr/bin/env python3

import logging
from typing import Any

from pydantic import BaseModel

from opnsense_mcp.utils.mock_api import MockOPNsenseClient

logger = logging.getLogger(__name__)


class SystemStatus(BaseModel):
    """Model for system status data"""

    cpu_usage: float
    memory_usage: float
    filesystem_usage: dict[str, float]
    uptime: str
    versions: dict[str, str]


class SystemTool:
    def __init__(self, client):
        self.client = client

    async def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        """Execute system status check"""
        try:
            if self.client is None or isinstance(self.client, MockOPNsenseClient):
                logger.warning(
                    "No real OPNsense client available, returning mock "
                    "system status data"
                )
                return await self.client.get_system_status()
            return await self.client.get_system_status()
        except Exception as e:
            logger.exception("Failed to get system status")
            return {
                "error": f"Failed to get system status: {str(e)}",
                "status": "error",
            }

    async def _get_system_health(self) -> dict[str, Any]:
        """Get system health information from various OPNsense endpoints"""
        try:
            status_data = {
                "cpu_usage": 0.0,
                "memory_usage": 0.0,
                "filesystem_usage": {},
                "uptime": "",
                "versions": {"opnsense": "", "kernel": ""},
            }

            # Get data from core/system endpoints
            try:
                response = await self.client._make_request("GET", "/core/system/status")
                health_data = response.get("data", {})

                if "cpu" in health_data:
                    cpu_info = health_data["cpu"]
                    if isinstance(cpu_info, dict):
                        status_data["cpu_usage"] = float(
                            cpu_info.get("used", "0").rstrip("%")
                        )

                if "memory" in health_data:
                    mem_info = health_data["memory"]
                    if isinstance(mem_info, dict):
                        status_data["memory_usage"] = float(
                            mem_info.get("used", "0").rstrip("%")
                        )

                if "filesystems" in health_data:
                    for fs in health_data["filesystems"]:
                        if isinstance(fs, dict):
                            mount = fs.get("mountpoint", "")
                            used = fs.get("used_percent", "0").rstrip("%")
                            status_data["filesystem_usage"][mount] = float(used)

                status_data["uptime"] = health_data.get("uptime", "")
                if "version" in health_data:
                    status_data["versions"]["opnsense"] = health_data["version"]
                if "kernel" in health_data:
                    status_data["versions"]["kernel"] = health_data["kernel"]

            except Exception as e:
                logger.warning(f"Failed to get system health data: {str(e)}")

        except Exception as e:
            logger.exception("Failed to get system health information")
            raise RuntimeError(f"Failed to get system health: {str(e)}") from e
        else:
            return status_data
