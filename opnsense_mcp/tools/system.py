#!/usr/bin/env python3

from typing import Dict, Any
from pydantic import BaseModel
import logging

logger = logging.getLogger(__name__)


class SystemStatus(BaseModel):
    """Model for system status data"""

    cpu_usage: float
    memory_usage: float
    filesystem_usage: Dict[str, float]
    uptime: str
    versions: Dict[str, str]


class SystemTool:
    def __init__(self, client):
        self.client = client

    async def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute system status check"""
        try:
            status_data = await self.client.get_system_status()
            return status_data
        except Exception as e:
            logger.error(f"Failed to get system status: {str(e)}")
            raise RuntimeError(f"Failed to get system status: {str(e)}")

    async def _get_system_health(self) -> Dict[str, Any]:
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
                response = await self.client._make_request(
                    "GET", "/core/system/status"
                )
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
                            status_data["filesystem_usage"][mount] = float(
                                used
                            )

                status_data["uptime"] = health_data.get("uptime", "")
                if "version" in health_data:
                    status_data["versions"]["opnsense"] = health_data[
                        "version"
                    ]
                if "kernel" in health_data:
                    status_data["versions"]["kernel"] = health_data["kernel"]

            except Exception as e:
                logger.warning(f"Failed to get system health data: {str(e)}")

            return status_data

        except Exception as e:
            logger.error(f"Failed to get system health information: {str(e)}")
            raise RuntimeError(f"Failed to get system health: {str(e)}")
