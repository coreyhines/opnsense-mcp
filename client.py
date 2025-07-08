"""OPNsense MCP client."""

import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class OPNsenseClient:
    """Client for interacting with OPNsense API."""

    def __init__(self, mock: bool = False, mock_data_path: str | None = None) -> None:
        """
        Initialize the OPNsense client.

        Args:
            mock: Whether to use mock data instead of real API calls
            mock_data_path: Path to mock data directory

        """
        self.mock = mock
        self.mock_data_path = mock_data_path or os.environ.get(
            "MOCK_DATA_PATH", "examples/mock_data"
        )
        logger.debug(
            f"Initialized OPNsense client (mock={mock}, "
            f"mock_data_path={mock_data_path})"
        )

    async def get_arp_table(self, params: dict[str, Any] = None) -> dict:
        """
        Get ARP/NDP table information.

        Args:
            params: Optional query parameters
                - ip: Filter by IP address
                - mac: Filter by MAC address
                - limit: Maximum number of entries to return

        Returns:
            dict: ARP table information

        """
        if self.mock:
            return await self._get_mock_data("arp.json", params)
        # TODO: Implement real API call
        raise NotImplementedError("Real API calls not implemented yet")

    async def _get_mock_data(
        self, filename: str, params: dict[str, Any] = None
    ) -> dict:
        """
        Get mock data from a JSON file.

        Args:
            filename: Name of the mock data file
            params: Optional query parameters to filter the data

        Returns:
            dict: Mock data

        """
        params = params or {}
        file_path = Path(self.mock_data_path) / filename
        logger.debug(f"Loading mock data from {file_path}")

        try:
            with open(file_path) as f:
                data = json.load(f)
        except FileNotFoundError:
            logger.exception(f"Mock data file not found: {file_path}")
            return {"entries": [], "total": 0}
        except json.JSONDecodeError:
            logger.exception(f"Invalid JSON in mock data file: {file_path}")
            return {"entries": [], "total": 0}

        # Apply filters
        entries = data.get("entries", [])
        if params.get("ip"):
            entries = [e for e in entries if params["ip"] in e.get("ip", "")]
        if params.get("mac"):
            entries = [e for e in entries if params["mac"] in e.get("mac", "")]
        if params.get("limit") is not None:
            entries = entries[: params["limit"]]

        return {"entries": entries, "total": len(entries)}
