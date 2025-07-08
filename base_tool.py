"""Base tool implementation."""

from abc import ABC, abstractmethod
from typing import Any

from client import OPNsenseClient


class BaseTool(ABC):
    """Base class for all tools."""

    def __init__(self, client: OPNsenseClient | None = None) -> None:
        """
        Initialize the tool.

        Args:
            client: Optional OPNsense client instance

        """
        self.client = client or OPNsenseClient(mock=True)

    @abstractmethod
    async def execute(self, params: dict[str, Any] = None) -> dict[str, Any]:
        """
        Execute the tool.

        Args:
            params: Optional parameters specific to the tool

        Returns:
            dict: Tool execution result
                - result: The actual result data if successful
                - error: Error message if execution failed

        """
