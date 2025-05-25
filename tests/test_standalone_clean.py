#!/usr/bin/env python3
"""
Standalone command-line tool for testing OPNsense API functionality directly.

This provides a simple interface for testing key API functions.
"""

import argparse
import base64
import json
import logging
import ssl
import sys
from pathlib import Path
from typing import Any

import requests
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


class OPNsenseAPIError(Exception):
    """Base API error for OPNsense."""


class OPNsenseClient:
    """Simplified OPNsense API client for testing."""

    def __init__(self, config: dict[str, Any]) -> None:
        """Initialize the OPNsense API client."""
        self.api_key = config["api_key"]
        self.api_secret = config["api_secret"]
        self.host = config["firewall_host"]
        self.base_url = f"https://{self.host}"
        self.api_url = f"{self.base_url}/api"

        # Configure SSL context to ignore verification
        ssl._create_default_https_context = ssl._create_unverified_context

        # Setup session for requests
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update(
            {
                "Authorization": f"Basic {self._get_basic_auth()}",
                "Content-Type": "application/json",
            }
        )

    def _get_basic_auth(self) -> str:
        """Create basic auth header from api key and secret."""
        auth_str = f"{self.api_key}:{self.api_secret}"
        encoded = base64.b64encode(auth_str.encode()).decode()
        return encoded

    def request(
        self, endpoint: str, method: str = "GET", **kwargs: Any
    ) -> dict[str, Any]:
        """Make a request to the API."""
        if not endpoint.startswith("/api"):
            endpoint = f"/api{endpoint}"

        url = f"{self.base_url}{endpoint}"
        logger.debug(f"Making {method} request to {url}")

        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()

            try:
                return response.json()
            except json.JSONDecodeError:
                return {"raw_response": response.text}

        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            raise OPNsenseAPIError(f"API request failed: {e}") from e

    def get_system_status(self) -> dict[str, Any]:
        """Get system status information."""
        try:
            return self.request("/core/system/status")
        except Exception as e:
            logger.error(f"Failed to get system status: {e}")
            raise

    def get_arp_table(self) -> dict[str, Any]:
        """Get ARP table entries."""
        try:
            return self.request("/diagnostics/interface/getArp")
        except Exception as e:
            logger.error(f"Failed to get ARP table: {e}")
            raise


def load_config(config_path: str) -> dict[str, Any]:
    """Load configuration from YAML file."""
    try:
        with Path(config_path).open() as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Failed to load config from {config_path}: {e}")
        raise


def test_system_status(client: OPNsenseClient) -> None:
    """Test system status functionality."""
    logger.info("Testing system status...")
    try:
        status = client.get_system_status()
        logger.info("System status retrieved successfully")
        logger.info(f"Response keys: {list(status.keys())}")

        # Check for common status fields
        if "cpu" in status:
            logger.info(f"CPU usage: {status['cpu']}")
        if "memory" in status:
            logger.info(f"Memory info: {status['memory']}")
        if "versions" in status:
            logger.info("Version info available")

    except Exception as e:
        logger.error(f"System status test failed: {e}")
        raise


def test_arp_table(client: OPNsenseClient) -> None:
    """Test ARP table functionality."""
    logger.info("Testing ARP table...")
    try:
        arp_data = client.get_arp_table()
        logger.info("ARP table retrieved successfully")
        logger.info(f"Response keys: {list(arp_data.keys())}")

        # Check for entries
        if "entries" in arp_data:
            entries = arp_data["entries"]
            logger.info(f"Found {len(entries)} ARP entries")
            if entries:
                logger.info(f"Sample entry: {entries[0]}")
        elif "arp" in arp_data:
            entries = arp_data["arp"]
            logger.info(f"Found {len(entries)} ARP entries")

    except Exception as e:
        logger.error(f"ARP table test failed: {e}")
        raise


def main() -> None:
    """Main entry point for the standalone tester."""
    parser = argparse.ArgumentParser(description="Test OPNsense API functionality")
    parser.add_argument(
        "--config",
        type=str,
        default="vars/key.yaml",
        help="Path to config file",
    )
    parser.add_argument(
        "test_type",
        choices=["system", "arp"],
        help="Type of test to run",
    )

    args = parser.parse_args()

    # Handle config path
    if not args.config.startswith("/"):
        config_path = Path(__file__).parent / args.config
    else:
        config_path = Path(args.config)

    if not config_path.exists():
        logger.error(f"Config file not found: {config_path}")
        sys.exit(1)

    try:
        # Load configuration and create client
        config = load_config(str(config_path))
        client = OPNsenseClient(config)

        # Run the requested test
        if args.test_type == "system":
            test_system_status(client)
        elif args.test_type == "arp":
            test_arp_table(client)

        logger.info("Test completed successfully!")

    except Exception as e:
        logger.error(f"Test failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
