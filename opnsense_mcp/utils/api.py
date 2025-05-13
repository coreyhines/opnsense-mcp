#!/usr/bin/env python3

import ssl
import requests
import time
from typing import Dict, Any
from pyopnsense import diagnostics
from urllib3.exceptions import InsecureRequestWarning
import logging
from functools import wraps

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
logger = logging.getLogger(__name__)

# API endpoint categories
ENDPOINTS = {
    "system": {
        "status": "/core/system/status",
        "health": "/api/diagnostics/system/health",
        "information": "/api/diagnostics/system/system_information",
    },
    "interface": {
        "get_interfaces": "/api/diagnostics/interface/get_interface_names",
        "get_configuration": "/api/diagnostics/interface/get_interface_config",
        "get_statistics": "/api/diagnostics/interface/get_interface_statistics",
    },
    "firewall": {
        "get_rules": "/api/firewall/filter/get_rule",
        "search_rules": "/api/firewall/filter/search_rule",
        "add_rule": "/api/firewall/filter/add_rule",
        "del_rule": "/api/firewall/filter/del_rule",
        "set_rule": "/api/firewall/filter/set_rule",
        "toggle_rule": "/api/firewall/filter/toggle_rule",
    },
    "diagnostics": {
        "arp": "/api/diagnostics/interface/get_arp",
        "ndp": "/api/diagnostics/interface/get_ndp",
        "pf_states": "/api/diagnostics/firewall/pf_states",
        "pf_stats": "/api/diagnostics/firewall/pf_statistics",
    },
}


def retry(max_attempts=3, delay=1, backoff=2):
    """Retry decorator with exponential backoff for API methods"""

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            attempts = 0
            current_delay = delay
            last_error = None

            while attempts < max_attempts:
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    attempts += 1
                    last_error = e
                    if attempts == max_attempts:
                        logger.error(f"Failed after {max_attempts} attempts: {str(e)}")
                        raise
                    logger.warning(
                        f"Attempt {attempts} failed, retrying in {current_delay}s: {str(e)}"
                    )
                    time.sleep(current_delay)
                    current_delay *= backoff

            # Should not reach here, but just in case
            raise RuntimeError(f"All {max_attempts} attempts failed: {last_error}")

        return wrapper

    return decorator


class APIError(Exception):
    """Base exception for OPNsense API errors"""

    pass


class ConnectionError(APIError):
    """Raised when connection to OPNsense fails"""

    pass


class AuthenticationError(APIError):
    """Raised when authentication fails"""

    pass


class RequestError(APIError):
    """Raised when request fails"""

    pass


class ResponseError(APIError):
    """Raised when response parsing fails"""

    pass


class OPNsenseClient:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.setup_ssl()
        self.base_url = f"https://{self.config['firewall_host']}"
        self.api_base_url = f"{self.base_url}/api"

        # Initialize clients using pyopnsense library
        self.diag_client = diagnostics.InterfaceClient(
            self.config["api_key"],
            self.config["api_secret"],
            self.api_base_url,
            verify_cert=False,
        )

        # Set up basic auth headers
        self.headers = {"Authorization": f"Basic {self._get_basic_auth()}"}

        logger.info("Successfully initialized OPNsense clients")

    def _get_basic_auth(self) -> str:
        """Create basic auth header from api key and secret"""
        import base64

        auth_str = f"{self.config['api_key']}:{self.config['api_secret']}"
        return base64.b64encode(auth_str.encode()).decode()

    def setup_ssl(self):
        """Configure SSL context for API calls"""
        _create_unverified_https_context = ssl._create_unverified_context
        ssl._create_default_https_context = _create_unverified_https_context

    @retry(max_attempts=3)
    async def _make_request(
        self, method: str, endpoint: str, **kwargs
    ) -> Dict[str, Any]:
        """Make a request to the OPNsense API"""
        try:
            # Add the /api prefix if it's not already in the endpoint
            if not endpoint.startswith("/api") and not endpoint.startswith("/core"):
                endpoint = f"/api{endpoint}"

            url = f"{self.base_url}{endpoint}"
            kwargs["headers"] = {**kwargs.get("headers", {}), **self.headers}
            kwargs["verify"] = False

            logger.debug(f"Making {method} request to {url}")
            response = requests.request(method, url, **kwargs)

            # Check for API errors first (status code 200 but error in JSON)
            if response.status_code == 200:
                try:
                    json_data = response.json()
                    # OPNsense sometimes returns errors in JSON with status 200
                    if (
                        isinstance(json_data, dict)
                        and json_data.get("result") == "failed"
                    ):
                        error_msg = json_data.get("message", "Unknown API error")
                        logger.error(f"API returned error: {error_msg}")
                        raise RequestError(f"API error: {error_msg}")
                    return json_data
                except ValueError as e:
                    # Could not parse JSON
                    raise ResponseError(f"Invalid JSON response: {str(e)}")

            # Handle HTTP errors
            response.raise_for_status()

            # If we get here without a JSON response, try to parse again
            try:
                return response.json()
            except ValueError as e:
                raise ResponseError(f"Invalid JSON response: {str(e)}")

        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection to OPNsense failed: {str(e)}")
            raise ConnectionError(f"Connection failed: {str(e)}")
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error: {str(e)}")
            raise RequestError(f"HTTP error: {str(e)}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            raise RequestError(f"Request failed: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error in API request: {str(e)}")
            raise

    async def get_arp_table(self):
        """Get ARP table from OPNsense"""
        return self.diag_client.get_arp()

    async def get_ndp_table(self):
        """Get NDP table from OPNsense"""
        return self.diag_client.get_ndp()

    async def get_firewall_rules(self):
        """Get firewall rules from OPNsense"""
        try:
            logger.debug("Fetching firewall rules...")
            data = await self._make_request("GET", ENDPOINTS["firewall"]["get_rules"])

            rules = []
            if not isinstance(data, dict):
                raise ValueError("Unexpected response format from firewall API")

            # Extract rules from response
            for rule_id, rule_data in data.get("rows", {}).items():
                try:
                    rule_info = {
                        "sequence": int(rule_data.get("sequence", 0)),
                        "description": rule_data.get("description", ""),
                        "interface": rule_data.get("interface", ""),
                        "protocol": rule_data.get("protocol", "any"),
                        "source": {
                            "net": rule_data.get("source_net", "any"),
                            "port": rule_data.get("source_port", "any"),
                        },
                        "destination": {
                            "net": rule_data.get("destination_net", "any"),
                            "port": rule_data.get("destination_port", "any"),
                        },
                        "action": rule_data.get("action", "pass"),
                        "enabled": rule_data.get("enabled", "1") == "1",
                        "id": rule_id,
                        "gateway": rule_data.get("gateway", ""),
                        "direction": rule_data.get("direction", "in"),
                        "ipprotocol": rule_data.get("ipprotocol", "inet"),
                    }
                    rules.append(rule_info)
                except (KeyError, ValueError) as e:
                    logger.warning(f"Error processing rule {rule_id}: {str(e)}")
                    continue

            # Sort rules by sequence number
            rules.sort(key=lambda x: x["sequence"])
            logger.debug(f"Successfully retrieved {len(rules)} firewall rules")
            return rules

        except (KeyError, ValueError, AttributeError) as e:
            logger.error(f"Failed to parse firewall rules data: {str(e)}")
            raise ResponseError(f"Failed to parse firewall rules response: {str(e)}")
        except APIError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error in get_firewall_rules: {str(e)}")
            raise RequestError(f"Firewall rules error: {str(e)}")

    async def get_system_status(self):
        """Get system status from OPNsense"""
        try:
            logger.debug("Fetching system status information...")

            # Make direct API call to system status endpoint
            response = await self._make_request("GET", ENDPOINTS["system"]["status"])

            if not isinstance(response, dict) or "data" not in response:
                raise ValueError("Unexpected response format from status API")

            data = response.get("data", {})

            # Process and structure the data
            status_data = {
                "cpu_usage": 0.0,
                "memory_usage": 0.0,
                "filesystem_usage": {},
                "uptime": "",
                "versions": {"opnsense": "", "kernel": ""},
                "temperature": {},
                "interfaces": {},
                "services": [],
            }

            # Extract CPU usage
            if "cpu" in data:
                cpu_info = data["cpu"]
                if isinstance(cpu_info, dict) and "used" in cpu_info:
                    status_data["cpu_usage"] = float(cpu_info["used"].rstrip("%"))

            # Extract memory usage
            if "memory" in data:
                mem_info = data["memory"]
                if isinstance(mem_info, dict) and "used" in mem_info:
                    status_data["memory_usage"] = float(mem_info["used"].rstrip("%"))

            # Extract filesystem usage
            if "filesystems" in data:
                for fs in data["filesystems"]:
                    if isinstance(fs, dict):
                        mount = fs.get("mountpoint", "")
                        used = fs.get("used_percent", "0").rstrip("%")
                        status_data["filesystem_usage"][mount] = float(used)

            # Extract version information
            status_data["uptime"] = data.get("uptime", "")
            status_data["versions"]["opnsense"] = data.get("version", "")
            status_data["versions"]["kernel"] = data.get("kernel", "")

            # Try to fetch additional system information if available
            try:
                sys_info = await self._make_request(
                    "GET", ENDPOINTS["system"]["information"]
                )
                if isinstance(sys_info, dict):
                    # Extract temperature data if available
                    if "temperature" in sys_info:
                        for sensor in sys_info.get("temperature", []):
                            if (
                                isinstance(sensor, dict)
                                and "device" in sensor
                                and "temperature" in sensor
                            ):
                                status_data["temperature"][sensor["device"]] = sensor[
                                    "temperature"
                                ]

                    # Extract any additional system information
                    if "product" in sys_info:
                        status_data["versions"]["product"] = sys_info["product"]
            except Exception as e:
                logger.warning(
                    f"Could not fetch additional system information: {str(e)}"
                )

            logger.debug(f"Successfully retrieved system status: {status_data}")
            return status_data

        except ValueError as e:
            logger.error(f"Failed to parse system status data: {str(e)}")
            raise ResponseError(f"Failed to parse system status response: {str(e)}")
        except APIError:
            raise
        except Exception as e:
            logger.error(f"Failed to get system status: {str(e)}")
            raise RequestError(f"Failed to get system status: {str(e)}")

    async def get_interfaces(self):
        """Get all interfaces from OPNsense using diagnostics interface"""
        try:
            # We'll use the existing diagnostics client to get interface information
            if not hasattr(self, "_diag_client"):
                from pyopnsense import diagnostics

                self._diag_client = diagnostics.InterfaceClient(
                    self.config["api_key"],
                    self.config["api_secret"],
                    self.base_url,
                    verify_cert=False,
                )

            # Get both ARP and NDP tables to extract interface information
            interfaces = []
            arp_table = self._diag_client.get_arp()
            ndp_table = self._diag_client.get_ndp()

            # Build interface list from ARP and NDP data
            seen_interfaces = set()
            for entry in arp_table + ndp_table:
                if "intf" in entry and entry["intf"] not in seen_interfaces:
                    interfaces.append(
                        {
                            "name": entry["intf"],
                            "status": "active",  # We know it's active if it has ARP/NDP entries
                            "addresses": [],
                        }
                    )
                    seen_interfaces.add(entry["intf"])

            return interfaces

        except Exception as e:
            raise RuntimeError(f"Failed to get interfaces: {str(e)}")

    async def get_interface(self, name: str):
        """Get specific interface configuration"""
        interfaces = await self.get_interfaces()
        return next((iface for iface in interfaces if iface["name"] == name), None)

    # New methods for firewall rule management
    async def add_firewall_rule(self, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a new firewall rule"""
        try:
            logger.debug(f"Creating firewall rule: {rule_data}")
            response = await self._make_request(
                "POST",
                ENDPOINTS["firewall"]["add_rule"],
                json={"rule": rule_data},
            )

            if not isinstance(response, dict) or "uuid" not in response:
                raise ResponseError(
                    "Failed to create firewall rule, invalid response format"
                )

            # Get the full rule details
            rule_uuid = response.get("uuid")
            logger.info(f"Successfully created firewall rule with UUID: {rule_uuid}")

            return {"uuid": rule_uuid, "result": "success"}

        except APIError:
            raise
        except Exception as e:
            logger.error(f"Failed to add firewall rule: {str(e)}")
            raise RequestError(f"Failed to add firewall rule: {str(e)}")

    async def update_firewall_rule(
        self, uuid: str, rule_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update an existing firewall rule"""
        try:
            logger.debug(f"Updating firewall rule {uuid} with data: {rule_data}")
            response = await self._make_request(
                "POST",
                f"{ENDPOINTS['firewall']['set_rule']}/{uuid}",
                json={"rule": rule_data},
            )

            if response.get("result") != "saved":
                raise ResponseError(
                    f"Failed to update firewall rule: {response.get('message', 'Unknown error')}"
                )

            logger.info(f"Successfully updated firewall rule {uuid}")
            return {"uuid": uuid, "result": "success"}

        except APIError:
            raise
        except Exception as e:
            logger.error(f"Failed to update firewall rule: {str(e)}")
            raise RequestError(f"Failed to update firewall rule: {str(e)}")

    async def delete_firewall_rule(self, uuid: str) -> Dict[str, Any]:
        """Delete a firewall rule"""
        try:
            logger.debug(f"Deleting firewall rule {uuid}")
            response = await self._make_request(
                "POST", f"{ENDPOINTS['firewall']['del_rule']}/{uuid}"
            )

            if not isinstance(response, dict) or response.get("result") != "deleted":
                raise ResponseError(
                    f"Failed to delete firewall rule: {response.get('message', 'Unknown error')}"
                )

            logger.info(f"Successfully deleted firewall rule {uuid}")
            return {"result": "success"}

        except APIError:
            raise
        except Exception as e:
            logger.error(f"Failed to delete firewall rule: {str(e)}")
            raise RequestError(f"Failed to delete firewall rule: {str(e)}")

    async def toggle_firewall_rule(self, uuid: str, enabled: bool) -> Dict[str, Any]:
        """Enable or disable a firewall rule"""
        try:
            status = "1" if enabled else "0"
            logger.debug(f"Setting firewall rule {uuid} enabled status to {enabled}")
            response = await self._make_request(
                "POST",
                f"{ENDPOINTS['firewall']['toggle_rule']}/{uuid}/{status}",
            )

            if not isinstance(response, dict) or response.get("result") != "ok":
                raise ResponseError(
                    f"Failed to toggle firewall rule: {response.get('message', 'Unknown error')}"
                )

            logger.info(
                f"Successfully {'enabled' if enabled else 'disabled'} firewall rule {uuid}"
            )
            return {"uuid": uuid, "enabled": enabled, "result": "success"}

        except APIError:
            raise
        except Exception as e:
            logger.error(f"Failed to toggle firewall rule: {str(e)}")
            raise RequestError(f"Failed to toggle firewall rule: {str(e)}")

    async def apply_firewall_changes(self) -> Dict[str, Any]:
        """Apply firewall changes and create a rollback point"""
        try:
            # Create a savepoint first
            logger.debug("Creating firewall savepoint")
            savepoint_resp = await self._make_request(
                "POST", "/api/firewall/filter/savepoint"
            )

            if "revision" not in savepoint_resp:
                raise ResponseError("Failed to create firewall savepoint")

            revision = savepoint_resp["revision"]

            # Apply the changes
            logger.debug(f"Applying firewall changes with revision: {revision}")
            apply_resp = await self._make_request(
                "POST", f"/api/firewall/filter/apply/{revision}"
            )

            if apply_resp.get("status") != "ok":
                raise ResponseError(
                    f"Failed to apply firewall changes: {apply_resp.get('message', 'Unknown error')}"
                )

            logger.info("Successfully applied firewall changes")
            return {"revision": revision, "result": "success"}

        except APIError:
            raise
        except Exception as e:
            logger.error(f"Failed to apply firewall changes: {str(e)}")
            raise RequestError(f"Failed to apply firewall changes: {str(e)}")

    async def cancel_firewall_rollback(self, revision: str) -> Dict[str, Any]:
        """Cancel a pending firewall rollback"""
        try:
            logger.debug(f"Canceling firewall rollback for revision: {revision}")
            response = await self._make_request(
                "POST", f"/api/firewall/filter/cancel_rollback/{revision}"
            )

            if response.get("status") != "ok":
                raise ResponseError(
                    f"Failed to cancel rollback: {response.get('message', 'Unknown error')}"
                )

            logger.info(f"Successfully canceled rollback for revision: {revision}")
            return {"result": "success"}

        except APIError:
            raise
        except Exception as e:
            logger.error(f"Failed to cancel rollback: {str(e)}")
            raise RequestError(f"Failed to cancel rollback: {str(e)}")

    async def search_arp_table(self, query: str) -> list[dict]:
        """Search ARP table for a specific IP, MAC, or hostname using the OPNsense API endpoint."""
        endpoint = "/api/diagnostics/interface/search_arp"
        params = {"search": query}
        response = await self._make_request("GET", endpoint, params=params)
        # The response format may vary; adapt as needed
        return response.get("data", []) if isinstance(response, dict) else []

    async def search_ndp_table(self, query: str) -> list[dict]:
        """Search NDP table for a specific IPv6, MAC, or hostname using the OPNsense API endpoint."""
        endpoint = "/api/diagnostics/interface/search_ndp"
        params = {"search": query}
        response = await self._make_request("GET", endpoint, params=params)
        return response.get("data", []) if isinstance(response, dict) else []
