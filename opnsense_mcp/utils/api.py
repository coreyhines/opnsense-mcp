#!/usr/bin/env python3

import ssl
import requests
import time
from typing import Dict, Any
from pyopnsense import diagnostics
from urllib3.exceptions import InsecureRequestWarning
import logging
from functools import wraps
import os

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
        "get_rules": "/api/firewall/filter/getRule",
        "search_rules": "/api/firewall/filter/searchRule",
        "add_rule": "/api/firewall/filter/addRule",
        "del_rule": "/api/firewall/filter/delRule",
        "set_rule": "/api/firewall/filter/setRule",
        "toggle_rule": "/api/firewall/filter/toggleRule",
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
        # Use env vars if not provided in config
        self.config = config.copy()
        self.config["api_key"] = self.config.get("api_key") or os.getenv(
            "OPNSENSE_API_KEY"
        )
        self.config["api_secret"] = self.config.get("api_secret") or os.getenv(
            "OPNSENSE_API_SECRET"
        )
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

        # Use official endpoints for DHCP leases
        self.dhcpv4_lease_endpoint = "/api/dhcpv4/leases/search_lease"
        self.dhcpv6_lease_endpoint = "/api/dhcpv6/leases/search_lease"
        self.firewall_log_endpoint = self._detect_endpoint(
            "Firewall logs",
            [
                os.getenv("OPNSENSE_FIREWALL_LOG_ENDPOINT"),
                "/api/diagnostics/firewall/log",
                "/api/firewall/log",
                "/api/diagnostics/firewall/pf_log",
            ],
        )
        logger.info(
            f"Using endpoints: DHCPv4 leases: {self.dhcpv4_lease_endpoint}, DHCPv6 leases: {self.dhcpv6_lease_endpoint}, Firewall logs: {self.firewall_log_endpoint}"
        )

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
            # Use the searchRule endpoint as per OPNsense API docs
            params = {"current": 1, "rowCount": 100}
            data = await self._make_request(
                "GET", "/api/firewall/filter/searchRule", params=params
            )

            rules = []
            if not isinstance(data, dict):
                raise ValueError("Unexpected response format from firewall API")

            for rule in data.get("rows", []):
                rules.append(rule)

            logger.debug(f"Successfully retrieved {len(rules)} firewall rules")
            return rules

        except Exception as e:
            logger.error(f"Failed to get firewall rules: {str(e)}")
            raise RequestError(f"Firewall rules error: {str(e)}")

    async def get_system_status(self):
        """Get system status from OPNsense with robust redirect and error handling"""
        try:
            logger.debug("Fetching system status information...")
            # Make direct API call to system status endpoint
            response = None
            try:
                response = await self._make_request(
                    "GET", ENDPOINTS["system"]["status"]
                )
            except ResponseError as e:
                # Check if this is a redirect or HTML error
                logger.warning(f"System status endpoint error: {e}")
                # Try to follow redirect manually if 302
                url = f"{self.base_url}{ENDPOINTS['system']['status']}"
                resp = requests.get(
                    url, headers=self.headers, verify=False, allow_redirects=True
                )
                if resp.status_code == 200:
                    content_type = resp.headers.get("Content-Type", "")
                    if "application/json" not in content_type:
                        logger.error(
                            "System status endpoint returned non-JSON (likely HTML). Endpoint may require session or is not available via API key."
                        )
                        return {
                            "cpu_usage": 0.0,
                            "memory_usage": 0.0,
                            "filesystem_usage": {},
                            "uptime": "",
                            "versions": {"opnsense": "", "kernel": ""},
                            "error": "System status endpoint returned HTML, not JSON. Check API permissions or use a session.",
                        }
                    try:
                        response = resp.json()
                    except Exception as e2:
                        logger.error(
                            f"System status endpoint returned invalid JSON: {e2}"
                        )
                        return {
                            "cpu_usage": 0.0,
                            "memory_usage": 0.0,
                            "filesystem_usage": {},
                            "uptime": "",
                            "versions": {"opnsense": "", "kernel": ""},
                            "error": f"System status endpoint returned invalid JSON: {e2}",
                        }
                else:
                    logger.error(
                        f"System status endpoint returned status {resp.status_code}"
                    )
                    return {
                        "cpu_usage": 0.0,
                        "memory_usage": 0.0,
                        "filesystem_usage": {},
                        "uptime": "",
                        "versions": {"opnsense": "", "kernel": ""},
                        "error": f"System status endpoint returned status {resp.status_code}",
                    }
            if not isinstance(response, dict) or "data" not in response:
                logger.error("Unexpected response format from status API")
                return {
                    "cpu_usage": 0.0,
                    "memory_usage": 0.0,
                    "filesystem_usage": {},
                    "uptime": "",
                    "versions": {"opnsense": "", "kernel": ""},
                    "error": "Unexpected response format from status API",
                }
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
        except Exception as e:
            logger.error(f"Failed to get system status: {str(e)}")
            return {
                "cpu_usage": 0.0,
                "memory_usage": 0.0,
                "filesystem_usage": {},
                "uptime": "",
                "versions": {"opnsense": "", "kernel": ""},
                "error": f"Failed to get system status: {str(e)}",
            }

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

            if not isinstance(response, dict):
                raise ResponseError(
                    "Failed to create firewall rule, invalid response format"
                )

            # Check for successful creation - OPNsense returns {"result":"saved","uuid":"..."}
            if response.get("result") != "saved" or "uuid" not in response:
                error_msg = response.get("message", "Unknown error")
                raise ResponseError(f"Failed to create firewall rule: {error_msg}")

            # Get the rule UUID
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
                "POST", f"/api/firewall/filter/cancelRollback/{revision}"
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
        """Search ARP table for a specific IP, MAC, or hostname using the OPNsense API endpoint. If query is '*', use get_arp endpoint for full table."""
        if query.strip() == '*' or not query.strip():
            # Use canonical endpoint for full table
            response = await self._make_request("GET", "/api/diagnostics/interface/get_arp")
            if isinstance(response, dict) and "rows" in response:
                return response["rows"]
            elif isinstance(response, list):
                return response
            else:
                return []
        else:
            endpoint = "/api/diagnostics/interface/search_arp"
            params = {"search": query}
            response = await self._make_request("GET", endpoint, params=params)
            return response.get("data", []) if isinstance(response, dict) else []

    async def search_ndp_table(self, query: str) -> list[dict]:
        """Search NDP table for a specific IPv6, MAC, or hostname using the OPNsense API endpoint. If query is '*', use get_ndp endpoint for full table."""
        if query.strip() == '*' or not query.strip():
            # Use canonical endpoint for full table
            response = await self._make_request("GET", "/api/diagnostics/interface/get_ndp")
            if isinstance(response, dict) and "rows" in response:
                return response["rows"]
            elif isinstance(response, list):
                return response
            else:
                return []
        else:
            endpoint = "/api/diagnostics/interface/search_ndp"
            params = {"search": query}
            response = await self._make_request("GET", endpoint, params=params)
            return response.get("data", []) if isinstance(response, dict) else []

    def _detect_endpoint(self, name, endpoints):
        for ep in endpoints:
            if not ep:
                continue
            try:
                url = f"{self.base_url}{ep}"
                logger.debug(f"Probing {name} endpoint: {url}")
                resp = requests.get(url, headers=self.headers, verify=False, timeout=5)
                if resp.status_code == 200:
                    logger.info(f"Using {name} endpoint: {ep}")
                    return ep
                elif resp.status_code == 401:
                    logger.warning(
                        f"{name} endpoint {ep} unauthorized (check API key/secret)"
                    )
                elif resp.status_code == 404:
                    logger.debug(f"{name} endpoint {ep} not found (404)")
            except Exception as e:
                logger.warning(f"Error probing {name} endpoint {ep}: {e}")
        logger.warning(
            f"No working endpoint found for {name}, will always return empty list."
        )
        return None

    async def get_dhcpv4_leases(self):
        """Get DHCPv4 lease table from OPNsense (official endpoint)"""
        try:
            response = await self._make_request("GET", self.dhcpv4_lease_endpoint)
            # Try to extract leases from dict or list
            if isinstance(response, dict):
                if "leases" in response:
                    return response["leases"]
                if "rows" in response:
                    return response["rows"]
            if isinstance(response, list):
                return response
            return []
        except Exception as e:
            logger.error(f"Failed to get DHCPv4 leases: {e}")
            return []

    async def get_dhcpv6_leases(self):
        """Get DHCPv6 lease table from OPNsense (official endpoint)"""
        try:
            response = await self._make_request("GET", self.dhcpv6_lease_endpoint)
            # Try to extract leases from dict or list
            if isinstance(response, dict):
                if "leases" in response:
                    return response["leases"]
                if "rows" in response:
                    return response["rows"]
            if isinstance(response, list):
                return response
            return []
        except Exception as e:
            logger.error(f"Failed to get DHCPv6 leases: {e}")
            return []

    async def get_firewall_logs(self, limit: int = 500):
        """Get firewall logs from OPNsense (auto-detect endpoint)

        Args:
            limit: Maximum number of log entries to return. Defaults to 500.

        Returns:
            List of log entries as strings
        """
        if not self.firewall_log_endpoint:
            logger.warning("No firewall log endpoint available, returning empty list.")
            return []
        try:
            params = {"limit": limit} if limit else {}
            response = await self._make_request(
                "GET", self.firewall_log_endpoint, params=params
            )
            # The response is usually a dict with a 'logs', 'data', or 'rows' key or a list
            if isinstance(response, dict):
                if "logs" in response:
                    return response["logs"][:limit] if limit else response["logs"]
                if "data" in response:
                    return response["data"][:limit] if limit else response["data"]
                if "rows" in response:
                    return response["rows"][:limit] if limit else response["rows"]
            # If the response is a list, return it directly
            elif isinstance(response, list):
                return response[:limit] if limit else response
            if isinstance(response, list):
                return response
            return []
        except Exception as e:
            logger.error(f"Failed to get firewall logs: {e}")
            return []

    async def search_firewall_logs(self, ip: str, row_count: int = 50) -> list[dict]:
        """
        Search firewall logs for a specific IP address using the correct endpoint.
        """
        logs = await self.get_firewall_logs()
        # Filter logs for the IP address in src or dst
        filtered = [
            log for log in logs if ip in log.get("src", "") or ip in log.get("dst", "")
        ]
        return filtered[:row_count]

    async def resolve_host_info(self, query: str) -> dict:
        """
        Recursively resolve all available info for a hostname, IP, or MAC.
        Returns a dict with keys: hostname, ip, mac, dhcpv4, dhcpv6, arp, ndp
        """
        # Normalize input
        query_lc = query.lower() if query else ""
        result = {
            "input": query,
            "hostname": None,
            "ip": None,
            "mac": None,
            "dhcpv4": None,
            "dhcpv6": None,
            "arp": None,
            "ndp": None,
        }

        # Step 1: Try ARP/NDP search
        arp_entries = await self.search_arp_table(query_lc)
        ndp_entries = await self.search_ndp_table(query_lc)
        if arp_entries:
            arp = arp_entries[0]
            result["arp"] = arp
            result["ip"] = arp.get("ip")
            result["mac"] = arp.get("mac")
            result["hostname"] = arp.get("hostname")
        if ndp_entries and not result["ip"]:
            ndp = ndp_entries[0]
            result["ndp"] = ndp
            result["ip"] = ndp.get("ip")
            result["mac"] = ndp.get("mac")
            result["hostname"] = ndp.get("hostname")

        # Step 2: Try DHCPv4/v6 search (by hostname, IP, or MAC)
        dhcpv4_leases = await self.get_dhcpv4_leases()
        dhcpv6_leases = await self.get_dhcpv6_leases()

        # Helper to match any field
        def match_lease(lease):
            return (
                query_lc in str(lease.get("hostname", "")).lower()
                or query_lc in str(lease.get("ip", "")).lower()
                or query_lc in str(lease.get("mac", "")).lower()
            )

        v4_matches = [lease for lease in dhcpv4_leases if match_lease(lease)]
        v6_matches = [lease for lease in dhcpv6_leases if match_lease(lease)]
        if v4_matches:
            lease = v4_matches[0]
            result["dhcpv4"] = lease
            if not result["ip"]:
                result["ip"] = lease.get("ip")
            if not result["mac"]:
                result["mac"] = lease.get("mac")
            if not result["hostname"]:
                result["hostname"] = lease.get("hostname")
        if v6_matches:
            lease = v6_matches[0]
            result["dhcpv6"] = lease
            if not result["ip"]:
                result["ip"] = lease.get("ip")
            if not result["mac"]:
                result["mac"] = lease.get("mac")
            if not result["hostname"]:
                result["hostname"] = lease.get("hostname")

        # Step 3: If still missing, try to infer from other fields
        # (e.g., if input is IP, look for matching MAC in ARP/DHCP, etc.)
        # Already handled above by matching all fields

        return result
