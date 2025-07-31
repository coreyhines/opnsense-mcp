#!/usr/bin/env python3
"""OPNsense API client for managing firewall operations and diagnostics."""

import base64
import logging
import os
import ssl
import time
from collections.abc import Callable
from functools import wraps
from typing import Any, ParamSpec, TypeVar

import requests
from pyopnsense import diagnostics
from urllib3.exceptions import InsecureRequestWarning

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

# Define type variables for the retry decorator
P = ParamSpec("P")
T = TypeVar("T")


def retry(
    max_attempts: int = 3, delay: int = 1, backoff: int = 2
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """Retry decorator with exponential backoff for API methods."""

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        @wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
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
                        logger.exception(f"Failed after {max_attempts} attempts")
                        raise
                    logger.warning(
                        f"Attempt {attempts} failed, retrying in "
                        f"{current_delay}s: {e!s}",
                    )
                    time.sleep(current_delay)
                    current_delay *= backoff

            # Should not reach here, but just in case
            raise RuntimeError(f"All {max_attempts} attempts failed: {last_error}")

        return wrapper

    return decorator


class APIError(Exception):
    """Base exception for OPNsense API errors."""


class ConnectionError(APIError):
    """Raised when connection to OPNsense fails."""


class AuthenticationError(APIError):
    """Raised when authentication fails."""


class RequestError(APIError):
    """Raised when request fails."""


class ResponseError(APIError):
    """Raised when response parsing fails."""


class OPNsenseClient:
    """OPNsense API client for firewall management and diagnostics."""

    def __init__(self, config: dict[str, Any]) -> None:
        """
        Initialize the OPNsense API client.

        Args:
            config: Configuration dictionary containing API credentials and host info.

        """
        # Use env vars if not provided in config
        self.config = config.copy()
        self.config["api_key"] = self.config.get("api_key") or os.getenv(
            "OPNSENSE_API_KEY",
        )
        self.config["api_secret"] = self.config.get("api_secret") or os.getenv(
            "OPNSENSE_API_SECRET",
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
            f"Using endpoints: DHCPv4 leases: {self.dhcpv4_lease_endpoint}, "
            f"DHCPv6 leases: {self.dhcpv6_lease_endpoint}, "
            f"Firewall logs: {self.firewall_log_endpoint}",
        )

        logger.info("Successfully initialized OPNsense clients")

    def _get_basic_auth(self: "OPNsenseClient") -> str:
        """Create basic auth header from api key and secret."""
        auth_str = f"{self.config['api_key']}:{self.config['api_secret']}"
        return base64.b64encode(auth_str.encode()).decode()

    def setup_ssl(self: "OPNsenseClient") -> None:
        """Configure SSL context for API calls."""
        # We deliberately use unverified context since OPNsense often uses
        # self-signed certs
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
        ctx.verify_mode = ssl.CERT_NONE
        ssl.create_default_context = lambda: ctx

    def _raise_unexpected_response_format(self: "OPNsenseClient") -> None:
        """Raise error for unexpected response format."""
        raise TypeError("Unexpected response format from firewall API")

    def _raise_invalid_create_response(self: "OPNsenseClient") -> None:
        """Raise error for invalid create response format."""
        raise ResponseError("Failed to create firewall rule, invalid response format")

    def _raise_create_rule_failed(self: "OPNsenseClient", error_msg: str) -> None:
        """Raise error for failed rule creation."""
        raise ResponseError(f"Failed to create firewall rule: {error_msg}")

    def _raise_update_rule_failed(self: "OPNsenseClient", error_msg: str) -> None:
        """Raise error for failed rule update."""
        raise ResponseError(f"Failed to update firewall rule: {error_msg}")

    def _raise_delete_rule_failed(self: "OPNsenseClient", error_msg: str) -> None:
        """Raise error for failed rule deletion."""
        raise ResponseError(f"Failed to delete firewall rule: {error_msg}")

    def _raise_toggle_rule_failed(self: "OPNsenseClient", error_msg: str) -> None:
        """Raise error for failed rule toggle."""
        raise ResponseError(f"Failed to toggle firewall rule: {error_msg}")

    def _raise_apply_changes_failed(self: "OPNsenseClient", error_msg: str) -> None:
        """Raise error for failed firewall changes apply."""
        raise ResponseError(f"Failed to apply firewall changes: {error_msg}")

    def _raise_cancel_rollback_failed(self: "OPNsenseClient", error_msg: str) -> None:
        """Raise error for failed rollback cancellation."""
        raise ResponseError(f"Failed to cancel rollback: {error_msg}")

    def _raise_savepoint_failed(self: "OPNsenseClient") -> None:
        """Raise error for failed savepoint creation."""
        raise ResponseError("Failed to create firewall savepoint")

    @retry(max_attempts=3)
    async def _make_request(
        self,
        method: str,
        endpoint: str,
        **kwargs: str | dict[str, str] | list[str] | int | bool | None,
    ) -> dict[str, Any]:
        """Make a request to the OPNsense API."""
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
                except ValueError as e:
                    # Could not parse JSON
                    raise ResponseError(f"Invalid JSON response: {e!s}") from e
                else:
                    # OPNsense sometimes returns errors in JSON with status 200
                    if (
                        isinstance(json_data, dict)
                        and json_data.get("result") == "failed"
                    ):
                        error_msg = json_data.get("message", "Unknown API error")
                        logger.error(f"API returned error: {error_msg}")
                        raise RequestError(f"API error: {error_msg}")
                    return json_data

            # Handle HTTP errors
            response.raise_for_status()

            # If we get here without a JSON response, try to parse again
            try:
                return response.json()
            except ValueError as e:
                raise ResponseError(f"Invalid JSON response: {e!s}") from e

        except requests.exceptions.ConnectionError as e:
            logger.exception("Connection to OPNsense failed")
            raise ConnectionError(f"Connection failed: {e!s}") from e
        except requests.exceptions.HTTPError as e:
            logger.exception("HTTP error")
            raise RequestError(f"HTTP error: {e!s}") from e
        except requests.exceptions.RequestException as e:
            logger.exception("Request failed")
            raise RequestError(f"Request failed: {e!s}") from e
        except Exception:
            logger.exception("Unexpected error in API request")
            raise

    async def get_arp_table(
        self: "OPNsenseClient",
    ) -> dict[str, Any] | list[dict[str, Any]]:
        """Get ARP table from OPNsense."""
        return self.diag_client.get_arp()

    async def get_ndp_table(
        self: "OPNsenseClient",
    ) -> dict[str, Any] | list[dict[str, Any]]:
        """Get NDP table from OPNsense."""
        return self.diag_client.get_ndp()

    async def get_firewall_rules(self: "OPNsenseClient") -> list[dict[str, Any]]:
        """Get firewall rules from OPNsense."""
        try:
            logger.debug("Fetching firewall rules...")
            # Use the searchRule endpoint as per OPNsense API docs
            # This should be a POST request with JSON body, not GET with params
            data = await self._make_request(
                "POST",
                "/api/firewall/filter/searchRule",
                json={"current": 1, "rowCount": 100},
            )

            if not isinstance(data, dict):
                self._raise_unexpected_response_format()
        except Exception as e:
            logger.exception("Failed to get firewall rules")
            raise RequestError(f"Firewall rules error: {e!s}") from e
        else:
            rules = list(data.get("rows", []))
            logger.debug(
                "Successfully retrieved %d firewall rules",
                len(rules),
            )
            return rules

    async def get_system_status(self: "OPNsenseClient") -> dict[str, Any]:
        """Get system version and info from OPNsense."""
        try:
            logger.debug(
                "Fetching system information from system_information endpoint..."
            )
            response = await self._make_request(
                "GET", "/api/diagnostics/system/system_information"
            )
            name = response.get("name", "")
            versions = response.get("versions", [])
            opnsense_version = ""
            kernel_version = ""
            for v in versions:
                if v.startswith("OPNsense"):
                    opnsense_version = v
                elif v.startswith("FreeBSD"):
                    kernel_version = v
        except Exception as e:
            logger.exception("Failed to get system status")
            return {
                "error": f"Failed to get system status: {e!s}",
                "status": "error",
            }
        else:
            return {
                "hostname": name,
                "versions": {
                    "opnsense": opnsense_version,
                    "kernel": kernel_version,
                },
                "status": "success",
            }

    async def get_interfaces(self: "OPNsenseClient") -> list[dict[str, Any]]:
        """Get all interfaces from OPNsense using diagnostics interface."""
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
                            # We know it's active if it has ARP/NDP entries
                            "status": "active",
                            "addresses": [],
                        },
                    )
                    seen_interfaces.add(entry["intf"])

        except Exception as e:
            raise RuntimeError(f"Failed to get interfaces: {e!s}") from e
        else:
            return interfaces

    async def get_interface(self: "OPNsenseClient", name: str) -> dict[str, Any] | None:
        """Get specific interface configuration."""
        interfaces = await self.get_interfaces()
        return next((iface for iface in interfaces if iface["name"] == name), None)

    async def get_firewall_interface_list(self: "OPNsenseClient") -> dict[str, Any]:
        """
        Get available interface names for firewall rules.

        Args:
        ----
        self: OPNsenseClient instance.

        """
        try:
            logger.debug("Fetching firewall interface list...")
            response = await self._make_request(
                "GET",
                "/api/firewall/filter/get_interface_list",
            )

            if not isinstance(response, dict):
                logger.error("Unexpected response format from interface list API")
                return {}

            logger.debug(f"Successfully retrieved interface list: {response}")
        except Exception as e:
            logger.exception("Failed to get firewall interface list")
            raise RequestError(f"Failed to get interface list: {e!s}") from e
        else:
            return response

    # New methods for firewall rule management
    async def add_firewall_rule(
        self: "OPNsenseClient", rule_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Add a new firewall rule."""
        try:
            logger.debug(f"Creating firewall rule: {rule_data}")
            response = await self._make_request(
                "POST",
                ENDPOINTS["firewall"]["add_rule"],
                json=rule_data,  # Send rule data directly, not wrapped in "rule" key
            )

            if not isinstance(response, dict):
                self._raise_invalid_create_response()

            # Check for successful creation
            if response.get("result") != "saved" or "uuid" not in response:
                error_msg = response.get("message", "Unknown error")
                self._raise_create_rule_failed(error_msg)

            # Get the rule UUID
            rule_uuid = response.get("uuid")

        except APIError:
            raise
        except Exception as e:
            logger.exception("Failed to add firewall rule")
            raise RequestError(f"Failed to add firewall rule: {e!s}") from e
        else:
            logger.info(f"Successfully created firewall rule with UUID: {rule_uuid}")
            return {"uuid": rule_uuid, "result": "success"}

    async def update_firewall_rule(
        self: "OPNsenseClient", uuid: str, rule_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Update an existing firewall rule."""
        try:
            logger.debug(f"Updating firewall rule {uuid} with data: {rule_data}")
            response = await self._make_request(
                "POST",
                f"{ENDPOINTS['firewall']['set_rule']}/{uuid}",
                json={"rule": rule_data},
            )

            if response.get("result") != "saved":
                error_msg = response.get("message", "Unknown error")
                self._raise_update_rule_failed(error_msg)

        except APIError:
            raise
        except Exception as e:
            logger.exception("Failed to update firewall rule")
            raise RequestError(f"Failed to update firewall rule: {e!s}") from e
        else:
            logger.info(f"Successfully updated firewall rule {uuid}")
            return {"uuid": uuid, "result": "success"}

    async def delete_firewall_rule(self: "OPNsenseClient", uuid: str) -> dict[str, Any]:
        """Delete a firewall rule."""
        try:
            logger.debug(f"Deleting firewall rule {uuid}")
            response = await self._make_request(
                "POST",
                f"{ENDPOINTS['firewall']['del_rule']}/{uuid}",
            )

            if not isinstance(response, dict) or response.get("result") != "deleted":
                error_msg = response.get("message", "Unknown error")
                self._raise_delete_rule_failed(f"Delete failed: {error_msg}")

        except APIError:
            raise
        except Exception as e:
            logger.exception("Failed to delete firewall rule")
            raise RequestError(f"Failed to delete firewall rule: {e!s}") from e
        else:
            logger.info(f"Successfully deleted firewall rule {uuid}")
            return {"result": "success"}

    async def toggle_firewall_rule(
        self: "OPNsenseClient", uuid: str, enabled: bool
    ) -> dict[str, Any]:
        """Enable or disable a firewall rule."""
        try:
            status = "1" if enabled else "0"
            logger.debug(f"Setting firewall rule {uuid} enabled status to {enabled}")
            response = await self._make_request(
                "POST",
                f"{ENDPOINTS['firewall']['toggle_rule']}/{uuid}/{status}",
            )

            if not isinstance(response, dict) or response.get("result") != "ok":
                error_msg = response.get("message", "Unknown error")
                self._raise_toggle_rule_failed(f"Toggle failed: {error_msg}")

        except APIError:
            raise
        except Exception as e:
            logger.exception("Failed to toggle firewall rule")
            raise RequestError(f"Failed to toggle firewall rule: {e!s}") from e
        else:
            logger.info(
                f"Set firewall rule {uuid} enabled={enabled}",
            )
            return {
                "uuid": uuid,
                "enabled": enabled,
                "result": "success",
            }

    async def apply_firewall_changes(self: "OPNsenseClient") -> dict[str, Any]:
        """Apply firewall changes and create a rollback point."""
        try:
            # Create a savepoint first
            logger.debug("Creating firewall savepoint")
            savepoint_resp = await self._make_request(
                "POST",
                "/api/firewall/filter/savepoint",
            )

            if "revision" not in savepoint_resp:
                self._raise_savepoint_failed()

            revision = savepoint_resp["revision"]

            # Apply the changes
            logger.debug(
                f"Applying firewall changes with revision: {revision}",
            )
            apply_resp = await self._make_request(
                "POST",
                f"/api/firewall/filter/apply/{revision}",
            )

            # Handle different response formats for apply operation
            status = apply_resp.get("status", "").strip().lower()
            if status not in ("ok", "success"):
                error_msg = apply_resp.get(
                    "message", f"Unknown error (status: {status})"
                )
                self._raise_apply_changes_failed(error_msg)
        except APIError:
            raise
        except Exception as e:
            logger.exception("Failed to apply firewall changes")
            raise RequestError(f"Failed to apply firewall changes: {e!s}") from e
        else:
            logger.info("Successfully applied firewall changes")
            return {
                "revision": revision,
                "result": "success",
            }

    async def cancel_firewall_rollback(
        self: "OPNsenseClient", revision: str
    ) -> dict[str, Any]:
        """Cancel a pending firewall rollback."""
        try:
            logger.debug(
                f"Canceling firewall rollback for revision: {revision}",
            )
            response = await self._make_request(
                "POST",
                f"/api/firewall/filter/cancelRollback/{revision}",
            )

            if response.get("status") != "ok":
                error_msg = response.get("message", "Unknown error")
                self._raise_cancel_rollback_failed(error_msg)
        except APIError:
            raise
        except Exception as e:
            logger.exception("Failed to cancel rollback")
            raise RequestError(f"Failed to cancel rollback: {e!s}") from e
        else:
            logger.info(
                f"Successfully canceled rollback for revision: {revision}",
            )
            return {"result": "success"}

    async def search_arp_table(self: "OPNsenseClient", query: str) -> list[dict]:
        """
        Search ARP table for IP, MAC, or hostname.

        Uses the OPNsense API. If query is '*', returns full table.
        """
        query = query.strip()
        try:
            if query == "*" or not query:
                # Use canonical endpoint for full table
                return await self._get_arp_table()

            # Use search endpoint for specific queries
            endpoint = "/api/diagnostics/interface/search_arp"
            params = {"search": query}
            response = await self._make_request("GET", endpoint, params=params)
        except Exception:
            logger.exception("Failed to search ARP table")
            return []
        else:
            return response.get("data", []) if isinstance(response, dict) else []

    async def search_ndp_table(self: "OPNsenseClient", query: str) -> list[dict]:
        """
        Search NDP table for IPv6, MAC, or hostname.

        Uses the OPNsense API. If query is '*', returns full table.
        """
        query = query.strip()
        try:
            if query == "*" or not query:
                # Use canonical endpoint for full table
                return await self._get_ndp_table()

            # Use search endpoint for specific queries
            endpoint = "/api/diagnostics/interface/search_ndp"
            params = {"search": query}
            response = await self._make_request("GET", endpoint, params=params)
        except Exception:
            logger.exception("Failed to search NDP table")
            return []
        else:
            return response.get("data", []) if isinstance(response, dict) else []

    def _detect_endpoint(
        self: "OPNsenseClient", name: str, endpoints: list[str | None]
    ) -> str | None:
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
                if resp.status_code == 401:
                    logger.warning(
                        f"{name} endpoint {ep} unauthorized (check API key/secret)",
                    )
                elif resp.status_code == 404:
                    logger.debug(f"{name} endpoint {ep} not found (404)")
            except Exception as e:
                logger.warning(f"Error probing {name} endpoint {ep}: {e}")
        logger.warning(
            f"No working endpoint found for {name}, will always return empty list.",
        )
        return None

    async def get_dhcpv4_leases(self: "OPNsenseClient") -> list[dict[str, Any]]:
        """Get DHCPv4 lease table from OPNsense (official endpoint)."""
        try:
            response = await self._make_request("GET", self.dhcpv4_lease_endpoint)
            # Try to extract leases from dict or list
            if isinstance(response, dict):
                if "leases" in response:
                    return response["leases"]
                if "rows" in response:
                    return response["rows"]
            parsed = response if isinstance(response, list) else []
        except Exception:
            logger.exception("Failed to get DHCPv4 leases")
            return []
        else:
            return parsed

    async def get_dhcpv6_leases(self: "OPNsenseClient") -> list[dict[str, Any]]:
        """Get DHCPv6 lease table from OPNsense (official endpoint)."""
        try:
            response = await self._make_request("GET", self.dhcpv6_lease_endpoint)
            # Try to extract leases from dict or list
            if isinstance(response, dict):
                if "leases" in response:
                    return response["leases"]
                if "rows" in response:
                    return response["rows"]
            parsed = response if isinstance(response, list) else []
        except Exception:
            logger.exception("Failed to get DHCPv6 leases")
            return []
        else:
            return parsed

    async def get_firewall_logs(
        self: "OPNsenseClient", limit: int = 500
    ) -> list[dict[str, Any]]:
        """
        Get firewall logs from OPNsense (auto-detect endpoint, robust to 404s).

        Args:
        ----
            limit: Maximum number of log entries to return. Defaults to 500.

        Returns:
        -------
            List of log entries as dicts.

        """
        endpoints = [
            os.getenv("OPNSENSE_FIREWALL_LOG_ENDPOINT"),
            "/api/diagnostics/firewall/log",
            "/api/firewall/log",
            "/api/diagnostics/firewall/pf_log",
        ]
        tried = []
        for ep in endpoints:
            if not ep:
                continue
            try:
                params = {"limit": limit} if limit else {}
                response = await self._make_request("GET", ep, params=params)
                logger.debug(f"Raw firewall log response type: {type(response)}")
                if isinstance(response, list):
                    logger.debug(
                        f"Raw firewall log response (list): {response[:2]} ..."
                    )
                    return response[:limit] if limit else response
                if isinstance(response, dict):
                    for key in ("logs", "data", "rows"):
                        if key in response and isinstance(response[key], list):
                            logger.debug(
                                f"Raw firewall log response (dict, key={key}): "
                                f"{response[key][:2]} ..."
                            )
                            return response[key][:limit] if limit else response[key]
                logger.warning(f"Unexpected firewall log response format: {response}")
            except requests.exceptions.HTTPError as e:
                if (
                    hasattr(e, "response")
                    and getattr(e.response, "status_code", None) == 404
                ):
                    logger.warning(f"Firewall log endpoint 404: {ep}")
                    tried.append(ep)
                    continue
                logger.exception(f"HTTP error on endpoint {ep}")
                tried.append(ep)
                continue
            except Exception as e:
                logger.warning(f"Error trying firewall log endpoint {ep}: {e}")
                tried.append(ep)
                continue
        logger.error(f"All firewall log endpoints failed or returned 404: {tried}")
        return []

    async def search_firewall_logs(
        self: "OPNsenseClient", ip: str, row_count: int = 50
    ) -> list[dict]:
        """Search firewall logs for a specific IP address using the correct endpoint."""
        logs = await self.get_firewall_logs()
        # Filter logs for the IP address in src or dst
        filtered = [
            log for log in logs if ip in log.get("src", "") or ip in log.get("dst", "")
        ]
        return filtered[:row_count]

    async def resolve_host_info(self: "OPNsenseClient", query: str) -> dict:
        """Recursively resolve all available info for a hostname, IP, or MAC."""
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
        def match_lease(lease: dict[str, Any]) -> bool:
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

    async def get_lldp_table(self: "OPNsenseClient") -> list[dict[str, str]]:
        """Get LLDP neighbor table from the LLDPd plugin endpoint and parse it."""
        try:
            response = await self._make_request("GET", "/api/lldpd/service/neighbor")
            text = response.get("response", "")
            neighbors = []
            current = {}
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("Interface:"):
                    if current:
                        neighbors.append(current)
                        current = {}
                    current["intf"] = line.split(":", 1)[1].split(",")[0].strip()
                elif line.startswith("ChassisID:"):
                    current["chassis_id"] = line.split(":", 1)[1].strip()
                elif line.startswith("SysName:"):
                    current["system_name"] = line.split(":", 1)[1].strip()
                elif line.startswith("SysDescr:"):
                    current["system_description"] = line.split(":", 1)[1].strip()
                elif line.startswith("MgmtIP:"):
                    current["management_address"] = line.split(":", 1)[1].strip()
                elif line.startswith("PortID:"):
                    current["port_id"] = line.split(":", 1)[1].strip()
                elif line.startswith("PortDescr:"):
                    current["port_description"] = line.split(":", 1)[1].strip()
                elif line.startswith("Capability:"):
                    cap = line.split(":", 1)[1].strip()
                    if "capabilities" in current:
                        current["capabilities"] += ", " + cap
                    else:
                        current["capabilities"] = cap
            if current:
                neighbors.append(current)
        except Exception:
            logger.exception("Failed to get LLDP table")
            return []
        else:
            return neighbors
