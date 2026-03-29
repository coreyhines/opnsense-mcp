#!/usr/bin/env python3
"""OPNsense API client for managing firewall operations and diagnostics."""

import asyncio
import base64
import ipaddress
import logging
import os
import re
import socket
import ssl
import threading
from typing import Any

import requests
from urllib3.exceptions import InsecureRequestWarning

from opnsense_mcp.utils.dhcp_provider import DHCPProvider, detect_dhcp_backend

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
logger = logging.getLogger(__name__)
_MAC_RE = re.compile(r"^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$", re.IGNORECASE)


def _reverse_name_matches_query(reverse_name: str, query: str) -> bool:
    """Return True when PTR reverse name confirms a hostname query."""
    q = query.lower().strip(".")
    n = reverse_name.lower().strip(".")
    if not q or not n:
        return False
    return n == q or n.startswith(f"{q}.") or n.split(".", 1)[0] == q


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
    "unbound": {
        "search": "/api/unbound/settings/searchHostOverride",
        "add": "/api/unbound/settings/addHostOverride",
        "set": "/api/unbound/settings/setHostOverride",
        "delete": "/api/unbound/settings/delHostOverride",
        "reconfigure": "/api/unbound/service/reconfigure",
    },
    "alias": {
        "search": "/api/firewall/alias/searchItem",
    },
    "routes": {
        "gateway_status": "/api/routes/gateway/status",
    },
}


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

        # Set up basic auth headers
        self.headers = {"Authorization": f"Basic {self._get_basic_auth()}"}

        # Persistent session — reuses TCP/TLS connections across calls
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.verify = False
        self._session_lock = threading.Lock()

        # DHCP provider is detected lazily on first DHCP operation.
        self._dhcp_provider: DHCPProvider | None = None
        self._dhcp_provider_lock = asyncio.Lock()

        # Store candidates; actual probe deferred to first get_firewall_logs call
        self._firewall_log_endpoint_candidates: list[str | None] = [
            os.getenv("OPNSENSE_FIREWALL_LOG_ENDPOINT"),
            "/api/diagnostics/firewall/log",
            "/api/firewall/log",
            "/api/diagnostics/firewall/pf_log",
        ]
        self.firewall_log_endpoint: str | None = None
        self._firewall_log_endpoint_detected: bool = False
        self._firewall_log_endpoint_lock = asyncio.Lock()

        logger.info("Successfully initialized OPNsense clients")

    async def _ensure_firewall_log_endpoint(self) -> None:
        """Detect and cache the working firewall log endpoint on first use."""
        if self._firewall_log_endpoint_detected:
            return
        async with self._firewall_log_endpoint_lock:
            # Double-check inside the lock (another coroutine may have completed detection)
            if self._firewall_log_endpoint_detected:
                return
            loop = asyncio.get_running_loop()
            self.firewall_log_endpoint = await loop.run_in_executor(
                None,
                lambda: self._detect_endpoint(
                    "Firewall logs", self._firewall_log_endpoint_candidates
                ),
            )
            self._firewall_log_endpoint_detected = True

    async def _ensure_dhcp_provider(self) -> None:
        """Detect and cache the DHCP backend provider on first use."""
        if self._dhcp_provider is not None:
            return
        async with self._dhcp_provider_lock:
            if self._dhcp_provider is not None:
                return
            self._dhcp_provider = await detect_dhcp_backend(self._make_request)

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

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        **kwargs: str | dict[str, str] | list[str] | int | bool | None,
    ) -> dict[str, Any]:
        """Make a non-blocking request to the OPNsense API."""
        if not endpoint.startswith("/api") and not endpoint.startswith("/core"):
            endpoint = f"/api{endpoint}"

        url = f"{self.base_url}{endpoint}"
        kwargs.setdefault("timeout", 5)  # Hard cap — never hang indefinitely

        def _do_request() -> dict[str, Any]:
            try:
                with self._session_lock:
                    response = self.session.request(method, url, **kwargs)

                if response.status_code == 200:
                    try:
                        json_data = response.json()
                    except ValueError as e:
                        raise ResponseError(f"Invalid JSON response: {e!s}") from e
                    if (
                        isinstance(json_data, dict)
                        and json_data.get("result") == "failed"
                    ):
                        error_msg = json_data.get("message", "Unknown API error")
                        raise RequestError(f"API error: {error_msg}")
                    return json_data

                response.raise_for_status()
                try:
                    return response.json()
                except ValueError as e:
                    raise ResponseError(f"Invalid JSON response: {e!s}") from e

            except requests.exceptions.ConnectionError as e:
                raise ConnectionError(f"Connection failed: {e!s}") from e
            except requests.exceptions.Timeout as e:
                raise RequestError(f"Request timed out: {e!s}") from e
            except requests.exceptions.HTTPError as e:
                raise RequestError(f"HTTP error: {e!s}") from e
            except requests.exceptions.RequestException as e:
                raise RequestError(f"Request failed: {e!s}") from e

        logger.debug(f"Making {method} request to {url}")
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _do_request)

    async def get_arp_table(self) -> list[dict[str, Any]]:
        """Get ARP table from OPNsense."""
        response = await self._make_request("GET", "/api/diagnostics/interface/get_arp")
        return response if isinstance(response, list) else []

    # Keep this alias — used by search_arp_table
    _get_arp_table = get_arp_table

    async def get_ndp_table(self) -> list[dict[str, Any]]:
        """Get NDP table from OPNsense."""
        response = await self._make_request("GET", "/api/diagnostics/interface/get_ndp")
        return response if isinstance(response, list) else []

    # Keep this alias — used by search_ndp_table
    _get_ndp_table = get_ndp_table

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
            # Get both ARP and NDP tables in parallel to extract interface information
            interfaces = []
            arp_table, ndp_table = await asyncio.gather(
                self.get_arp_table(),
                self.get_ndp_table(),
            )

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
            data = response.get("data", []) if isinstance(response, dict) else []
            if data:
                return data

            # Some OPNsense versions return empty for valid queries; fall back
            # to local filtering over the full table for reliability.
            full_table = await self._get_arp_table()
            query_lc = query.lower()
            is_ip_query = False
            try:
                ipaddress.ip_address(query_lc)
                is_ip_query = True
            except ValueError:
                is_ip_query = False
            is_mac_query = bool(_MAC_RE.match(query_lc))
            return [
                entry
                for entry in full_table
                if (
                    str(entry.get("ip", "")).lower() == query_lc
                    if is_ip_query
                    else query_lc in str(entry.get("ip", "")).lower()
                )
                or (
                    str(entry.get("mac", "")).lower().replace("-", ":")
                    == query_lc.replace("-", ":")
                    if is_mac_query
                    else query_lc in str(entry.get("mac", "")).lower()
                )
                or query_lc in str(entry.get("hostname", "")).lower()
            ]

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
            data = response.get("data", []) if isinstance(response, dict) else []
            if data:
                return data

            # Some OPNsense versions return empty for valid queries; fall back
            # to local filtering over the full table for reliability.
            full_table = await self._get_ndp_table()
            query_lc = query.lower()
            is_ip_query = False
            try:
                ipaddress.ip_address(query_lc)
                is_ip_query = True
            except ValueError:
                is_ip_query = False
            is_mac_query = bool(_MAC_RE.match(query_lc))
            return [
                entry
                for entry in full_table
                if (
                    str(entry.get("ip", "")).lower() == query_lc
                    if is_ip_query
                    else query_lc in str(entry.get("ip", "")).lower()
                )
                or (
                    str(entry.get("mac", "")).lower().replace("-", ":")
                    == query_lc.replace("-", ":")
                    if is_mac_query
                    else query_lc in str(entry.get("mac", "")).lower()
                )
                or query_lc in str(entry.get("hostname", "")).lower()
            ]

    def _detect_endpoint(
        self: "OPNsenseClient", name: str, endpoints: list[str | None]
    ) -> str | None:
        for ep in endpoints:
            if not ep:
                continue
            try:
                url = f"{self.base_url}{ep}"
                logger.debug(f"Probing {name} endpoint: {url}")
                with self._session_lock:
                    resp = self.session.get(url, timeout=5)
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

    def close(self) -> None:
        """Close the underlying HTTP session."""
        with self._session_lock:
            self.session.close()

    def __enter__(self) -> "OPNsenseClient":
        """Enter context manager scope."""
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        """Exit context manager scope and close resources."""
        self.close()

    async def get_dhcpv4_leases(self: "OPNsenseClient") -> list[dict[str, Any]]:
        """Get DHCPv4 lease table from OPNsense."""
        await self._ensure_dhcp_provider()
        assert self._dhcp_provider is not None
        return await self._dhcp_provider.get_v4_leases()

    async def get_dhcpv6_leases(self: "OPNsenseClient") -> list[dict[str, Any]]:
        """Get DHCPv6 lease table from OPNsense."""
        await self._ensure_dhcp_provider()
        assert self._dhcp_provider is not None
        return await self._dhcp_provider.get_v6_leases()

    async def search_dhcpv4_leases(self, query: str) -> list[dict[str, Any]]:
        """Search DHCPv4 leases server-side by hostname, IP, or MAC."""
        await self._ensure_dhcp_provider()
        assert self._dhcp_provider is not None
        return await self._dhcp_provider.search_v4_leases(query)

    async def search_dhcpv6_leases(self, query: str) -> list[dict[str, Any]]:
        """Search DHCPv6 leases server-side by hostname, IP, or MAC."""
        await self._ensure_dhcp_provider()
        assert self._dhcp_provider is not None
        return await self._dhcp_provider.search_v6_leases(query)

    async def delete_dhcpv4_lease(self, ip: str) -> dict[str, Any]:
        """Delete a DHCPv4 lease by IP address."""
        await self._ensure_dhcp_provider()
        assert self._dhcp_provider is not None
        return await self._dhcp_provider.delete_v4_lease(ip)

    async def delete_dhcpv6_lease(self, ip: str) -> dict[str, Any]:
        """Delete a DHCPv6 lease by IP address."""
        await self._ensure_dhcp_provider()
        assert self._dhcp_provider is not None
        return await self._dhcp_provider.delete_v6_lease(ip)

    async def get_firewall_logs(
        self: "OPNsenseClient", limit: int = 100
    ) -> list[dict[str, Any]]:
        """
        Get firewall logs from OPNsense using the pre-detected endpoint.

        Args:
        ----
            limit: Maximum number of log entries to return. Defaults to 100.

        Returns:
        -------
            List of log entries as dicts.

        """
        await self._ensure_firewall_log_endpoint()

        if not self.firewall_log_endpoint:
            logger.warning("No working firewall log endpoint available")
            return []

        try:
            params = {"limit": limit} if limit else {}
            response = await self._make_request(
                "GET", self.firewall_log_endpoint, params=params
            )
            if isinstance(response, list):
                return response[:limit] if limit else response
            if isinstance(response, dict):
                for key in ("logs", "data", "rows"):
                    if key in response and isinstance(response[key], list):
                        return response[key][:limit] if limit else response[key]
            logger.warning(f"Unexpected firewall log response format: {response}")
            return []
        except Exception as e:
            logger.warning(f"Error fetching firewall logs: {e}")
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
        """Resolve all available info for a hostname, IP, or MAC query."""
        # Normalize input
        query_lc = query.lower() if query else ""
        is_ip_query = False
        try:
            ipaddress.ip_address(query_lc)
            is_ip_query = True
        except ValueError:
            is_ip_query = False
        result = {
            "input": query,
            "hostname": None,
            "ip": None,
            "mac": None,
            "dhcpv4": None,
            "dhcpv6": None,
            "arp": None,
            "ndp": None,
            "dns_forward_ips": [],
            "dns_reverse_names": [],
            "dns_verified": False,
        }

        # Run lookups in parallel so hostname resolution can chain quickly.
        (
            arp_entries,
            ndp_entries,
            dhcpv4_leases,
            dhcpv6_leases,
            host_overrides,
            dns_forward_ips,
        ) = await asyncio.gather(
            self.search_arp_table(query_lc),
            self.search_ndp_table(query_lc),
            self.get_dhcpv4_leases(),
            self.get_dhcpv6_leases(),
            self.search_host_overrides(query),
            self.resolve_dns_forward(query) if not is_ip_query else self._empty_list(),
        )
        result["dns_forward_ips"] = dns_forward_ips

        # Step 1: Populate from ARP/NDP results
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

        # Step 2: DHCPv4/v6 already fetched above

        # Helper to match any field
        def match_lease(lease: dict[str, Any]) -> bool:
            lease_ip = lease.get("ip") or lease.get("address", "")
            return (
                query_lc in str(lease.get("hostname", "")).lower()
                or query_lc in str(lease_ip).lower()
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

        # Step 3: Use DNS host overrides as a hostname -> IP fallback.
        if host_overrides and not result["ip"]:
            override = host_overrides[0]
            result["ip"] = override.get("server")
            if not result["hostname"]:
                host = str(override.get("hostname", "")).strip()
                domain = str(override.get("domain", "")).strip()
                if host and domain:
                    result["hostname"] = f"{host}.{domain}"
                elif host:
                    result["hostname"] = host

        candidate_dns_ips: list[str] = []

        # Step 4: Always perform reverse DNS checks for forward-resolved names.
        if dns_forward_ips and not is_ip_query:
            verified_forward_ips: list[str] = []
            reverse_name_union: list[str] = []
            for ip in dns_forward_ips:
                reverse_names = await self.resolve_dns_reverse(str(ip))
                reverse_name_union.extend(reverse_names)
                if any(
                    _reverse_name_matches_query(name, query_lc)
                    for name in reverse_names
                ):
                    verified_forward_ips.append(ip)

            result["dns_reverse_names"] = list(dict.fromkeys(reverse_name_union))
            result["dns_verified"] = bool(verified_forward_ips)
            # Keep all forward results visible, but prioritize verified entries.
            result["dns_forward_ips"] = dns_forward_ips
            candidate_dns_ips = verified_forward_ips or dns_forward_ips

            if candidate_dns_ips and not result["ip"]:
                result["ip"] = candidate_dns_ips[0]

        # Step 5: If DNS/other lookup gave us candidate IPs, try each to hydrate ARP.
        if candidate_dns_ips and not result["arp"]:
            for ip in candidate_dns_ips:
                arp_by_ip = await self.search_arp_table(str(ip))
                if arp_by_ip:
                    result["arp"] = arp_by_ip[0]
                    result["ip"] = result["arp"].get("ip") or ip
                    if not result["mac"]:
                        result["mac"] = result["arp"].get("mac")
                    if not result["hostname"]:
                        result["hostname"] = result["arp"].get("hostname")
                    break

        # Step 5b: If DNS/other lookup gave us an IP, re-hydrate ARP/NDP by address.
        if result["ip"] and not result["arp"]:
            arp_by_ip = await self.search_arp_table(str(result["ip"]))
            if arp_by_ip:
                result["arp"] = arp_by_ip[0]
                if not result["mac"]:
                    result["mac"] = result["arp"].get("mac")
                if not result["hostname"]:
                    result["hostname"] = result["arp"].get("hostname")

        if result["ip"] and not result["ndp"]:
            ndp_by_ip = await self.search_ndp_table(str(result["ip"]))
            if ndp_by_ip:
                result["ndp"] = ndp_by_ip[0]
                if not result["mac"]:
                    result["mac"] = result["ndp"].get("mac")
                if not result["hostname"]:
                    result["hostname"] = result["ndp"].get("hostname")

        # Step 6: Reverse lookup for confidence on final IP.
        if result["ip"]:
            reverse_names = await self.resolve_dns_reverse(str(result["ip"]))
            if not result["dns_reverse_names"]:
                result["dns_reverse_names"] = reverse_names
            if not result["dns_verified"]:
                result["dns_verified"] = any(
                    _reverse_name_matches_query(name, query_lc)
                    for name in reverse_names
                )

        return result

    async def _empty_list(self) -> list[Any]:
        """Return an empty list for async gather branches."""
        return []

    async def resolve_dns_forward(self, hostname: str) -> list[str]:
        """Resolve hostname to IP addresses via local resolver."""

        def _resolve() -> list[str]:
            try:
                infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
            except OSError:
                return []
            ips = {info[4][0] for info in infos if info and len(info) > 4 and info[4]}
            return sorted(ips)

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _resolve)

    async def resolve_dns_reverse(self, ip: str) -> list[str]:
        """Resolve reverse DNS PTR names for an IP address."""

        def _reverse() -> list[str]:
            try:
                host, aliases, _ = socket.gethostbyaddr(ip)
            except OSError:
                return []
            names = [host, *aliases]
            # Deduplicate while preserving order.
            seen: set[str] = set()
            unique_names: list[str] = []
            for name in names:
                key = name.lower().strip(".")
                if key and key not in seen:
                    seen.add(key)
                    unique_names.append(name)
            return unique_names

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _reverse)

    async def search_host_overrides(self, search: str = "") -> list[dict[str, Any]]:
        """List Unbound DNS host overrides, optionally filtered by hostname/IP/description."""
        try:
            data = await self._make_request(
                "POST",
                ENDPOINTS["unbound"]["search"],
                json={"current": 1, "rowCount": 100, "searchPhrase": search},
            )
            return data.get("rows", []) if isinstance(data, dict) else []
        except Exception:
            logger.exception("Failed to search host overrides")
            return []

    async def add_host_override(
        self,
        hostname: str,
        domain: str,
        server: str,
        description: str = "",
        enabled: bool = True,
    ) -> dict[str, Any]:
        """Add a DNS host override to Unbound."""
        return await self._make_request(
            "POST",
            ENDPOINTS["unbound"]["add"],
            json={
                "host": {
                    "enabled": "1" if enabled else "0",
                    "hostname": hostname,
                    "domain": domain,
                    "rr": "A",
                    "server": server,
                    "description": description,
                }
            },
        )

    async def del_host_override(self, uuid: str) -> dict[str, Any]:
        """Delete a DNS host override by UUID."""
        return await self._make_request(
            "POST",
            f"{ENDPOINTS['unbound']['delete']}/{uuid}",
        )

    async def reconfigure_unbound(self) -> dict[str, Any]:
        """Apply Unbound DNS configuration changes."""
        return await self._make_request("POST", ENDPOINTS["unbound"]["reconfigure"])

    async def search_aliases(self, search: str = "") -> list[dict[str, Any]]:
        """List firewall aliases, optionally filtered."""
        try:
            data = await self._make_request(
                "POST",
                ENDPOINTS["alias"]["search"],
                json={"current": 1, "rowCount": 100, "searchPhrase": search},
            )
            return data.get("rows", []) if isinstance(data, dict) else []
        except Exception:
            logger.exception("Failed to search aliases")
            return []

    async def get_gateway_status(self) -> list[dict[str, Any]]:
        """Get WAN/gateway health status."""
        try:
            data = await self._make_request(
                "GET", ENDPOINTS["routes"]["gateway_status"]
            )
            if isinstance(data, dict):
                return data.get("items", list(data.values()))
            return data if isinstance(data, list) else []
        except Exception:
            logger.exception("Failed to get gateway status")
            return []

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
