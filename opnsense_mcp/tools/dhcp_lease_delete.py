"""DHCP lease deletion tool for OPNsense."""

import logging
from typing import Any

from pydantic import BaseModel

from opnsense_mcp.utils.api import OPNsenseClient

logger = logging.getLogger(__name__)


class DHCPLeaseDeleteParams(BaseModel):
    """Parameters for DHCP lease deletion."""

    hostname: str | None = None
    ip: str | None = None
    mac: str | None = None


class DHCPLeaseDeleteTool:
    """Tool for deleting DHCP leases from OPNsense."""

    name = "dhcp_lease_delete"
    description = "Delete DHCP leases by hostname, IP, or MAC address"
    input_schema = {
        "type": "object",
        "properties": {
            "hostname": {"type": "string", "description": "Hostname to search for"},
            "ip": {"type": "string", "description": "IP address to delete"},
            "mac": {"type": "string", "description": "MAC address to search for"},
        },
        "anyOf": [
            {"required": ["hostname"]},
            {"required": ["ip"]},
            {"required": ["mac"]},
        ],
    }

    def __init__(self, client: OPNsenseClient | None) -> None:
        """
        Initialize the DHCP lease deletion tool.

        Args:
            client: OPNsense client instance for API communication.

        """
        self.client = client

    def _normalize_mac(self, mac: str) -> str:
        """
        Normalize MAC address format.

        Args:
            mac: MAC address in any common format.

        Returns:
            Normalized MAC address in lowercase with colons.

        """
        # Remove common separators and convert to lowercase
        mac = mac.replace("-", "").replace(":", "").replace(".", "").lower()
        # Add colons every 2 characters
        return ":".join(mac[i : i + 2] for i in range(0, len(mac), 2))

    def _find_lease_by_criteria(
        self,
        leases: list[dict[str, Any]],
        hostname: str | None = None,
        ip: str | None = None,
        mac: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Find leases matching the given criteria.

        Args:
            leases: List of lease dictionaries.
            hostname: Hostname to search for.
            ip: IP address to search for.
            mac: MAC address to search for.

        Returns:
            List of matching leases.

        """
        matching_leases = []

        for lease in leases:
            # Normalize lease data
            lease_ip = lease.get("ip") or lease.get("address", "")
            lease_mac = lease.get("mac", "").lower()
            lease_hostname = lease.get("hostname", "").lower()

            # Check if lease matches any criteria
            if (
                ip
                and lease_ip == ip
                or mac
                and self._normalize_mac(lease_mac) == self._normalize_mac(mac)
                or hostname
                and lease_hostname == hostname.lower()
            ):
                matching_leases.append(lease)

        return matching_leases

    async def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        """
        Execute DHCP lease deletion.

        Args:
            params: Execution parameters containing hostname, ip, or mac.

        Returns:
            Dictionary containing deletion results.

        """
        try:
            if not self.client:
                return {
                    "status": "error",
                    "error": "No client available",
                    "deleted_leases": [],
                }

            # Parse parameters
            hostname = params.get("hostname")
            ip = params.get("ip")
            mac = params.get("mac")

            if not any([hostname, ip, mac]):
                return {
                    "status": "error",
                    "error": "Must provide hostname, ip, or mac parameter",
                    "deleted_leases": [],
                }

            deleted_leases = []
            errors = []

            # Get current leases to find matches
            dhcpv4_leases = await self.client.get_dhcpv4_leases()
            dhcpv6_leases = await self.client.get_dhcpv6_leases()

            # Find matching IPv4 leases
            matching_v4 = self._find_lease_by_criteria(dhcpv4_leases, hostname, ip, mac)

            # Find matching IPv6 leases
            matching_v6 = self._find_lease_by_criteria(dhcpv6_leases, hostname, ip, mac)

            # Delete matching IPv4 leases
            for lease in matching_v4:
                lease_ip = lease.get("ip") or lease.get("address")
                if lease_ip:
                    try:
                        # Delete IPv4 lease
                        response = await self.client._make_request(
                            "POST", f"/api/dhcpv4/leases/del_lease/{lease_ip}"
                        )
                        deleted_leases.append(
                            {
                                "ip": lease_ip,
                                "mac": lease.get("mac"),
                                "hostname": lease.get("hostname"),
                                "type": "IPv4",
                                "status": "deleted",
                            }
                        )
                        logger.info(f"Deleted IPv4 lease for IP: {lease_ip}")
                    except Exception as e:
                        error_msg = f"Failed to delete IPv4 lease {lease_ip}: {str(e)}"
                        errors.append(error_msg)
                        logger.error(error_msg)

            # Delete matching IPv6 leases
            for lease in matching_v6:
                lease_ip = lease.get("ip") or lease.get("address")
                if lease_ip:
                    try:
                        # Delete IPv6 lease
                        response = await self.client._make_request(
                            "POST", f"/api/dhcpv6/leases/del_lease/{lease_ip}"
                        )
                        deleted_leases.append(
                            {
                                "ip": lease_ip,
                                "mac": lease.get("mac"),
                                "hostname": lease.get("hostname"),
                                "type": "IPv6",
                                "status": "deleted",
                            }
                        )
                        logger.info(f"Deleted IPv6 lease for IP: {lease_ip}")
                    except Exception as e:
                        error_msg = f"Failed to delete IPv6 lease {lease_ip}: {str(e)}"
                        errors.append(error_msg)
                        logger.error(error_msg)

            # Return results
            result = {
                "status": "success" if deleted_leases else "no_matches",
                "deleted_leases": deleted_leases,
                "total_deleted": len(deleted_leases),
                "search_criteria": {"hostname": hostname, "ip": ip, "mac": mac},
            }

            if errors:
                result["errors"] = errors
                result["status"] = "partial_success" if deleted_leases else "error"

            return result

        except Exception as e:
            logger.exception("Failed to delete DHCP leases")
            return {
                "status": "error",
                "error": str(e),
                "deleted_leases": [],
            }

    def _get_dummy_data(self) -> dict[str, Any]:
        """
        Get dummy DHCP lease deletion data for testing.

        Returns:
            Dictionary with dummy DHCP lease deletion results.

        """
        return {
            "status": "success",
            "deleted_leases": [
                {
                    "ip": "10.0.2.15",
                    "mac": "08:00:27:12:34:56",
                    "hostname": "test-device",
                    "type": "IPv4",
                    "status": "deleted",
                }
            ],
            "total_deleted": 1,
            "search_criteria": {"hostname": "test-device", "ip": None, "mac": None},
        }
