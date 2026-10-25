"""Unbound DNS host override creation tool for OPNsense."""

import ipaddress
import logging
from typing import Any

from opnsense_mcp.utils.api import OPNsenseClient, _record_type_for_server

logger = logging.getLogger(__name__)


def _same_ip(value: str, addresses: set[str]) -> bool:
    """True when value is one of addresses, comparing IPs (IPv6 has many spellings)."""
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return value in addresses
    return any(ip == ipaddress.ip_address(a) for a in addresses)


class MkdnsTool:
    """Tool for adding Unbound DNS host overrides."""

    name = "mkdns"
    description = "Add a DNS host override in Unbound"
    input_schema = {
        "type": "object",
        "properties": {
            "hostname": {
                "type": "string",
                "description": "Hostname (without domain, e.g. 'myserver')",
            },
            "domain": {
                "type": "string",
                "description": "Domain (e.g. 'local' or 'example.com')",
            },
            "server": {
                "type": "string",
                "description": "IP address this hostname resolves to",
            },
            "server6": {
                "type": "string",
                "description": "Optional IPv6 address for an AAAA record in the same call; `server` must then be IPv4",
                "optional": True,
            },
            "description": {
                "type": "string",
                "description": "Optional description",
                "optional": True,
            },
            "enabled": {
                "type": "boolean",
                "description": "Whether the override is active (default: true)",
                "optional": True,
            },
        },
        "required": ["hostname", "domain", "server"],
    }

    def __init__(self, client: OPNsenseClient | None) -> None:
        """
        Initialize the DNS creation tool.

        Args:
            client: OPNsense client instance for API communication.

        """
        self.client = client

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Add a new DNS host override and reload Unbound.

        Args:
            params: Dict with hostname, domain, server, and optional fields.

        Returns:
            Dictionary containing the created override UUID and status.

        """
        if params is None:
            params = {}

        if not self.client:
            return {"status": "error", "error": "No client available"}

        hostname = params.get("hostname", "").strip()
        domain = params.get("domain", "").strip()
        server = params.get("server", "").strip()
        server6 = str(params.get("server6") or "").strip()
        paired = bool(server6)

        if not hostname or not domain or not server:
            return {
                "status": "error",
                "error": "hostname, domain, and server are required",
            }

        try:
            record_type = _record_type_for_server(server)
        except ValueError:
            return {
                "status": "error",
                "error": f"Invalid IP address for server: {server}",
            }

        if paired:
            try:
                record_type6 = _record_type_for_server(server6)
            except ValueError:
                return {
                    "status": "error",
                    "error": f"Invalid IP address for server6: {server6}",
                }
            if record_type != "A" or record_type6 != "AAAA":
                return {
                    "status": "error",
                    "error": "server must be IPv4 and server6 must be IPv6",
                }

        try:
            existing = await self.client.search_host_overrides(hostname)
            addresses = {server, server6} if paired else {server}
            for row in existing:
                if (
                    row.get("hostname", "").casefold() == hostname.casefold()
                    and row.get("domain", "").casefold() == domain.casefold()
                    and _same_ip(str(row.get("server", "")), addresses)
                ):
                    return {
                        "status": "error",
                        "error": f"DNS override already exists for {hostname}.{domain}: {row['server']}",
                    }

            add_params = {
                "hostname": hostname,
                "domain": domain,
                "server": server,
                "description": params.get("description", ""),
                "enabled": params.get("enabled", True),
            }
            if paired:
                add_params["rr"] = "A"
            result = await self.client.add_host_override(**add_params)

            uuid = result.get("uuid", "")
            if not uuid:
                return {
                    "status": "error",
                    "error": f"API did not return a UUID: {result}",
                }

            uuids = {record_type: uuid}
            if paired:
                try:
                    result6 = await self.client.add_host_override(
                        hostname=hostname,
                        domain=domain,
                        server=server6,
                        description=params.get("description", ""),
                        enabled=params.get("enabled", True),
                        rr="AAAA",
                    )
                    uuid6 = result6.get("uuid", "")
                    if not uuid6:
                        raise ValueError(f"API did not return an AAAA UUID: {result6}")
                except Exception as add_error:
                    try:
                        await self.client.del_host_override(uuid)
                    except Exception as rollback_error:
                        logger.exception(
                            "Failed to roll back DNS host override %s", uuid
                        )
                        return {
                            "status": "error",
                            "error": (
                                f"AAAA add failed: {add_error}; rollback failed for "
                                f"{uuid}: {rollback_error}"
                            ),
                        }
                    return {"status": "error", "error": f"AAAA add failed: {add_error}"}
                uuids["AAAA"] = uuid6

            apply_result = await self.client.reconfigure_unbound()

            response = {
                "uuid": uuid,
                "uuids": uuids,
                "hostname": hostname,
                "domain": domain,
                "server": server,
                "rr": "A+AAAA" if paired else record_type,
                "applied": apply_result.get("applied", False),
                "status": "success",
            }
            if paired:
                response["server6"] = server6
            if "apply_error" in apply_result:
                response["apply_error"] = apply_result["apply_error"]
            return response
        except Exception as e:
            logger.exception("Failed to add DNS host override")
            return {"status": "error", "error": str(e)}
