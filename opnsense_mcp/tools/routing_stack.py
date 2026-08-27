"""VLAN devices, gateways and static routes.

The three objects a routed transit needs: a tagged device on a parent
interface, a next hop, and a prefix pointed at it.

Two things here are easy to get wrong, both confirmed against the firmware
models rather than the documentation:

* Routes carry `enabled`. Gateways carry `disabled`. Opposite senses, same
  wave. The published docs also describe route toggling with a `$disabled`
  argument, which this firmware contradicts.
* `search_gateway` returns configuration and live monitoring in one row, 44
  fields deep, so reads project rather than pass through.

Because the toggle endpoints' argument sense is ambiguous across versions,
enabling and disabling is done by reading the object and writing the field
back. The state asked for is the state written, whatever the endpoint would
have done.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

from opnsense_mcp.utils.mvc_merge import flatten_mvc_node
from opnsense_mcp.utils.shaper_write_helpers import (
    issue_delete_confirm_token,
    validate_delete_confirm_token,
)

logger = logging.getLogger(__name__)

VLAN = {
    "search": "/api/interfaces/vlan_settings/search_item",
    "get": "/api/interfaces/vlan_settings/get_item",
    "add": "/api/interfaces/vlan_settings/add_item",
    "delete": "/api/interfaces/vlan_settings/del_item",
    "reconfigure": "/api/interfaces/vlan_settings/reconfigure",
}
GATEWAY = {
    "search": "/api/routing/settings/search_gateway",
    "get": "/api/routing/settings/get_gateway",
    "add": "/api/routing/settings/add_gateway",
    "set": "/api/routing/settings/set_gateway",
    "delete": "/api/routing/settings/del_gateway",
    "reconfigure": "/api/routing/settings/reconfigure",
}
ROUTE = {
    "search": "/api/routes/routes/searchroute",
    "get": "/api/routes/routes/getroute",
    "add": "/api/routes/routes/addroute",
    "set": "/api/routes/routes/setroute",
    "delete": "/api/routes/routes/delroute",
    "reconfigure": "/api/routes/routes/reconfigure",
}

INTERFACE_OVERVIEW = "/api/interfaces/overview/export"

# search_gateway mixes live monitoring into the configuration row.
_GATEWAY_CONFIG_FIELDS = (
    "uuid",
    "name",
    "interface",
    "gateway",
    "ipprotocol",
    "disabled",
    "defaultgw",
    "fargw",
    "monitor",
    "monitor_disable",
    "priority",
    "weight",
    "descr",
)


class _RoutingToolBase:
    """Shared client handling and lookups."""

    def __init__(self, client: Any) -> None:
        """Store the OPNsense client."""
        self.client = client

    def _no_client(self) -> dict[str, Any]:
        return {"status": "error", "error": "No client available"}

    async def _rows(self, endpoint: str) -> list[dict[str, Any]]:
        data = await self.client._make_request(
            "POST", endpoint, json={"current": 1, "rowCount": 5000}
        )
        return data.get("rows", []) if isinstance(data, dict) else []

    def _confirm(self, resource: str, uuid: str, confirm: Any) -> dict[str, Any] | None:
        """Return a confirmation response, or None when the token is valid."""
        if validate_delete_confirm_token(resource, uuid, str(confirm or "")):
            return None
        token = issue_delete_confirm_token(resource, uuid)
        return {
            "status": "confirmation_required",
            "uuid": uuid,
            "confirm_token": token["token"],
            "message": token["message"],
        }


class ListVlansTool(_RoutingToolBase):
    """List VLAN devices."""

    name = "list_vlans"
    description = "List 802.1Q VLAN devices"
    input_schema: dict[str, Any] = {"type": "object", "properties": {}, "required": []}

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return each VLAN's parent, tag and device name."""
        if not self.client:
            return self._no_client()
        try:
            rows = await self._rows(VLAN["search"])
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to list VLANs")
            return {"status": "error", "error": str(exc)}

        vlans = [
            {
                "uuid": row.get("uuid", ""),
                "parent": row.get("if", ""),
                "tag": row.get("tag", ""),
                "pcp": row.get("pcp", ""),
                "device": row.get("vlanif", ""),
                "description": row.get("descr", ""),
            }
            for row in rows
        ]
        return {"status": "success", "count": len(vlans), "vlans": vlans}


class MkVlanTool(_RoutingToolBase):
    """Create a VLAN device."""

    name = "mk_vlan"
    description = "Create an 802.1Q VLAN device on a parent interface"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "parent": {
                "type": "string",
                "description": "Parent device, for example ax0",
            },
            "tag": {"type": "number", "description": "VLAN id, 1 to 4094"},
            "pcp": {
                "type": "number",
                "description": "Priority code point",
                "optional": True,
            },
            "description": {"type": "string", "optional": True},
            "apply": {
                "type": "boolean",
                "description": "Reconfigure VLAN devices afterwards (default false)",
                "optional": True,
            },
        },
        "required": ["parent", "tag"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create the device, or return the existing one for this parent and tag.

        An existing device is reused rather than replaced: it may already be
        assigned to an interface, and deleting it would take that with it.
        """
        params = params or {}
        if not self.client:
            return self._no_client()

        parent = (params.get("parent") or "").strip()
        tag = params.get("tag")
        if not parent or tag is None:
            return {"status": "error", "error": "parent and tag are required"}
        try:
            tag_int = int(tag)
        except (TypeError, ValueError):
            return {"status": "error", "error": f"tag {tag!r} is not a number"}
        if not 1 <= tag_int <= 4094:
            return {"status": "error", "error": "tag must be between 1 and 4094"}

        try:
            for row in await self._rows(VLAN["search"]):
                if row.get("if") == parent and str(row.get("tag")) == str(tag_int):
                    return {
                        "status": "success",
                        "created": False,
                        "uuid": row.get("uuid", ""),
                        "device": row.get("vlanif", ""),
                        "note": "This parent and tag already exist; reused, not replaced.",
                    }

            payload = {
                "if": parent,
                "tag": str(tag_int),
                "pcp": str(params.get("pcp", 0)),
                "descr": params.get("description", ""),
            }
            result = await self.client._make_request(
                "POST", VLAN["add"], call_class="write", json={"vlan": payload}
            )
            if params.get("apply", False):
                await self.client._make_request(
                    "POST", VLAN["reconfigure"], call_class="apply"
                )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to create VLAN")
            return {"status": "error", "error": str(exc)}

        return {
            "status": "success",
            "created": True,
            "uuid": result.get("uuid", "") if isinstance(result, dict) else "",
            "note": "Staged. Assigning and addressing the interface stays a UI step.",
        }


class RmVlanTool(_RoutingToolBase):
    """Delete a VLAN device."""

    name = "rm_vlan"
    description = "Delete a VLAN device; refuses while it is assigned to an interface"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "VLAN uuid"},
            "confirm": {"type": "string", "optional": True},
        },
        "required": ["uuid"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Delete the device once confirmed, unless an interface still uses it."""
        params = params or {}
        if not self.client:
            return self._no_client()
        uuid = (params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}

        pending = self._confirm("vlan", uuid, params.get("confirm"))
        if pending:
            return pending

        try:
            rows = await self._rows(VLAN["search"])
            row = next((r for r in rows if r.get("uuid") == uuid), None)
            if not row:
                return {"status": "error", "error": f"VLAN {uuid} not found"}

            device = (row.get("vlanif") or "").split(" ")[0]
            overview = await self.client._make_request("GET", INTERFACE_OVERVIEW)
            entries = overview if isinstance(overview, list) else []
            assigned = [
                entry.get("identifier", "")
                for entry in entries
                if isinstance(entry, dict) and entry.get("device") == device
            ]
            if assigned:
                return {
                    "status": "error",
                    "error": (
                        f"{device} is assigned to interface {', '.join(assigned)}. "
                        f"Unassign it first; deleting the device would take the "
                        f"interface with it."
                    ),
                }

            await self.client._make_request(
                "POST", f"{VLAN['delete']}/{uuid}", call_class="write", json={}
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to delete VLAN")
            return {"status": "error", "error": str(exc)}

        return {"status": "success", "uuid": uuid, "deleted": True}


class ListGatewaysTool(_RoutingToolBase):
    """List configured gateways."""

    name = "list_gateways"
    description = "List configured gateways, configuration fields only"
    input_schema: dict[str, Any] = {"type": "object", "properties": {}, "required": []}

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return the configuration of each gateway.

        The rows also carry live latency and loss counters. Those belong to
        `gateway_status`, so they are dropped here rather than returned as if
        they were settings.
        """
        if not self.client:
            return self._no_client()
        try:
            rows = await self._rows(GATEWAY["search"])
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to list gateways")
            return {"status": "error", "error": str(exc)}

        gateways = [
            {field: row.get(field, "") for field in _GATEWAY_CONFIG_FIELDS}
            for row in rows
        ]
        return {"status": "success", "count": len(gateways), "gateways": gateways}


class MkGatewayTool(_RoutingToolBase):
    """Create a gateway."""

    name = "mk_gateway"
    description = "Create a gateway on an interface"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Gateway name"},
            "interface": {"type": "string", "description": "Interface identifier"},
            "gateway": {"type": "string", "description": "Next hop address"},
            "ipprotocol": {
                "type": "string",
                "description": "inet or inet6 (default inet)",
                "optional": True,
            },
            "far_gateway": {
                "type": "boolean",
                "description": "Next hop outside the interface subnet",
                "optional": True,
            },
            "monitor_disable": {
                "type": "boolean",
                "description": "Turn off monitoring, usual for a point-to-point transit",
                "optional": True,
            },
            "description": {"type": "string", "optional": True},
            "apply": {
                "type": "boolean",
                "description": "Reconfigure routing afterwards (default false)",
                "optional": True,
            },
        },
        "required": ["name", "interface", "gateway"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create the gateway, keyed on interface and next hop."""
        params = params or {}
        if not self.client:
            return self._no_client()

        name = (params.get("name") or "").strip()
        interface = (params.get("interface") or "").strip()
        gateway = (params.get("gateway") or "").strip()
        if not name or not interface or not gateway:
            return {
                "status": "error",
                "error": "name, interface and gateway are required",
            }
        try:
            ipaddress.ip_address(gateway)
        except ValueError:
            return {
                "status": "error",
                "error": f"gateway {gateway!r} is not a valid address",
            }

        try:
            for row in await self._rows(GATEWAY["search"]):
                if row.get("interface") == interface and row.get("gateway") == gateway:
                    return {
                        "status": "success",
                        "created": False,
                        "uuid": row.get("uuid", ""),
                        "note": "A gateway with this next hop exists on that interface.",
                    }

            # The model has `disabled`, not `enabled`.
            payload = {
                "name": name,
                "interface": interface,
                "gateway": gateway,
                "ipprotocol": params.get("ipprotocol", "inet"),
                "disabled": "0",
                "fargw": "1" if params.get("far_gateway") else "0",
                "monitor_disable": "1" if params.get("monitor_disable") else "0",
                "descr": params.get("description", ""),
            }
            result = await self.client._make_request(
                "POST",
                GATEWAY["add"],
                call_class="write",
                json={"gateway_item": payload},
            )
            if params.get("apply", False):
                await self.client._make_request(
                    "POST", GATEWAY["reconfigure"], call_class="apply"
                )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to create gateway")
            return {"status": "error", "error": str(exc)}

        return {
            "status": "success",
            "created": True,
            "uuid": result.get("uuid", "") if isinstance(result, dict) else "",
            "note": "Staged.",
        }


class ToggleGatewayTool(_RoutingToolBase):
    """Enable or disable a gateway."""

    name = "toggle_gateway"
    description = "Enable or disable a gateway"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "Gateway uuid"},
            "enabled": {"type": "boolean", "description": "Target state"},
            "apply": {"type": "boolean", "optional": True},
        },
        "required": ["uuid", "enabled"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Write the target state to `disabled`, the inverse of what is asked.

        Done by read and write rather than the toggle endpoint: the endpoint's
        argument sense differs between the docs and this firmware, and a
        gateway that ends up in the opposite state to the one requested takes
        its routes with it.
        """
        params = params or {}
        if not self.client:
            return self._no_client()
        uuid = (params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}
        if params.get("enabled") is None:
            return {"status": "error", "error": "enabled is required"}

        try:
            current = await self.client._make_request("GET", f"{GATEWAY['get']}/{uuid}")
            node = current.get("gateway_item") if isinstance(current, dict) else None
            if not isinstance(node, dict):
                return {"status": "error", "error": f"gateway {uuid} not found"}

            payload = flatten_mvc_node(node)
            payload["disabled"] = "0" if params["enabled"] else "1"

            await self.client._make_request(
                "POST",
                f"{GATEWAY['set']}/{uuid}",
                call_class="write",
                json={"gateway_item": payload},
            )
            if params.get("apply", False):
                await self.client._make_request(
                    "POST", GATEWAY["reconfigure"], call_class="apply"
                )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to toggle gateway")
            return {"status": "error", "error": str(exc)}

        return {
            "status": "success",
            "uuid": uuid,
            "enabled": bool(params["enabled"]),
            "disabled_field": payload["disabled"],
        }


class ListRoutesTool(_RoutingToolBase):
    """List static routes."""

    name = "list_routes"
    description = "List configured static routes"
    input_schema: dict[str, Any] = {"type": "object", "properties": {}, "required": []}

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return each route's prefix, gateway and state."""
        if not self.client:
            return self._no_client()
        try:
            rows = await self._rows(ROUTE["search"])
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to list routes")
            return {"status": "error", "error": str(exc)}

        routes = [
            {
                "uuid": row.get("uuid", ""),
                "network": row.get("network", ""),
                "gateway": row.get("gateway", ""),
                "enabled": row.get("enabled", ""),
                "description": row.get("descr", ""),
            }
            for row in rows
        ]
        return {"status": "success", "count": len(routes), "routes": routes}


class MkRouteTool(_RoutingToolBase):
    """Create a static route."""

    name = "mk_route"
    description = "Create a static route via a configured gateway"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "network": {
                "type": "string",
                "description": "Destination prefix, for example 172.20.2.0/24",
            },
            "gateway": {
                "type": "string",
                "description": "Gateway name, from list_gateways",
            },
            "description": {"type": "string", "optional": True},
            "apply": {
                "type": "boolean",
                "description": "Reconfigure routes afterwards (default false)",
                "optional": True,
            },
        },
        "required": ["network", "gateway"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create the route, keyed on prefix and gateway."""
        params = params or {}
        if not self.client:
            return self._no_client()

        network = (params.get("network") or "").strip()
        gateway = (params.get("gateway") or "").strip()
        if not network or not gateway:
            return {"status": "error", "error": "network and gateway are required"}
        try:
            ipaddress.ip_network(network, strict=False)
        except ValueError as exc:
            return {
                "status": "error",
                "error": f"network {network!r} is not a valid prefix: {exc}",
            }

        try:
            for row in await self._rows(ROUTE["search"]):
                if row.get("network") == network and row.get("gateway") == gateway:
                    return {
                        "status": "success",
                        "created": False,
                        "uuid": row.get("uuid", ""),
                        "note": "This prefix already routes via that gateway.",
                    }

            # The model has `enabled`, not `disabled`, despite the docs.
            payload = {
                "network": network,
                "gateway": gateway,
                "descr": params.get("description", ""),
                "enabled": "1",
            }
            result = await self.client._make_request(
                "POST", ROUTE["add"], call_class="write", json={"route": payload}
            )
            if params.get("apply", False):
                await self.client._make_request(
                    "POST", ROUTE["reconfigure"], call_class="apply"
                )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to create route")
            return {"status": "error", "error": str(exc)}

        return {
            "status": "success",
            "created": True,
            "uuid": result.get("uuid", "") if isinstance(result, dict) else "",
            "note": "Staged.",
        }


class ToggleRouteTool(_RoutingToolBase):
    """Enable or disable a static route."""

    name = "toggle_route"
    description = "Enable or disable a static route"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "Route uuid"},
            "enabled": {"type": "boolean", "description": "Target state"},
            "apply": {"type": "boolean", "optional": True},
        },
        "required": ["uuid", "enabled"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Write the target state to `enabled`.

        Note the opposite sense to `toggle_gateway`: this model stores
        `enabled`, that one stores `disabled`.
        """
        params = params or {}
        if not self.client:
            return self._no_client()
        uuid = (params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}
        if params.get("enabled") is None:
            return {"status": "error", "error": "enabled is required"}

        try:
            current = await self.client._make_request("GET", f"{ROUTE['get']}/{uuid}")
            node = current.get("route") if isinstance(current, dict) else None
            if not isinstance(node, dict):
                return {"status": "error", "error": f"route {uuid} not found"}

            payload = flatten_mvc_node(node)
            payload["enabled"] = "1" if params["enabled"] else "0"

            await self.client._make_request(
                "POST",
                f"{ROUTE['set']}/{uuid}",
                call_class="write",
                json={"route": payload},
            )
            if params.get("apply", False):
                await self.client._make_request(
                    "POST", ROUTE["reconfigure"], call_class="apply"
                )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to toggle route")
            return {"status": "error", "error": str(exc)}

        return {"status": "success", "uuid": uuid, "enabled": bool(params["enabled"])}


class RmRouteTool(_RoutingToolBase):
    """Delete a static route."""

    name = "rm_route"
    description = "Delete a static route; requires a confirm token from a prior call"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "Route uuid"},
            "confirm": {"type": "string", "optional": True},
            "apply": {"type": "boolean", "optional": True},
        },
        "required": ["uuid"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Delete once confirmed."""
        params = params or {}
        if not self.client:
            return self._no_client()
        uuid = (params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}

        pending = self._confirm("route", uuid, params.get("confirm"))
        if pending:
            return pending

        try:
            await self.client._make_request(
                "POST", f"{ROUTE['delete']}/{uuid}", call_class="write", json={}
            )
            if params.get("apply", False):
                await self.client._make_request(
                    "POST", ROUTE["reconfigure"], call_class="apply"
                )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to delete route")
            return {"status": "error", "error": str(exc)}

        return {"status": "success", "uuid": uuid, "deleted": True}


class RmGatewayTool(_RoutingToolBase):
    """Delete a gateway."""

    name = "rm_gateway"
    description = "Delete a gateway; requires a confirm token"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "Gateway uuid"},
            "confirm": {"type": "string", "optional": True},
            "apply": {"type": "boolean", "optional": True},
        },
        "required": ["uuid"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Delete once confirmed.

        A gateway can be the default route, and every static route pointing at
        it goes with it, so the blast radius is larger than the object.
        """
        params = params or {}
        if not self.client:
            return self._no_client()
        uuid = (params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}

        if not validate_delete_confirm_token(
            "gateway", uuid, str(params.get("confirm") or "")
        ):
            token = issue_delete_confirm_token("gateway", uuid)
            return {
                "status": "confirmation_required",
                "uuid": uuid,
                "confirm_token": token["token"],
                "message": token["message"],
            }

        try:
            result = await self.client._make_request(
                "POST", f"{GATEWAY['delete']}/{uuid}", call_class="write", json={}
            )
            if params.get("apply", False):
                await self.client._make_request(
                    "POST", GATEWAY["reconfigure"], call_class="apply"
                )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to delete gateway")
            return {"status": "error", "error": str(exc)}

        if isinstance(result, dict) and result.get("result") == "not found":
            return {
                "status": "error",
                "error": f"no gateway with uuid {uuid}; it may already be gone.",
            }
        return {"status": "success", "uuid": uuid, "deleted": True}
