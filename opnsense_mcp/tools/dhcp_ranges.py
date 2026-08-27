"""DHCP ranges and DHCP options, including the router option.

Option 3 is the capability this adds. A subnet that sits behind a router rather
than on the firewall gets its default gateway from DHCP, and nothing here could
set one, so moving a subnet behind a router was a UI-only operation.

Two shapes that are easy to get wrong, both read off the live API rather than
guessed:

- `constructor` on a range is the IPv6 prefix-from-interface field. It reads
  like a relay setting and is not one.
- An option scopes by `interface` or by `tag`, and the v4 and v6 option numbers
  are separate enums: 3 is `router` in v4 and `option_ia_na` in v6, so putting
  a v4 number in `option6` yields a valid request that configures something
  else.
"""

from __future__ import annotations

import logging
from typing import Any

from opnsense_mcp.utils.mvc_merge import merge_for_set
from opnsense_mcp.utils.shaper_write_helpers import (
    issue_delete_confirm_token,
    validate_delete_confirm_token,
)

logger = logging.getLogger(__name__)

DNSMASQ = {
    "search_range": "/api/dnsmasq/settings/search_range",
    "get_range": "/api/dnsmasq/settings/get_range",
    "add_range": "/api/dnsmasq/settings/add_range",
    "set_range": "/api/dnsmasq/settings/set_range",
    "del_range": "/api/dnsmasq/settings/del_range",
    "search_option": "/api/dnsmasq/settings/search_option",
    "get_option": "/api/dnsmasq/settings/get_option",
    "add_option": "/api/dnsmasq/settings/add_option",
    "set_option": "/api/dnsmasq/settings/set_option",
    "del_option": "/api/dnsmasq/settings/del_option",
    "reconfigure": "/api/dnsmasq/service/reconfigure",
}

ROUTER_OPTION = "3"

_RANGE_FIELDS = (
    "uuid",
    "interface",
    "start_addr",
    "end_addr",
    "subnet_mask",
    "constructor",
    "mode",
    "prefix_len",
    "lease_time",
    "domain",
    "set_tag",
    "nosync",
    "description",
)

_OPTION_FIELDS = (
    "uuid",
    "type",
    "option",
    "option6",
    "interface",
    "tag",
    "set_tag",
    "value",
    "force",
    "description",
)


class _DnsmasqToolBase:
    """Shared client handling and row access."""

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

    async def _reconfigure(self) -> None:
        await self.client._make_request(
            "POST", DNSMASQ["reconfigure"], call_class="apply"
        )


def _project(row: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    """Keep the real fields, and surface the display label under a plain name."""
    out = {field: row.get(field, "") for field in fields}
    if "%interface" in row:
        out["interface_label"] = row["%interface"]
    return out


class ListDhcpRangesTool(_DnsmasqToolBase):
    """List dnsmasq DHCP ranges."""

    name = "list_dhcp_ranges"
    description = "List DHCP ranges served by dnsmasq"
    input_schema: dict[str, Any] = {"type": "object", "properties": {}, "required": []}

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return the ranges without the display-only fields."""
        if not self.client:
            return self._no_client()
        try:
            rows = await self._rows(DNSMASQ["search_range"])
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to list DHCP ranges")
            return {"status": "error", "error": str(exc)}
        ranges = [_project(row, _RANGE_FIELDS) for row in rows]
        return {"status": "success", "count": len(ranges), "ranges": ranges}


class MkDhcpRangeTool(_DnsmasqToolBase):
    """Create a DHCP range."""

    name = "mk_dhcp_range"
    description = "Create a DHCP range on an interface"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "interface": {"type": "string", "description": "Interface key, e.g. opt3"},
            "start_addr": {"type": "string", "description": "First address"},
            "end_addr": {"type": "string", "description": "Last address"},
            "subnet_mask": {"type": "string", "optional": True},
            "lease_time": {
                "type": "string",
                "description": "Seconds, or a suffixed value like 2h",
                "optional": True,
            },
            "domain": {"type": "string", "optional": True},
            "description": {"type": "string", "optional": True},
            "apply": {
                "type": "boolean",
                "description": "Reconfigure dnsmasq afterwards (default false)",
                "optional": True,
            },
        },
        "required": ["interface", "start_addr", "end_addr"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create the range, keyed on interface and start address."""
        params = params or {}
        if not self.client:
            return self._no_client()

        interface = (params.get("interface") or "").strip()
        start = (params.get("start_addr") or "").strip()
        end = (params.get("end_addr") or "").strip()
        if not interface:
            return {"status": "error", "error": "interface is required"}
        if not start or not end:
            missing = "start_addr" if not start else "end_addr"
            return {
                "status": "error",
                "error": f"{missing} is required; a range needs both bounds",
            }

        try:
            for row in await self._rows(DNSMASQ["search_range"]):
                if row.get("interface") == interface and row.get("start_addr") == start:
                    return {
                        "status": "success",
                        "created": False,
                        "uuid": row.get("uuid", ""),
                        "note": "A range with this interface and start address exists.",
                    }

            payload = {
                "interface": interface,
                "start_addr": start,
                "end_addr": end,
                "subnet_mask": params.get("subnet_mask", ""),
                "lease_time": params.get("lease_time", ""),
                "domain": params.get("domain", ""),
                "description": params.get("description", ""),
            }
            result = await self.client._make_request(
                "POST",
                DNSMASQ["add_range"],
                call_class="write",
                json={"range": payload},
            )
            if params.get("apply", False):
                await self._reconfigure()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to create DHCP range")
            return {"status": "error", "error": str(exc)}

        return {
            "status": "success",
            "created": True,
            "uuid": result.get("uuid", "") if isinstance(result, dict) else "",
            "note": "Staged. Reconfigure dnsmasq to serve it.",
        }


class SetDhcpRangeTool(_DnsmasqToolBase):
    """Update a DHCP range."""

    name = "set_dhcp_range"
    description = "Update fields on an existing DHCP range"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "Range uuid"},
            "start_addr": {"type": "string", "optional": True},
            "end_addr": {"type": "string", "optional": True},
            "subnet_mask": {"type": "string", "optional": True},
            "lease_time": {"type": "string", "optional": True},
            "domain": {"type": "string", "optional": True},
            "description": {"type": "string", "optional": True},
            "apply": {"type": "boolean", "optional": True},
        },
        "required": ["uuid"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Read the range, merge the given fields, write the whole node back.

        A partial POST to an MVC model blanks every field it omits. That is the
        defect that made set_fw_rule widen rules to any/any, and a range would
        lose its bounds the same way.
        """
        params = params or {}
        if not self.client:
            return self._no_client()
        uuid = (params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}

        editable = (
            "start_addr",
            "end_addr",
            "subnet_mask",
            "lease_time",
            "domain",
            "description",
        )
        changes = {key: params[key] for key in editable if key in params}
        if not changes:
            return {
                "status": "error",
                "error": f"nothing to change; pass one of: {', '.join(editable)}",
            }

        try:
            current = await self.client._make_request(
                "GET", f"{DNSMASQ['get_range']}/{uuid}"
            )
            node = current.get("range", {}) if isinstance(current, dict) else {}
            if not node:
                return {"status": "error", "error": f"range {uuid} not found"}

            payload = merge_for_set(node, changes)
            await self.client._make_request(
                "POST",
                f"{DNSMASQ['set_range']}/{uuid}",
                call_class="write",
                json={"range": payload},
            )
            if params.get("apply", False):
                await self._reconfigure()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to update DHCP range")
            return {"status": "error", "error": str(exc)}

        return {"status": "success", "uuid": uuid, "changed": sorted(changes)}


class RmDhcpRangeTool(_DnsmasqToolBase):
    """Delete a DHCP range."""

    name = "rm_dhcp_range"
    description = "Delete a DHCP range; requires a confirm token"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "Range uuid"},
            "confirm": {"type": "string", "optional": True},
            "apply": {"type": "boolean", "optional": True},
        },
        "required": ["uuid"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Delete once confirmed.

        Removing a range stops the subnet getting addresses at all, and the
        symptom appears whenever leases happen to expire rather than at once.
        """
        params = params or {}
        if not self.client:
            return self._no_client()
        uuid = (params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}

        if not validate_delete_confirm_token(
            "dhcp_range", uuid, str(params.get("confirm") or "")
        ):
            token = issue_delete_confirm_token("dhcp_range", uuid)
            return {
                "status": "confirmation_required",
                "uuid": uuid,
                "confirm_token": token["token"],
                "message": token["message"],
            }

        try:
            await self.client._make_request(
                "POST", f"{DNSMASQ['del_range']}/{uuid}", call_class="write", json={}
            )
            if params.get("apply", False):
                await self._reconfigure()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to delete DHCP range")
            return {"status": "error", "error": str(exc)}
        return {"status": "success", "uuid": uuid, "deleted": True}


class ListDhcpOptionsTool(_DnsmasqToolBase):
    """List dnsmasq DHCP options."""

    name = "list_dhcp_options"
    description = "List DHCP options, with their human-readable option names"
    input_schema: dict[str, Any] = {"type": "object", "properties": {}, "required": []}

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return the options, keeping the option label alongside the number."""
        if not self.client:
            return self._no_client()
        try:
            rows = await self._rows(DNSMASQ["search_option"])
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to list DHCP options")
            return {"status": "error", "error": str(exc)}

        options = []
        for row in rows:
            entry = _project(row, _OPTION_FIELDS)
            # The number alone is unreadable; the API already knows the name.
            entry["label"] = row.get("%option") or row.get("%option6") or ""
            options.append(entry)
        return {"status": "success", "count": len(options), "options": options}


class SetDhcpRouterOptionTool(_DnsmasqToolBase):
    """Set the default gateway handed out by DHCP."""

    name = "set_dhcp_router_option"
    description = (
        "Set the default gateway (DHCP option 3) for an interface or tag, "
        "which is what a subnet behind a router needs"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "router": {
                "type": "string",
                "description": "Gateway address to advertise",
            },
            "interface": {
                "type": "string",
                "description": "Interface key to scope the option to, e.g. opt3",
                "optional": True,
            },
            "tag": {
                "type": "string",
                "description": "Tag uuid to scope to instead of an interface",
                "optional": True,
            },
            "force": {
                "type": "boolean",
                "description": "Send the option even when the client did not ask",
                "optional": True,
            },
            "apply": {"type": "boolean", "optional": True},
        },
        "required": ["router"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create or update the option 3 row for this scope.

        Scoping is required. An unscoped option 3 applies to every subnet
        dnsmasq serves, which points unrelated networks at the wrong gateway
        and looks like a routing fault rather than a DHCP one.
        """
        params = params or {}
        if not self.client:
            return self._no_client()

        router = (params.get("router") or "").strip()
        if not router:
            return {"status": "error", "error": "router is required"}

        interface = (params.get("interface") or "").strip()
        tag = (params.get("tag") or "").strip()
        if not interface and not tag:
            return {
                "status": "error",
                "error": (
                    "one of interface or tag is required. An unscoped option 3 "
                    "becomes the default gateway for every subnet dnsmasq serves."
                ),
            }

        try:
            existing = None
            for row in await self._rows(DNSMASQ["search_option"]):
                # Match the option number too: an interface usually carries
                # several options, and matching on scope alone would overwrite
                # whichever happened to be first.
                if row.get("option") != ROUTER_OPTION:
                    continue
                if interface and row.get("interface") == interface:
                    existing = row
                    break
                if tag and row.get("tag") == tag:
                    existing = row
                    break

            payload = {
                "type": "set",
                "option": ROUTER_OPTION,
                # Left empty deliberately: 3 is option_ia_na in the v6 enum.
                "option6": "",
                "interface": interface,
                "tag": tag,
                "set_tag": "",
                "value": router,
                "force": "1" if params.get("force") else "0",
                "description": (existing or {}).get("description", ""),
            }

            if existing:
                uuid = existing.get("uuid", "")
                await self.client._make_request(
                    "POST",
                    f"{DNSMASQ['set_option']}/{uuid}",
                    call_class="write",
                    json={"option": payload},
                )
                created = False
            else:
                result = await self.client._make_request(
                    "POST",
                    DNSMASQ["add_option"],
                    call_class="write",
                    json={"option": payload},
                )
                uuid = result.get("uuid", "") if isinstance(result, dict) else ""
                created = True

            if params.get("apply", False):
                await self._reconfigure()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to set the DHCP router option")
            return {"status": "error", "error": str(exc)}

        return {
            "status": "success",
            "uuid": uuid,
            "created": created,
            "router": router,
            "scope": interface or f"tag:{tag}",
            "note": "Staged. Reconfigure dnsmasq to serve it.",
        }


class RmDhcpOptionTool(_DnsmasqToolBase):
    """Delete a DHCP option."""

    name = "rm_dhcp_option"
    description = "Delete a DHCP option; requires a confirm token"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "Option uuid"},
            "confirm": {"type": "string", "optional": True},
            "apply": {"type": "boolean", "optional": True},
        },
        "required": ["uuid"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Delete once confirmed.

        Exists so set_dhcp_router_option is reversible. Removing option 3
        strips a subnet's default gateway, and clients keep working until
        their leases renew, so the damage surfaces long after the change.
        """
        params = params or {}
        if not self.client:
            return self._no_client()
        uuid = (params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}

        if not validate_delete_confirm_token(
            "dhcp_option", uuid, str(params.get("confirm") or "")
        ):
            token = issue_delete_confirm_token("dhcp_option", uuid)
            return {
                "status": "confirmation_required",
                "uuid": uuid,
                "confirm_token": token["token"],
                "message": token["message"],
            }

        try:
            await self.client._make_request(
                "POST", f"{DNSMASQ['del_option']}/{uuid}", call_class="write", json={}
            )
            if params.get("apply", False):
                await self._reconfigure()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to delete DHCP option")
            return {"status": "error", "error": str(exc)}
        return {"status": "success", "uuid": uuid, "deleted": True}
