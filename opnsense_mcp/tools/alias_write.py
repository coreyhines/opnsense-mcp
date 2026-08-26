"""Create, update, toggle and delete firewall aliases.

Aliases are named groups of hosts, networks, ports or countries that firewall
and NAT rules reference by name. The existing `aliases` tool only searches; this
adds the write side, which the routing work needs for its source groups.

Updates read the whole node, merge the caller's changes and write it back.
A partial POST to an MVC model blanks every field it omits, which is how
`set_fw_rule` silently widened rules before it was fixed.
"""

from __future__ import annotations

import logging
from typing import Any

from opnsense_mcp.utils.mvc_merge import flatten_mvc_node
from opnsense_mcp.utils.shaper_write_helpers import (
    issue_delete_confirm_token,
    validate_delete_confirm_token,
)

logger = logging.getLogger(__name__)

ENDPOINTS = {
    "search": "/api/firewall/alias/searchItem",
    "get": "/api/firewall/alias/getItem",
    "add": "/api/firewall/alias/addItem",
    "set": "/api/firewall/alias/setItem",
    "delete": "/api/firewall/alias/delItem",
    "toggle": "/api/firewall/alias/toggleItem",
    "reconfigure": "/api/firewall/alias/reconfigure",
}

# Alias types OPNsense accepts. Rejecting early gives a better message than the
# validation error the API returns.
ALIAS_TYPES = (
    "host",
    "network",
    "port",
    "url",
    "urltable",
    "geoip",
    "networkgroup",
    "mac",
    "asn",
    "dynipv6host",
    "authgroup",
    "internal",
    "external",
)

# Read-only or credential fields. Never written back, never returned.
_COMPUTED_FIELDS = frozenset(
    {
        "counters",
        "current_items",
        "last_updated",
        "in_block_b",
        "in_block_p",
        "in_pass_b",
        "in_pass_p",
        "out_block_b",
        "out_block_p",
        "out_pass_b",
        "out_pass_p",
    }
)
_SECRET_FIELDS = frozenset({"username", "password"})


def _safe_summary(row: dict[str, Any]) -> dict[str, Any]:
    """The fields worth returning for an alias, with credentials removed."""
    return {
        key: value
        for key, value in row.items()
        if key in {"uuid", "name", "type", "description", "enabled", "content"}
    }


class _AliasToolBase:
    """Shared lookup, apply and error handling."""

    def __init__(self, client: Any) -> None:
        """Store the OPNsense client."""
        self.client = client

    def _no_client(self) -> dict[str, Any]:
        return {"status": "error", "error": "No client available"}

    async def _find_by_name(self, name: str) -> dict[str, Any] | None:
        """Return the alias row with this name, if it exists."""
        data = await self.client._make_request(
            "POST", ENDPOINTS["search"], json={"current": 1, "rowCount": 5000}
        )
        rows = data.get("rows", []) if isinstance(data, dict) else []
        for row in rows:
            if row.get("name") == name:
                return row
        return None

    async def _reconfigure(self) -> None:
        await self.client._make_request(
            "POST", ENDPOINTS["reconfigure"], call_class="apply"
        )


class MkAliasTool(_AliasToolBase):
    """Create a firewall alias."""

    name = "mk_alias"
    description = (
        "Create a firewall alias; returns the existing one if the name is taken"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Alias name"},
            "type": {
                "type": "string",
                "description": f"Alias type, one of: {', '.join(ALIAS_TYPES)}",
            },
            "content": {
                "type": "array",
                "description": "Members: addresses, networks, ports or codes",
            },
            "description": {"type": "string", "optional": True},
            "apply": {
                "type": "boolean",
                "description": "Reconfigure aliases afterwards (default true)",
                "optional": True,
            },
        },
        "required": ["name", "type", "content"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create the alias, or return the existing one with the same name."""
        params = params or {}
        if not self.client:
            return self._no_client()

        alias_name = (params.get("name") or "").strip()
        alias_type = (params.get("type") or "").strip()
        content = params.get("content")

        if not alias_name:
            return {"status": "error", "error": "name is required"}
        if alias_type not in ALIAS_TYPES:
            return {
                "status": "error",
                "error": f"unknown type {alias_type!r}; expected one of: "
                + ", ".join(ALIAS_TYPES),
            }
        if not content:
            return {"status": "error", "error": "content is required"}

        try:
            existing = await self._find_by_name(alias_name)
            if existing:
                return {
                    "status": "success",
                    "created": False,
                    "uuid": existing.get("uuid", ""),
                    "alias": _safe_summary(existing),
                    "note": "An alias with this name already exists; nothing changed.",
                }

            members = content if isinstance(content, list) else [content]
            payload = {
                "name": alias_name,
                "type": alias_type,
                "content": "\n".join(str(item) for item in members),
                "description": params.get("description", ""),
                "enabled": "1",
            }
            result = await self.client._make_request(
                "POST", ENDPOINTS["add"], call_class="write", json={"alias": payload}
            )
            if params.get("apply", True):
                await self._reconfigure()
        except Exception as exc:  # noqa: BLE001 - surfaced to the caller
            logger.exception("Failed to create alias")
            return {"status": "error", "error": str(exc)}

        return {
            "status": "success",
            "created": True,
            "uuid": result.get("uuid", "") if isinstance(result, dict) else "",
            "name": alias_name,
        }


class SetAliasTool(_AliasToolBase):
    """Update an existing alias, preserving fields not being changed."""

    name = "set_alias"
    description = "Update a firewall alias; unspecified fields keep their values"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "Alias uuid"},
            "content": {
                "type": "array",
                "description": "Replacement members; omit to keep the current set",
                "optional": True,
            },
            "description": {"type": "string", "optional": True},
            "enabled": {"type": "boolean", "optional": True},
            "apply": {
                "type": "boolean",
                "description": "Reconfigure aliases afterwards (default true)",
                "optional": True,
            },
        },
        "required": ["uuid"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Fetch the alias, overlay the caller's changes, write it back."""
        params = params or {}
        if not self.client:
            return self._no_client()

        uuid = (params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}

        try:
            current = await self.client._make_request(
                "GET", f"{ENDPOINTS['get']}/{uuid}"
            )
            node = current.get("alias") if isinstance(current, dict) else None
            if not isinstance(node, dict):
                return {"status": "error", "error": f"alias {uuid} not found"}

            payload = flatten_mvc_node(node)
            for field in _COMPUTED_FIELDS:
                payload.pop(field, None)

            # flatten_mvc_node comma-joins multi-selects, but the alias model
            # reads `content` as newline-separated entries and treats a
            # comma-joined string as a single malformed member. Live check:
            # 'Entry "192.0.2.0/24,198.51.100.0/24" is not a network.'
            if payload.get("content"):
                payload["content"] = "\n".join(
                    part for part in payload["content"].split(",") if part
                )

            if "content" in params and params["content"] is not None:
                members = params["content"]
                if not isinstance(members, list):
                    members = [members]
                payload["content"] = "\n".join(str(item) for item in members)
            if params.get("description") is not None:
                payload["description"] = params["description"]
            if params.get("enabled") is not None:
                payload["enabled"] = "1" if params["enabled"] else "0"

            await self.client._make_request(
                "POST",
                f"{ENDPOINTS['set']}/{uuid}",
                call_class="write",
                json={"alias": payload},
            )
            if params.get("apply", True):
                await self._reconfigure()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to update alias")
            return {"status": "error", "error": str(exc)}

        return {
            "status": "success",
            "uuid": uuid,
            "name": payload.get("name", ""),
            "updated": sorted(
                key
                for key in ("content", "description", "enabled")
                if params.get(key) is not None
            ),
        }


class ToggleAliasTool(_AliasToolBase):
    """Enable or disable an alias."""

    name = "toggle_alias"
    description = "Enable or disable a firewall alias"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "Alias uuid"},
            "enabled": {
                "type": "boolean",
                "description": "Target state; this is not a blind flip",
            },
            "apply": {
                "type": "boolean",
                "description": "Reconfigure aliases afterwards (default true)",
                "optional": True,
            },
        },
        "required": ["uuid", "enabled"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Set the alias to an explicit state.

        The target state is required rather than flipping whatever is there: a
        blind toggle that times out and gets retried ends up back where it
        started while reporting success.
        """
        params = params or {}
        if not self.client:
            return self._no_client()

        uuid = (params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}
        if params.get("enabled") is None:
            return {
                "status": "error",
                "error": "enabled is required; pass the target state, not a flip",
            }

        state = "1" if params["enabled"] else "0"
        try:
            await self.client._make_request(
                "POST",
                f"{ENDPOINTS['toggle']}/{uuid}/{state}",
                call_class="write",
            )
            if params.get("apply", True):
                await self._reconfigure()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to toggle alias")
            return {"status": "error", "error": str(exc)}

        return {"status": "success", "uuid": uuid, "enabled": bool(params["enabled"])}


class RmAliasTool(_AliasToolBase):
    """Delete an alias, with confirmation."""

    name = "rm_alias"
    description = "Delete a firewall alias; requires a confirm token from a prior call"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "Alias uuid"},
            "confirm": {
                "type": "string",
                "description": "Token returned by the first call",
                "optional": True,
            },
            "apply": {
                "type": "boolean",
                "description": "Reconfigure aliases afterwards (default true)",
                "optional": True,
            },
        },
        "required": ["uuid"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Delete the alias once a matching confirm token is supplied.

        Rules that reference a deleted alias stop matching what the operator
        expects, so the two-step applies here as it does for shaper deletes.
        """
        params = params or {}
        if not self.client:
            return self._no_client()

        uuid = (params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}

        confirm = params.get("confirm")
        if not validate_delete_confirm_token("alias", uuid, str(confirm or "")):
            token = issue_delete_confirm_token("alias", uuid)
            return {
                "status": "confirmation_required",
                "uuid": uuid,
                "confirm_token": token["token"],
                "message": token["message"],
            }

        try:
            await self.client._make_request(
                "POST", f"{ENDPOINTS['delete']}/{uuid}", call_class="write", json={}
            )
            if params.get("apply", True):
                await self._reconfigure()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to delete alias")
            return {"status": "error", "error": str(exc)}

        return {"status": "success", "uuid": uuid, "deleted": True}
