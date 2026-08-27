"""Firewall interface groups.

A group names a set of assigned interfaces so one rule can cover all of them.
Adding a network to an existing zone is otherwise a rule-per-interface job,
which is where rule sets drift apart.

Groups hold assigned interfaces only, so a VLAN device that has not been
assigned cannot join one.
"""

from __future__ import annotations

import logging
from typing import Any

from opnsense_mcp.utils.mvc_merge import merge_for_set

logger = logging.getLogger(__name__)

GROUP = {
    "search": "/api/firewall/group/search_item",
    "get": "/api/firewall/group/get_item",
    "set": "/api/firewall/group/set_item",
    "reconfigure": "/api/firewall/group/reconfigure",
}

# openvpn, enc0 and wireguard are provided by the system and keyed by name
# rather than a uuid. A uuid is 36 characters; anything shorter is built in.
UUID_LENGTH = 36


class _GroupToolBase:
    """Shared client handling."""

    def __init__(self, client: Any) -> None:
        """Store the OPNsense client."""
        self.client = client

    def _no_client(self) -> dict[str, Any]:
        return {"status": "error", "error": "No client available"}

    async def _rows(self) -> list[dict[str, Any]]:
        data = await self.client._make_request(
            "POST", GROUP["search"], json={"current": 1, "rowCount": 500}
        )
        return data.get("rows", []) if isinstance(data, dict) else []


def _is_editable(uuid: str) -> bool:
    """Built-in groups are keyed by name, so they have no uuid."""
    return len(uuid) == UUID_LENGTH


class ListFwGroupsTool(_GroupToolBase):
    """List firewall interface groups."""

    name = "list_fw_groups"
    description = "List firewall interface groups and their members"
    input_schema: dict[str, Any] = {"type": "object", "properties": {}, "required": []}

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return the groups, with membership split into a list."""
        if not self.client:
            return self._no_client()
        try:
            rows = await self._rows()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to list firewall groups")
            return {"status": "error", "error": str(exc)}

        groups = []
        for row in rows:
            uuid = row.get("uuid", "")
            members = [m for m in str(row.get("members", "")).split(",") if m]
            groups.append(
                {
                    "uuid": uuid,
                    "ifname": row.get("ifname", ""),
                    "members": members,
                    "member_labels": row.get("%members", ""),
                    "nogroup": row.get("nogroup", ""),
                    "sequence": row.get("sequence", ""),
                    "descr": row.get("descr", ""),
                    # Surfaced rather than left to be discovered on write: the
                    # API accepts a write to a built-in group and drops it.
                    "editable": _is_editable(uuid),
                }
            )
        return {"status": "success", "count": len(groups), "groups": groups}


class SetFwGroupTool(_GroupToolBase):
    """Replace a group's interface membership."""

    name = "set_fw_group"
    description = "Replace the interface membership of a firewall group"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "Group uuid"},
            "members": {
                "type": "array",
                "description": (
                    "Interface keys the group should contain, e.g. "
                    "['opt3', 'opt4']. This replaces the membership rather "
                    "than adding to it."
                ),
                "items": {"type": "string"},
            },
            "descr": {"type": "string", "optional": True},
            "apply": {
                "type": "boolean",
                "description": "Reload the group configuration (default false)",
                "optional": True,
            },
        },
        "required": ["uuid", "members"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Read the group, replace membership, write the whole node back.

        Membership is replaced, not merged, because "the group contains exactly
        these interfaces" is checkable from the arguments alone. A merge would
        make the outcome depend on state the caller cannot see.
        """
        params = params or {}
        if not self.client:
            return self._no_client()

        uuid = (params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}
        members = params.get("members")
        if members is None:
            return {"status": "error", "error": "members is required"}
        if not isinstance(members, list):
            return {"status": "error", "error": "members must be a list of interfaces"}

        if not _is_editable(uuid):
            return {
                "status": "error",
                "error": (
                    f"{uuid!r} is a system group. The API accepts a write to one "
                    f"and discards it, which reads as success. Only groups with a "
                    f"uuid can be edited."
                ),
            }

        try:
            current = await self.client._make_request("GET", f"{GROUP['get']}/{uuid}")
            node = current.get("group", {}) if isinstance(current, dict) else {}
            if not node:
                return {"status": "error", "error": f"group {uuid} not found"}

            changes: dict[str, Any] = {"members": ",".join(members)}
            if "descr" in params:
                changes["descr"] = params["descr"]

            payload = merge_for_set(node, changes)
            await self.client._make_request(
                "POST",
                f"{GROUP['set']}/{uuid}",
                call_class="write",
                json={"group": payload},
            )
            if params.get("apply", False):
                await self.client._make_request(
                    "POST", GROUP["reconfigure"], call_class="apply"
                )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to update firewall group")
            return {"status": "error", "error": str(exc)}

        return {
            "status": "success",
            "uuid": uuid,
            "ifname": node.get("ifname", ""),
            "members": members,
            "note": "Staged. Reload the group configuration to apply it.",
        }
