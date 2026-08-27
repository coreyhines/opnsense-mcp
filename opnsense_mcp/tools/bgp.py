"""FRR BGP: reading state, and managing neighbours.

FRR ships as the os-frr plugin and is commonly installed but switched off, which
is the state on the target firewall: `general.enabled` and `bgp.enabled` are both
"0" and no daemons are selected. So "off" has to read as a clear answer rather
than an error, because seeing what is configured before enabling anything is the
whole point of the read tools.

Two things about this model are worth knowing before writing to it.

A neighbour defaults to `enabled: "1"`. Creating one therefore means "start
trying to establish a session", which is a live network action rather than a
staged change, so these tools default it off and make the caller ask.

There are two ways to say who the peer is: a numeric `remoteas`, or
`remote_as_mode` set to internal or external, which derives it from the local
AS. The model accepts neither being set, and a neighbour configured that way is
silently inert.
"""

from __future__ import annotations

import logging
from typing import Any

from opnsense_mcp.utils.shaper_write_helpers import (
    issue_delete_confirm_token,
    validate_delete_confirm_token,
)

logger = logging.getLogger(__name__)

QUAGGA = {
    "general": "/api/quagga/general/get",
    "bgp": "/api/quagga/bgp/get",
    "search_neighbor": "/api/quagga/bgp/searchNeighbor",
    "get_neighbor": "/api/quagga/bgp/getNeighbor",
    "add_neighbor": "/api/quagga/bgp/addNeighbor",
    "set_neighbor": "/api/quagga/bgp/setNeighbor",
    "del_neighbor": "/api/quagga/bgp/delNeighbor",
    "toggle_neighbor": "/api/quagga/bgp/toggleNeighbor",
    "summary": "/api/quagga/diagnostics/bgpsummary",
    "service_status": "/api/quagga/service/status",
    "reconfigure": "/api/quagga/service/reconfigure",
}

AS_MODES = ("internal", "external")

# Everything except the password, which the model stores in clear.
_NEIGHBOR_FIELDS = (
    "uuid",
    "enabled",
    "address",
    "remoteas",
    "remote_as_mode",
    "localas",
    "description",
    "updatesource",
    "linklocalinterface",
    "multihop",
    "multiprotocol",
    "nexthopself",
    "bfd",
    "weight",
    "keepalive",
    "holddown",
)


class _BgpToolBase:
    """Shared client handling."""

    def __init__(self, client: Any) -> None:
        """Store the OPNsense client."""
        self.client = client

    def _no_client(self) -> dict[str, Any]:
        return {"status": "error", "error": "No client available"}

    async def _neighbors(self) -> list[dict[str, Any]]:
        data = await self.client._make_request(
            "POST", QUAGGA["search_neighbor"], json={"current": 1, "rowCount": 5000}
        )
        return data.get("rows", []) if isinstance(data, dict) else []

    async def _reconfigure(self) -> None:
        await self.client._make_request(
            "POST", QUAGGA["reconfigure"], call_class="apply"
        )


def _on(value: Any) -> bool:
    """OPNsense writes booleans as "0"/"1" strings."""
    return str(value) in {"1", "True", "true"}


def _selected(field: Any) -> list[str]:
    """Which keys of an enum object are selected."""
    if not isinstance(field, dict):
        return []
    return [
        k for k, v in field.items() if isinstance(v, dict) and _on(v.get("selected"))
    ]


class BgpStatusTool(_BgpToolBase):
    """Read whether BGP is running and how it is configured."""

    name = "bgp_status"
    description = "Report FRR and BGP state: enabled, running, AS number, peer count"
    input_schema: dict[str, Any] = {"type": "object", "properties": {}, "required": []}

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Gather the several places FRR records whether BGP is actually on.

        Three switches have to line up: FRR itself, the bgp daemon being
        selected, and the BGP section. Any one of them off means no sessions,
        and the UI shows them on different pages, so they are reported together
        here.
        """
        if not self.client:
            return self._no_client()

        try:
            general = await self.client._make_request("GET", QUAGGA["general"])
            bgp = await self.client._make_request("GET", QUAGGA["bgp"])
            neighbors = await self._neighbors()
            try:
                service = await self.client._make_request(
                    "GET", QUAGGA["service_status"]
                )
            except Exception:  # noqa: BLE001 - absent on some builds
                service = {}
            try:
                summary = await self.client._make_request("GET", QUAGGA["summary"])
            except Exception:  # noqa: BLE001
                summary = {}
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to read BGP status")
            return {"status": "error", "error": str(exc)}

        general_node = general.get("general", {}) if isinstance(general, dict) else {}
        bgp_node = bgp.get("bgp", {}) if isinstance(bgp, dict) else {}
        daemons = _selected(general_node.get("daemons"))

        frr_enabled = _on(general_node.get("enabled"))
        bgp_enabled = _on(bgp_node.get("enabled"))
        daemon_selected = "bgp" in daemons
        running = str(service.get("status", "")) == "running"

        notes = []
        if not frr_enabled:
            notes.append("FRR itself is disabled, so nothing is running.")
        elif not daemon_selected:
            notes.append(
                "FRR is enabled but the bgp daemon is not selected, so BGP is "
                "configured and not running."
            )
        elif not bgp_enabled:
            notes.append("The bgp daemon is selected but the BGP section is disabled.")

        return {
            "status": "success",
            "frr_enabled": frr_enabled,
            "bgp_enabled": bgp_enabled,
            "bgp_daemon_selected": daemon_selected,
            "daemons_selected": daemons,
            "running": running,
            "as_number": bgp_node.get("asnumber", ""),
            "router_id": bgp_node.get("routerid", ""),
            "neighbor_count": len(neighbors),
            "sessions": summary.get("response", [])
            if isinstance(summary, dict)
            else [],
            "note": " ".join(notes) or "FRR is enabled and the bgp daemon is selected.",
        }


class ListBgpNeighborsTool(_BgpToolBase):
    """List configured BGP neighbours."""

    name = "list_bgp_neighbors"
    description = "List BGP neighbours and their settings"
    input_schema: dict[str, Any] = {"type": "object", "properties": {}, "required": []}

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return the neighbours, without the MD5 secret.

        The model stores `password` in clear and the search endpoint returns
        it. Listing peers is an ordinary read, so it reports whether a password
        is set rather than what it is.
        """
        if not self.client:
            return self._no_client()
        try:
            rows = await self._neighbors()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to list BGP neighbours")
            return {"status": "error", "error": str(exc)}

        neighbors = []
        for row in rows:
            entry = {field: row.get(field, "") for field in _NEIGHBOR_FIELDS}
            entry["password_set"] = bool(str(row.get("password", "")).strip())
            neighbors.append(entry)
        return {"status": "success", "count": len(neighbors), "neighbors": neighbors}


class MkBgpNeighborTool(_BgpToolBase):
    """Create a BGP neighbour."""

    name = "mk_bgp_neighbor"
    description = (
        "Create a BGP neighbour. Created disabled unless asked otherwise, "
        "because an enabled neighbour starts trying to peer immediately"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "address": {"type": "string", "description": "Peer address"},
            "remote_as": {
                "type": "string",
                "description": "Peer AS number. Give this or remote_as_mode, not both",
                "optional": True,
            },
            "remote_as_mode": {
                "type": "string",
                "description": (
                    "internal or external, deriving the peer AS from the local one"
                ),
                "optional": True,
            },
            "enabled": {
                "type": "boolean",
                "description": (
                    "Start peering now. Defaults to false so the neighbour is "
                    "staged rather than brought up"
                ),
                "optional": True,
            },
            "update_source": {
                "type": "string",
                "description": "Interface to source the session from, e.g. lo0",
                "optional": True,
            },
            "multihop": {
                "type": "boolean",
                "description": "Peer is not on a directly connected subnet",
                "optional": True,
            },
            "bfd": {
                "type": "boolean",
                "description": "Use BFD for fast failure detection",
                "optional": True,
            },
            "password": {
                "type": "string",
                "description": "MD5 session password; stored in clear by OPNsense",
                "optional": True,
            },
            "description": {"type": "string", "optional": True},
            "apply": {
                "type": "boolean",
                "description": "Reconfigure FRR, which restarts it (default false)",
                "optional": True,
            },
        },
        "required": ["address"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create the neighbour, keyed on peer address."""
        params = params or {}
        if not self.client:
            return self._no_client()

        address = (params.get("address") or "").strip()
        if not address:
            return {"status": "error", "error": "address is required"}

        remote_as = str(params.get("remote_as") or "").strip()
        mode = (params.get("remote_as_mode") or "").strip()

        if remote_as and mode:
            return {
                "status": "error",
                "error": (
                    "give remote_as or remote_as_mode, not both. The mode derives "
                    "the peer AS from the local one, so setting both states two "
                    "different things."
                ),
            }
        if not remote_as and not mode:
            return {
                "status": "error",
                "error": (
                    "one of remote_as or remote_as_mode is required. The model "
                    "accepts a neighbour with neither and it never establishes."
                ),
            }
        if mode and mode not in AS_MODES:
            return {
                "status": "error",
                "error": f"remote_as_mode must be one of: {', '.join(AS_MODES)}",
            }

        try:
            for row in await self._neighbors():
                if row.get("address") == address:
                    return {
                        "status": "success",
                        "created": False,
                        "uuid": row.get("uuid", ""),
                        "note": f"A neighbour for {address} already exists.",
                    }

            payload = {
                # Off unless asked. The API default is "1", which would start a
                # session attempt the moment FRR next reloads.
                "enabled": "1" if params.get("enabled") else "0",
                "address": address,
                "remoteas": remote_as,
                "remote_as_mode": mode,
                "description": params.get("description", ""),
                "updatesource": params.get("update_source", ""),
                "multihop": "1" if params.get("multihop") else "0",
                "bfd": "1" if params.get("bfd") else "0",
                "password": params.get("password", ""),
            }
            result = await self.client._make_request(
                "POST",
                QUAGGA["add_neighbor"],
                call_class="write",
                json={"neighbor": payload},
            )
            if params.get("apply", False):
                await self._reconfigure()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to create BGP neighbour")
            return {"status": "error", "error": str(exc)}

        return {
            "status": "success",
            "created": True,
            "uuid": result.get("uuid", "") if isinstance(result, dict) else "",
            "enabled": bool(params.get("enabled")),
            "note": (
                "Staged and disabled. Enable it and reconfigure FRR when the peer "
                "is ready."
                if not params.get("enabled")
                else "Enabled. Reconfigure FRR to bring the session up."
            ),
        }


class ToggleBgpNeighborTool(_BgpToolBase):
    """Enable or disable a BGP neighbour."""

    name = "toggle_bgp_neighbor"
    description = "Enable or disable a BGP neighbour"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "Neighbour uuid"},
            "enabled": {"type": "boolean", "description": "Target state"},
            "apply": {"type": "boolean", "optional": True},
        },
        "required": ["uuid", "enabled"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Set the neighbour to an explicit state."""
        params = params or {}
        if not self.client:
            return self._no_client()
        uuid = (params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}
        if params.get("enabled") is None:
            return {"status": "error", "error": "enabled is required"}

        state = "1" if params["enabled"] else "0"
        try:
            await self.client._make_request(
                "POST",
                f"{QUAGGA['toggle_neighbor']}/{uuid}/{state}",
                call_class="write",
            )
            if params.get("apply", False):
                await self._reconfigure()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to toggle BGP neighbour")
            return {"status": "error", "error": str(exc)}
        return {"status": "success", "uuid": uuid, "enabled": bool(params["enabled"])}


class RmBgpNeighborTool(_BgpToolBase):
    """Delete a BGP neighbour."""

    name = "rm_bgp_neighbor"
    description = "Delete a BGP neighbour; requires a confirm token"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "Neighbour uuid"},
            "confirm": {"type": "string", "optional": True},
            "apply": {"type": "boolean", "optional": True},
        },
        "required": ["uuid"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Delete once confirmed.

        Removing a neighbour withdraws every prefix learned from it, which on a
        border can be the whole default route.
        """
        params = params or {}
        if not self.client:
            return self._no_client()
        uuid = (params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}

        if not validate_delete_confirm_token(
            "bgp_neighbor", uuid, str(params.get("confirm") or "")
        ):
            token = issue_delete_confirm_token("bgp_neighbor", uuid)
            return {
                "status": "confirmation_required",
                "uuid": uuid,
                "confirm_token": token["token"],
                "message": token["message"],
            }

        try:
            await self.client._make_request(
                "POST", f"{QUAGGA['del_neighbor']}/{uuid}", call_class="write", json={}
            )
            if params.get("apply", False):
                await self._reconfigure()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to delete BGP neighbour")
            return {"status": "error", "error": str(exc)}
        return {"status": "success", "uuid": uuid, "deleted": True}
