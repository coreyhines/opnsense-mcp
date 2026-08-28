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

from opnsense_mcp.utils.apply import ApplyError, run_apply
from opnsense_mcp.utils.mvc_merge import merge_for_set
from opnsense_mcp.utils.shaper_write_helpers import (
    issue_delete_confirm_token,
    validate_delete_confirm_token,
)

logger = logging.getLogger(__name__)

QUAGGA = {
    "general": "/api/quagga/general/get",
    "set_general": "/api/quagga/general/set",
    "bgp": "/api/quagga/bgp/get",
    "set_bgp": "/api/quagga/bgp/set",
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

# What OPNsense ships in the BGP section. It is above the 2-byte private range
# (64512-65534), so inheriting it is a sign nobody chose an AS number.
DEFAULT_AS = "65551"

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

    async def _apply_if_asked(self, params: dict[str, Any]) -> tuple[bool, str]:
        """Apply as a separate phase. Returns (applied, error).

        Deliberately not inside the write's try block: a failure here means the
        write landed and was not applied, which is a different outcome from the
        write failing, and reporting it as the latter is how a delete came to
        report failure after removing the record.
        """
        if not params.get("apply", False):
            return False, ""
        try:
            await run_apply(self.client, QUAGGA["reconfigure"])
        except ApplyError as exc:
            logger.warning("Write succeeded but apply failed: %s", exc)
            return False, str(exc)
        return True, ""


def _on(value: Any) -> bool:
    """OPNsense writes booleans as "0"/"1" strings."""
    return str(value) in {"1", "True", "true"}


def _staging_note(applied: bool, apply_error: str, *, staged: str, done: str) -> str:
    """Describe what actually happened, not what was requested.

    The previous notes branched only on the caller's arguments, so a tool that
    had just tried and failed to reconfigure still told the operator to go and
    reconfigure.
    """
    if apply_error:
        return f"The change was written but not applied: {apply_error}"
    return done if applied else staged


def _join_error(existing: str | None, addition: str) -> str:
    """Accumulate diagnostic errors without losing the earlier one."""
    return f"{existing}; {addition}" if existing else addition


def _has_established_peer(summary: Any) -> bool:
    """Does this bgpsummary response show a peer in state Established?

    Reads the `state` field on peer objects, wherever they nest, rather than
    substring-matching the whole document. The document carries a `desc` field
    that is the caller's own neighbour description, so "peering established 2024"
    matched, blocking every AS change; and an error string mentioning the word
    was read as evidence of the thing it failed to determine.

    A peer object is a dict with a `state`. Everything else is walked through to
    find them.
    """
    if isinstance(summary, dict):
        state = summary.get("state")
        if isinstance(state, str) and state.strip().lower() == "established":
            return True
        return any(_has_established_peer(v) for v in summary.values())
    if isinstance(summary, (list, tuple)):
        return any(_has_established_peer(v) for v in summary)
    return False


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
            # These two are the difference between "BGP is down" and "I could
            # not tell". Swallowing them turned a read timeout on a loaded
            # firewall into a confident "no sessions", on the one tool an
            # operator uses to decide whether peering is up.
            diagnostics_error = None
            try:
                service = await self.client._make_request(
                    "GET", QUAGGA["service_status"]
                )
            except Exception as exc:  # noqa: BLE001
                service = None
                diagnostics_error = _join_error(
                    diagnostics_error, f"service status: {exc}"
                )
            try:
                summary = await self.client._make_request("GET", QUAGGA["summary"])
            except Exception as exc:  # noqa: BLE001
                summary = None
                diagnostics_error = _join_error(
                    diagnostics_error, f"bgp summary: {exc}"
                )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to read BGP status")
            return {"status": "error", "error": str(exc)}

        # A non-dict response (a string, a captive-portal HTML page) is also
        # "could not tell", not a stopped service. Coercing to None silently
        # was the same swallow the excepts above were fixed for.
        if service is not None and not isinstance(service, dict):
            diagnostics_error = _join_error(
                diagnostics_error,
                f"service status: unexpected {type(service).__name__}",
            )
            service = None
        if summary is not None and not isinstance(summary, dict):
            diagnostics_error = _join_error(
                diagnostics_error, f"bgp summary: unexpected {type(summary).__name__}"
            )
            summary = None
        general_node = general.get("general", {}) if isinstance(general, dict) else {}
        bgp_node = bgp.get("bgp", {}) if isinstance(bgp, dict) else {}
        daemons = _selected(general_node.get("daemons"))

        frr_enabled = _on(general_node.get("enabled"))
        bgp_enabled = _on(bgp_node.get("enabled"))
        daemon_selected = "bgp" in daemons
        # None, not False: an unread status is not a stopped service.
        running = (
            None if service is None else str(service.get("status", "")) == "running"
        )

        notes = []
        if diagnostics_error:
            notes.append(f"Some diagnostics could not be read: {diagnostics_error}.")
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
            "diagnostics_error": diagnostics_error,
            "as_number": bgp_node.get("asnumber", ""),
            "router_id": bgp_node.get("routerid", ""),
            "neighbor_count": len(neighbors),
            "sessions": summary.get("response", []) if summary is not None else None,
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
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to create BGP neighbour")
            return {"status": "error", "error": str(exc)}

        applied, apply_error = await self._apply_if_asked(params)
        out = {
            "status": "success",
            "created": True,
            "uuid": result.get("uuid", "") if isinstance(result, dict) else "",
            "enabled": bool(params.get("enabled")),
            "applied": applied,
            "note": _staging_note(
                applied,
                apply_error,
                staged="Staged and disabled. Enable it and apply when the peer is ready."
                if not params.get("enabled")
                else "Enabled but not applied. Apply to bring the session up.",
                done="Applied."
                if params.get("enabled")
                else "Applied, and the neighbour is disabled until you enable it.",
            ),
        }
        if apply_error:
            out["apply_error"] = apply_error
        return out


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
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to toggle BGP neighbour")
            return {"status": "error", "error": str(exc)}
        applied, apply_error = await self._apply_if_asked(params)
        out = {
            "status": "success",
            "uuid": uuid,
            "enabled": bool(params["enabled"]),
            "applied": applied,
        }
        if apply_error:
            out["apply_error"] = apply_error
        return out


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
            result = await self.client._make_request(
                "POST", f"{QUAGGA['del_neighbor']}/{uuid}", call_class="write", json={}
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to delete BGP neighbour")
            return {"status": "error", "error": str(exc)}

        # delBase answers an unknown uuid with {"result": "not found"} at HTTP
        # 200, which the client does not raise on. rm_gateway and rm_loopback
        # both check for this; reporting a deletion that did not happen tells
        # the operator a peer is gone while it is still peering.
        if isinstance(result, dict) and result.get("result") == "not found":
            return {
                "status": "error",
                "error": (
                    f"no BGP neighbour with uuid {uuid}; it may already be gone, "
                    f"or the uuid came from an older listing."
                ),
            }
        applied, apply_error = await self._apply_if_asked(params)
        out = {"status": "success", "uuid": uuid, "deleted": True, "applied": applied}
        if apply_error:
            out["apply_error"] = apply_error
        return out


class SetBgpGlobalTool(_BgpToolBase):
    """Enable BGP, and set the AS number and router id."""

    name = "set_bgp_global"
    description = (
        "Enable or disable BGP and set the AS number and router id. Handles all "
        "three switches that gate a session, not one of them"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "enabled": {
                "type": "boolean",
                "description": (
                    "Turn BGP on or off: FRR itself, the bgp daemon, and the BGP "
                    "section together"
                ),
                "optional": True,
            },
            "as_number": {
                "type": "string",
                "description": "Local AS number. Required the first time BGP is enabled",
                "optional": True,
            },
            "router_id": {
                "type": "string",
                "description": "Router id, conventionally a loopback address",
                "optional": True,
            },
            "apply": {
                "type": "boolean",
                "description": (
                    "Reconfigure FRR, which restarts it and drops every "
                    "established session (default false)"
                ),
                "optional": True,
            },
        },
        "required": [],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Write the global switches, reading and merging both nodes first.

        BGP needs three separate things on: FRR, the `bgp` daemon in the daemon
        list, and the BGP section. Setting one of them is the most common way to
        end up with a configuration that looks enabled and peers with nobody, so
        `enabled` moves all three together.

        `daemons` is a multi-select, and writing it replaces the whole list, so
        the other daemons are read and carried through rather than dropped.
        """
        params = params or {}
        if not self.client:
            return self._no_client()

        enabled = params.get("enabled")
        as_number = str(params.get("as_number") or "").strip()
        router_id = str(params.get("router_id") or "").strip()

        if enabled is None and not as_number and not router_id:
            return {
                "status": "error",
                "error": "nothing to change; pass enabled, as_number or router_id",
            }

        try:
            general_doc = await self.client._make_request("GET", QUAGGA["general"])
            bgp_doc = await self.client._make_request("GET", QUAGGA["bgp"])
            general = (
                general_doc.get("general", {}) if isinstance(general_doc, dict) else {}
            )
            bgp = bgp_doc.get("bgp", {}) if isinstance(bgp_doc, dict) else {}

            # The AS number appears in every OPEN message, so changing it makes
            # each peer renegotiate from scratch.
            if as_number and as_number != str(bgp.get("asnumber", "")):
                try:
                    summary = await self.client._make_request("GET", QUAGGA["summary"])
                except Exception as exc:  # noqa: BLE001
                    # Failing open defeats the guard. An unreadable session list
                    # is not evidence that there are no sessions.
                    return {
                        "status": "error",
                        "error": (
                            f"refusing to change the AS number: could not read "
                            f"the current sessions to check whether any are "
                            f"Established ({exc}). Retry, or disable BGP first "
                            f"if a reset is intended."
                        ),
                    }
                if _has_established_peer(summary):
                    return {
                        "status": "error",
                        "error": (
                            "refusing to change the AS number while sessions are "
                            "Established: it is carried in every OPEN message, so "
                            "every peer would reset. Disable BGP first if that is "
                            "intended."
                        ),
                    }

            effective_as = as_number or str(bgp.get("asnumber", ""))
            if enabled and not effective_as:
                return {
                    "status": "error",
                    "error": "as_number is required to enable BGP",
                }
            if enabled and not as_number and effective_as == DEFAULT_AS:
                return {
                    "status": "error",
                    "error": (
                        f"as_number is required: the configured value {DEFAULT_AS} is "
                        f"the shipped default and sits outside the 2-byte private "
                        f"range, so it is almost certainly not intended."
                    ),
                }

            daemons = set(_selected(general.get("daemons")))
            general_changes: dict[str, Any] = {}
            bgp_changes: dict[str, Any] = {}

            # Disabling BGP must not stop the daemons sharing the service.
            # Clearing general.enabled stops FRR wholesale, so where others
            # remain selected the bgp daemon is deselected and FRR left up;
            # only when bgp is the last one does the service itself stop.
            others_remain = enabled is False and bool(daemons - {"bgp"})

            if enabled is not None:
                daemons = daemons | {"bgp"} if enabled else daemons - {"bgp"}
                general_changes["enabled"] = "1" if (enabled or others_remain) else "0"
                general_changes["daemons"] = ",".join(sorted(daemons))
                bgp_changes["enabled"] = "1" if enabled else "0"
            if as_number:
                bgp_changes["asnumber"] = as_number
            if router_id:
                bgp_changes["routerid"] = router_id

            # Both payloads are built before either is sent. These are two
            # endpoints and cannot be one transaction, but a payload the model
            # rejects should not first leave FRR enabled with the wrong AS,
            # which is what happened when the BGP write 500'd on its own.
            writes = []
            if general_changes:
                writes.append(
                    (
                        QUAGGA["set_general"],
                        {"general": merge_for_set(general, general_changes)},
                    )
                )
            if bgp_changes:
                writes.append(
                    (QUAGGA["set_bgp"], {"bgp": merge_for_set(bgp, bgp_changes)})
                )

            done: list[str] = []
            for endpoint, payload in writes:
                try:
                    await self.client._make_request(
                        "POST", endpoint, call_class="write", json=payload
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.exception("BGP global write failed at %s", endpoint)
                    return {
                        "status": "error",
                        "error": (
                            f"write to {endpoint} failed: {exc}. "
                            + (
                                f"Already written: {', '.join(done)}. The "
                                f"configuration is now inconsistent; re-run once "
                                f"the cause is fixed."
                                if done
                                else "Nothing was changed."
                            )
                        ),
                    }
                done.append(endpoint)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to set BGP globals")
            return {"status": "error", "error": str(exc)}

        applied, apply_error = await self._apply_if_asked(params)
        out = {
            "status": "success",
            "enabled": enabled,
            "as_number": effective_as,
            "router_id": router_id or bgp.get("routerid", ""),
            "daemons": sorted(daemons),
            "frr_left_running": others_remain,
            "applied": applied,
            "note": _staging_note(
                applied,
                apply_error,
                staged=(
                    f"Staged. BGP disabled; FRR stays up for "
                    f"{', '.join(sorted(daemons))}. Apply to act on it."
                    if others_remain
                    else "Staged. Apply to act on it."
                ),
                done="Applied; FRR was restarted.",
            ),
        }
        if apply_error:
            out["apply_error"] = apply_error
        return out
