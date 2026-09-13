"""GIF tunnel devices and interface assignment helpers."""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

from opnsense_mcp.utils.apply import ApplyError, run_apply
from opnsense_mcp.utils.mvc_merge import merge_for_set
from opnsense_mcp.utils.shaper_write_helpers import (
    issue_delete_confirm_token,
    validate_delete_confirm_token,
)

logger = logging.getLogger(__name__)

GIF = {
    "search": "/api/interfaces/gif_settings/search_item",
    "get": "/api/interfaces/gif_settings/get_item",
    "add": "/api/interfaces/gif_settings/add_item",
    "set": "/api/interfaces/gif_settings/set_item",
    "delete": "/api/interfaces/gif_settings/del_item",
    "reconfigure": "/api/interfaces/gif_settings/reconfigure",
}

ASSIGNMENT = {
    "search": "/api/interfaces/assignment/search_item",
    "get": "/api/interfaces/assignment/get_item/",
    "add": "/api/interfaces/assignment/add_item",
    "set": "/api/interfaces/assignment/set_item",
    "delete": "/api/interfaces/assignment/del_item",
    "reconfigure": "/api/interfaces/assignment/reconfigure",
}

PRIVILEGE_HINT = (
    "API privilege missing for gif_settings (HTTP 403). Grant the key "
    "Interfaces → Devices → GIF access, then retry."
)


def privilege_error_message() -> str:
    """Return the operator-facing message when gif_settings returns 403."""
    return PRIVILEGE_HINT


_GIF_UPDATE_FIELDS = (
    "parent",
    "remote",
    "tunnel_local",
    "tunnel_remote",
    "tunnel_remote_net",
    "description",
    "ecn",
    "link2",
    "noclamp",
)


def _gif_update_changes(params: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    """Map only caller-supplied update fields to Gif.xml wire keys."""
    changes: dict[str, Any] = {}

    if "parent" in params:
        parent = str(params.get("parent") or "").strip()
        if not parent:
            return {}, "parent cannot be empty"
        try:
            ipaddress.ip_address(parent.split("%", 1)[0])
            changes["ipaddr"] = parent
            changes["if"] = ""
        except ValueError:
            changes["if"] = parent
            changes["ipaddr"] = ""

    for label, key in (
        ("remote", "remote-addr"),
        ("tunnel_local", "tunnel-local-addr"),
        ("tunnel_remote", "tunnel-remote-addr"),
    ):
        if label not in params:
            continue
        addr = str(params.get(label) or "").strip()
        if not addr:
            return {}, f"{label} cannot be empty"
        try:
            _normalize_addr(addr)
        except ValueError:
            return {}, f"{label} {addr!r} is not a valid address"
        changes[key] = addr

    if "tunnel_remote_net" in params:
        tunnel_remote_net = params.get("tunnel_remote_net", 32)
        try:
            net_int = int(tunnel_remote_net)
        except (TypeError, ValueError):
            return {}, f"tunnel_remote_net {tunnel_remote_net!r} is not a number"
        if not 1 <= net_int <= 128:
            return {}, "tunnel_remote_net must be between 1 and 128"
        changes["tunnel-remote-net"] = str(net_int)

    if "description" in params:
        changes["descr"] = str(params.get("description") or "")

    for param, wire_key in (
        ("ecn", "link1"),
        ("link2", "link2"),
        ("noclamp", "noclamp"),
    ):
        if param in params:
            changes[wire_key] = "1" if params.get(param) else "0"

    return changes, None


def gif_params_to_wire(params: dict[str, Any]) -> dict[str, Any]:
    """Map MCP create/update fields to Gif.xml wire keys."""
    parent = str(params.get("parent") or "").strip()
    wire: dict[str, Any] = {
        "remote-addr": str(params.get("remote") or "").strip(),
        "tunnel-local-addr": str(params.get("tunnel_local") or "").strip(),
        "tunnel-remote-addr": str(params.get("tunnel_remote") or "").strip(),
        "tunnel-remote-net": str(params.get("tunnel_remote_net", 32)),
        "descr": str(params.get("description") or ""),
        "link1": "1" if params.get("ecn") else "0",
        "link2": "1" if params.get("link2") else "0",
        "noclamp": "1" if params.get("noclamp") else "0",
    }
    if parent:
        # Interface keys are names; addresses parse as IP.
        try:
            ipaddress.ip_address(parent.split("%", 1)[0])
            wire["ipaddr"] = parent
        except ValueError:
            wire["if"] = parent
    device = str(params.get("device") or "").strip()
    if device:
        wire["gifif"] = device
    return wire


def project_gif_row(row: dict[str, Any]) -> dict[str, Any]:
    """Public list/create projection."""
    parent = row.get("if") or row.get("ipaddr") or ""
    return {
        "uuid": row.get("uuid", ""),
        "device": row.get("gifif", ""),
        "parent": parent,
        "remote": row.get("remote-addr", ""),
        "tunnel_local": row.get("tunnel-local-addr", ""),
        "tunnel_remote": row.get("tunnel-remote-addr", ""),
        "tunnel_remote_net": row.get("tunnel-remote-net", ""),
        "description": row.get("descr", ""),
    }


def _normalize_addr(addr: str) -> str:
    """Return a canonical IP string, or raise ValueError."""
    return str(ipaddress.ip_address(addr.split("%", 1)[0].strip()))


def _row_parent(row: dict[str, Any]) -> str:
    """Parent interface name or address from a search row."""
    return str(row.get("if") or row.get("ipaddr") or "")


def _parent_matches(row: dict[str, Any], parent: str) -> bool:
    """Return True when the row's parent matches the requested parent."""
    row_parent = _row_parent(row)
    if not row_parent:
        return False
    try:
        return _normalize_addr(row_parent) == _normalize_addr(parent)
    except ValueError:
        return row_parent == parent


def _gif_identity_matches(
    row: dict[str, Any],
    parent: str,
    remote: str,
    tunnel_local: str,
    tunnel_remote: str,
) -> bool:
    """Return True when the row describes the same GIF tunnel identity."""
    if not _parent_matches(row, parent):
        return False
    try:
        return (
            _normalize_addr(str(row.get("remote-addr", ""))) == _normalize_addr(remote)
            and _normalize_addr(str(row.get("tunnel-local-addr", "")))
            == _normalize_addr(tunnel_local)
            and _normalize_addr(str(row.get("tunnel-remote-addr", "")))
            == _normalize_addr(tunnel_remote)
        )
    except ValueError:
        return False


def _is_gif_privilege_failure(exc_or_body: Any) -> bool:
    """Return True when gif_settings denied access (HTTP 403)."""
    if isinstance(exc_or_body, dict) and exc_or_body.get("status") == 403:
        return True
    text = str(exc_or_body)
    return "403" in text


class _GifToolBase:
    """Shared client handling for GIF tools."""

    def __init__(self, client: Any) -> None:
        """Store the OPNsense client."""
        self.client = client

    def _no_client(self) -> dict[str, Any]:
        return {"status": "error", "error": "No client available"}

    def _privilege_error(self) -> dict[str, Any]:
        return {"status": "error", "error": privilege_error_message()}

    async def _rows(self, endpoint: str) -> list[dict[str, Any]]:
        data = await self.client._make_request(
            "POST", endpoint, json={"current": 1, "rowCount": 5000}
        )
        if _is_gif_privilege_failure(data):
            raise ValueError(PRIVILEGE_HINT)
        return data.get("rows", []) if isinstance(data, dict) else []

    async def _apply(
        self, params: dict[str, Any], endpoint: str, what: str
    ) -> tuple[bool, str]:
        """Reconfigure as a separate phase after the write."""
        if not params.get("apply", False):
            return False, ""
        try:
            await run_apply(self.client, endpoint)
        except ApplyError as exc:
            logger.warning("%s written but not applied: %s", what, exc)
            return False, str(exc)
        return True, ""

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

    async def _assignment_rows(self) -> list[dict[str, Any]]:
        """Return interface assignment rows."""
        return await self._rows(ASSIGNMENT["search"])


class ListGifTool(_GifToolBase):
    """List GIF tunnel devices."""

    name = "list_gif"
    description = "List GIF tunnel devices"
    input_schema: dict[str, Any] = {"type": "object", "properties": {}, "required": []}

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return each GIF's parent, remote peer, and tunnel endpoints."""
        if not self.client:
            return self._no_client()
        try:
            rows = await self._rows(GIF["search"])
        except Exception as exc:  # noqa: BLE001
            if _is_gif_privilege_failure(exc):
                return self._privilege_error()
            logger.exception("Failed to list GIF devices")
            return {"status": "error", "error": str(exc)}

        gifs = [project_gif_row(row) for row in rows]
        return {"status": "success", "count": len(gifs), "gifs": gifs}


class MkGifTool(_GifToolBase):
    """Create a GIF tunnel device."""

    name = "mk_gif"
    description = "Create a GIF tunnel on a parent interface or address"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "parent": {
                "type": "string",
                "description": "Parent interface name or local address",
            },
            "remote": {"type": "string", "description": "Outer remote peer address"},
            "tunnel_local": {
                "type": "string",
                "description": "Inner local tunnel endpoint",
            },
            "tunnel_remote": {
                "type": "string",
                "description": "Inner remote tunnel endpoint",
            },
            "tunnel_remote_net": {
                "type": "number",
                "description": "Prefix length for tunnel remote (1-128, default 32)",
                "optional": True,
            },
            "device": {
                "type": "string",
                "description": "GIF device name, for example gif0",
                "optional": True,
            },
            "description": {"type": "string", "optional": True},
            "ecn": {"type": "boolean", "optional": True},
            "link2": {"type": "boolean", "optional": True},
            "noclamp": {"type": "boolean", "optional": True},
            "apply": {
                "type": "boolean",
                "description": "Reconfigure GIF devices afterwards (default false)",
                "optional": True,
                "default": False,
            },
        },
        "required": ["parent", "remote", "tunnel_local", "tunnel_remote"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create the device, or return the existing one for this tunnel identity."""
        params = params or {}
        if not self.client:
            return self._no_client()

        parent = str(params.get("parent") or "").strip()
        remote = str(params.get("remote") or "").strip()
        tunnel_local = str(params.get("tunnel_local") or "").strip()
        tunnel_remote = str(params.get("tunnel_remote") or "").strip()
        if not parent or not remote or not tunnel_local or not tunnel_remote:
            return {
                "status": "error",
                "error": "parent, remote, tunnel_local, and tunnel_remote are required",
            }

        for label, addr in (
            ("remote", remote),
            ("tunnel_local", tunnel_local),
            ("tunnel_remote", tunnel_remote),
        ):
            try:
                _normalize_addr(addr)
            except ValueError:
                return {
                    "status": "error",
                    "error": f"{label} {addr!r} is not a valid address",
                }

        tunnel_remote_net = params.get("tunnel_remote_net", 32)
        try:
            net_int = int(tunnel_remote_net)
        except (TypeError, ValueError):
            return {
                "status": "error",
                "error": f"tunnel_remote_net {tunnel_remote_net!r} is not a number",
            }
        if not 1 <= net_int <= 128:
            return {
                "status": "error",
                "error": "tunnel_remote_net must be between 1 and 128",
            }

        try:
            for row in await self._rows(GIF["search"]):
                if _gif_identity_matches(
                    row, parent, remote, tunnel_local, tunnel_remote
                ):
                    return {
                        "status": "success",
                        "created": False,
                        "uuid": row.get("uuid", ""),
                        "device": row.get("gifif", ""),
                        "note": (
                            "This tunnel identity already exists; reused, not replaced."
                        ),
                    }

            wire = gif_params_to_wire({**params, "tunnel_remote_net": net_int})
            result = await self.client._make_request(
                "POST", GIF["add"], call_class="write", json={"gif": wire}
            )
        except Exception as exc:  # noqa: BLE001
            if _is_gif_privilege_failure(exc):
                return self._privilege_error()
            logger.exception("Failed to create GIF")
            return {"status": "error", "error": str(exc)}

        applied, apply_error = await self._apply(params, GIF["reconfigure"], "GIF")

        out: dict[str, Any] = {
            "status": "success",
            "created": True,
            "uuid": result.get("uuid", "") if isinstance(result, dict) else "",
            "applied": applied,
            "note": (
                "Created and reconfigured, so the device exists on the system."
                if applied
                else "Staged. Assign and address the interface separately."
            ),
        }
        if isinstance(result, dict) and result.get("gifif"):
            out["device"] = result["gifif"]
        if apply_error:
            out["apply_error"] = apply_error
        return out


class SetGifTool(_GifToolBase):
    """Update a GIF tunnel device."""

    name = "set_gif"
    description = "Update fields on an existing GIF tunnel device"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "GIF device uuid"},
            "parent": {
                "type": "string",
                "description": "Parent interface name or local address",
                "optional": True,
            },
            "remote": {
                "type": "string",
                "description": "Outer remote peer address",
                "optional": True,
            },
            "tunnel_local": {
                "type": "string",
                "description": "Inner local tunnel endpoint",
                "optional": True,
            },
            "tunnel_remote": {
                "type": "string",
                "description": "Inner remote tunnel endpoint",
                "optional": True,
            },
            "tunnel_remote_net": {
                "type": "number",
                "description": "Prefix length for tunnel remote (1-128)",
                "optional": True,
            },
            "description": {"type": "string", "optional": True},
            "ecn": {"type": "boolean", "optional": True},
            "link2": {"type": "boolean", "optional": True},
            "noclamp": {"type": "boolean", "optional": True},
            "apply": {
                "type": "boolean",
                "description": "Reconfigure GIF devices afterwards (default false)",
                "optional": True,
                "default": False,
            },
        },
        "required": ["uuid"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Read the device, merge caller changes, and write the whole node back."""
        params = params or {}
        if not self.client:
            return self._no_client()
        uuid = (params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}

        if str(params.get("device") or "").strip():
            return {
                "status": "error",
                "error": (
                    "device (gifif) cannot be changed after creation; the firmware "
                    "overlay locks it. Delete and recreate the tunnel instead."
                ),
            }

        changes, error = _gif_update_changes(params)
        if error:
            return {"status": "error", "error": error}
        if not changes:
            return {
                "status": "error",
                "error": (
                    f"nothing to change; pass one of: {', '.join(_GIF_UPDATE_FIELDS)}"
                ),
            }

        try:
            current = await self.client._make_request("GET", f"{GIF['get']}/{uuid}")
            node = current.get("gif", {}) if isinstance(current, dict) else {}
            if not node:
                return {"status": "error", "error": f"GIF {uuid} not found"}

            payload = merge_for_set(node, changes)
            await self.client._make_request(
                "POST",
                f"{GIF['set']}/{uuid}",
                call_class="write",
                json={"gif": payload},
            )
        except Exception as exc:  # noqa: BLE001
            if _is_gif_privilege_failure(exc):
                return self._privilege_error()
            logger.exception("Failed to update GIF")
            return {"status": "error", "error": str(exc)}

        applied, apply_error = await self._apply(params, GIF["reconfigure"], "GIF")
        out: dict[str, Any] = {
            "status": "success",
            "uuid": uuid,
            "changed": sorted(changes),
            "applied": applied,
        }
        if apply_error:
            out["apply_error"] = apply_error
        return out


class RmGifTool(_GifToolBase):
    """Delete a GIF tunnel device."""

    name = "rm_gif"
    description = (
        "Delete a GIF tunnel device; refuses while it is assigned to an interface"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "uuid": {"type": "string", "description": "GIF device uuid"},
            "confirm": {"type": "string", "optional": True},
            "apply": {
                "type": "boolean",
                "description": "Reconfigure GIF devices afterwards (default false)",
                "optional": True,
                "default": False,
            },
        },
        "required": ["uuid"],
    }

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Delete once confirmed, unless an interface assignment still uses it."""
        params = params or {}
        if not self.client:
            return self._no_client()
        uuid = (params.get("uuid") or "").strip()
        if not uuid:
            return {"status": "error", "error": "uuid is required"}

        pending = self._confirm("gif", uuid, params.get("confirm"))
        if pending:
            return pending

        try:
            rows = await self._rows(GIF["search"])
            row = next((r for r in rows if r.get("uuid") == uuid), None)
            if not row:
                return {"status": "error", "error": f"GIF {uuid} not found"}

            device = (row.get("gifif") or "").strip()
            if not device:
                return {
                    "status": "error",
                    "error": f"GIF {uuid} has no device name; cannot check assignments",
                }

            assignment_rows = await self._assignment_rows()
            holders = [
                r.get("identifier") or r.get("uuid")
                for r in assignment_rows
                if (r.get("if") or "") == device
            ]
            if holders:
                return {
                    "status": "error",
                    "error": (
                        f"{device} is assigned to interface {', '.join(holders)}. "
                        f"Unassign it first; deleting the device would take the "
                        f"interface with it."
                    ),
                }

            result = await self.client._make_request(
                "POST", f"{GIF['delete']}/{uuid}", call_class="write", json={}
            )
        except Exception as exc:  # noqa: BLE001
            if _is_gif_privilege_failure(exc):
                return self._privilege_error()
            logger.exception("Failed to delete GIF")
            return {"status": "error", "error": str(exc)}

        if isinstance(result, dict) and result.get("result") == "not found":
            return {
                "status": "error",
                "error": (
                    f"no GIF device with uuid {uuid}. It may already be gone, "
                    f"or the uuid came from an older listing."
                ),
            }

        applied, apply_error = await self._apply(params, GIF["reconfigure"], "GIF")
        out: dict[str, Any] = {
            "status": "success",
            "uuid": uuid,
            "deleted": True,
            "applied": applied,
        }
        if apply_error:
            out["apply_error"] = apply_error
        return out
