"""GIF tunnel devices and interface assignment helpers."""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

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
