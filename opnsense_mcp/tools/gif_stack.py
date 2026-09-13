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
