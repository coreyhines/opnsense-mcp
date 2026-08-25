"""Shared helpers for the tool-surface contract test and its regenerator.

Kept separate so the regenerator does not import the test module, which reads
the snapshot at collection time and therefore cannot run before it exists.
"""

from __future__ import annotations

import importlib
import inspect
import json
import pkgutil
import re
from pathlib import Path
from typing import Any

import opnsense_mcp.tools as tools_pkg

GOLDEN = Path(__file__).parent / "fixtures" / "tool_surface.json"

# Tools that legitimately take no client, so a registry cannot assume one.
NO_CLIENT_TOOLS = {"packet_capture"}


def _is_tool_class(class_name: str) -> bool:
    """Match tool classes, including suffixed variants such as PacketCaptureTool2."""
    return re.search(r"Tool\d*$", class_name) is not None


def discover_tool_classes() -> dict[str, type]:
    """Every *Tool class that advertises a name, keyed by tool name."""
    found: dict[str, type] = {}
    for mod_info in pkgutil.iter_modules(tools_pkg.__path__):
        try:
            mod = importlib.import_module(f"opnsense_mcp.tools.{mod_info.name}")
        except Exception:  # noqa: BLE001 - optional deps must not break discovery
            continue
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if not _is_tool_class(obj.__name__):
                continue
            name = getattr(obj, "name", None)
            if isinstance(name, str) and name:
                found[name] = obj
    return found


def discover_all_tool_classes() -> dict[str, type]:
    """Every *Tool class, including those with no metadata at all.

    `discover_tool_classes` keys on the tool name, so classes lacking one are
    invisible to it. Those are exactly the classes a registry cannot read, so
    they need their own view.
    """
    found: dict[str, type] = {}
    for mod_info in pkgutil.iter_modules(tools_pkg.__path__):
        try:
            mod = importlib.import_module(f"opnsense_mcp.tools.{mod_info.name}")
        except Exception:  # noqa: BLE001
            continue
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if _is_tool_class(obj.__name__) and obj.__module__ == mod.__name__:
                found[obj.__name__] = obj
    return found


def classes_missing_metadata() -> set[str]:
    """Class names that a registry cannot emit as-is."""
    return {
        cls_name
        for cls_name, cls in discover_all_tool_classes().items()
        if not getattr(cls, "name", None)
        or not getattr(cls, "description", None)
        or getattr(cls, "input_schema", None) is None
    }


def current_surface() -> dict[str, dict[str, Any]]:
    """Name to {description, inputSchema} for every discoverable tool."""
    return {
        name: {
            "description": getattr(cls, "description", "") or "",
            "inputSchema": getattr(cls, "input_schema", None),
        }
        for name, cls in discover_tool_classes().items()
    }


def load_golden() -> dict[str, dict[str, Any]]:
    """The recorded surface, or empty when it has not been generated yet."""
    if not GOLDEN.exists():
        return {}
    return json.loads(GOLDEN.read_text())
