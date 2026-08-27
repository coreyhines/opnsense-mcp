"""Read-merge-write helpers for OPNsense MVC ``get*`` / ``set*`` round-trips.

OPNsense MVC models render a node differently on read and write:

* enum fields come back as ``{option: {"selected": 0|1, "value": "label"}}`` but
  are written as the bare option key (comma-joined when multi-select);
* keys prefixed with ``%`` are resolved display labels (``"This Firewall"``)
  and must never be posted back;
* scalars come back as strings (``"1"`` / ``"0"`` / ``""``).

A ``set*`` POST replaces the whole node, so any field omitted from the payload
is reset to its model default. Partial updates must therefore fetch the node,
overlay the caller's changes, and write every remaining field back unchanged.

The traffic-shaper modules solved the same problem for their own models; see
:func:`opnsense_mcp.utils.shaper_normalize.selected_enum` and the template merge
described in :mod:`opnsense_mcp.utils.shaper_serialize`. This module generalises
it so any MVC resource can round-trip.

No I/O; no OPNsense API calls.
"""

from __future__ import annotations

from typing import Any

from opnsense_mcp.utils.shaper_normalize import parse_boolish

DISPLAY_PREFIX = "%"


def is_enum_field(value: Any) -> bool:
    """Return True when *value* is an MVC enum object.

    Every option of a real enum carries a ``selected`` flag. Testing only for a
    dict of dicts also matched a parent node's embedded child collections, such
    as quagga/bgp's ``neighbors`` and ``routemaps``, which are separate
    resources with their own endpoints. Posting one back rejects the whole
    write with a 500.
    """
    if not isinstance(value, dict) or not value:
        return False
    return all(isinstance(meta, dict) and "selected" in meta for meta in value.values())


def is_child_collection(value: Any) -> bool:
    """Return True when *value* is an embedded child resource, not a field.

    Anything dict-shaped that is not an enum: the node's own sub-resources,
    which must be left out of a ``set*`` payload entirely.
    """
    return isinstance(value, dict) and not is_enum_field(value)


def selected_keys(field: dict[str, Any]) -> str:
    """Return the selected option key(s), comma-joined for multi-select.

    Empty string when nothing is selected, which is what OPNsense expects for
    an unset optional enum.
    """
    return ",".join(
        key
        for key, meta in field.items()
        if isinstance(meta, dict) and parse_boolish(meta.get("selected"))
    )


def flatten_mvc_node(node: dict[str, Any]) -> dict[str, str]:
    """Collapse a ``get*`` node into the flat form a ``set*`` POST expects.

    Drops ``%``-prefixed display fields and embedded child collections,
    collapses enum objects to their selected key(s), and stringifies scalars.
    """
    flat: dict[str, str] = {}
    for key, value in node.items():
        if key.startswith(DISPLAY_PREFIX):
            continue
        if is_child_collection(value):
            # A sub-resource with its own endpoints. Sending it back rejects
            # the write, so it is dropped rather than stringified.
            continue
        if is_enum_field(value):
            flat[key] = selected_keys(value)
        elif value is None:
            flat[key] = ""
        elif isinstance(value, bool):
            flat[key] = "1" if value else "0"
        else:
            flat[key] = str(value)
    return flat


def merge_for_set(node: dict[str, Any], overrides: dict[str, Any]) -> dict[str, str]:
    """Flatten *node* and overlay *overrides*, preserving every other field."""
    flat = flatten_mvc_node(node)
    for key, value in overrides.items():
        if value is None:
            continue
        if isinstance(value, bool):
            flat[key] = "1" if value else "0"
        else:
            flat[key] = str(value)
    return flat
