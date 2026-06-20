"""Serialize flat agent-view shaper models to OPNsense GUI POST payloads.

Inverse of :mod:`opnsense_mcp.utils.shaper_normalize`. The OPNsense
``settings/set`` write path mirrors the GUI ``settings/get`` shape: enum
fields are objects ``{option: {"selected": 0|1, "value": "label"}}`` and
booleans/ints are strings (``"1"``/``"0"``, ``""`` for empty optionals).

When a *template* (a fetched ``get_*`` subtree or a ``settings/get`` entry) is
provided, keys absent from the flat model are preserved and enum option sets
(with their human-readable ``value`` labels) are reused — only the ``selected``
flag is flipped to match the flat record.

No I/O; no OPNsense API calls.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from opnsense_mcp.utils.shaper_types import (
        FlatShaperPipe,
        FlatShaperQueue,
        FlatShaperRule,
    )

# ---------------------------------------------------------------------------
# Canonical enum option sets (key -> GUI label), used when no template exists
# ---------------------------------------------------------------------------

BANDWIDTH_METRIC_OPTIONS: dict[str, str] = {
    "bit": "bit/s",
    "Kbit": "Kbit/s",
    "Mbit": "Mbit/s",
    "Gbit": "Gbit/s",
}

MASK_OPTIONS: dict[str, str] = {
    "none": "none",
    "src-ip": "source IP",
    "dst-ip": "destination IP",
}

SCHEDULER_OPTIONS: dict[str, str] = {
    "fq_codel": "FQ-CoDel",
    "fifo": "FIFO",
    "fq_pie": "FQ-PIE",
    "qfq": "QFQ",
    "rr": "RR",
    "drr": "DRR",
    "wfq": "WFQ",
    "codel": "CoDel",
    "pie": "PIE",
}

DIRECTION_OPTIONS: dict[str, str] = {
    "in": "in",
    "out": "out",
}

PROTO_OPTIONS: dict[str, str] = {
    "ip": "IP",
    "ip6": "IPv6",
    "tcp": "TCP",
    "udp": "UDP",
}


# ---------------------------------------------------------------------------
# Scalar helpers
# ---------------------------------------------------------------------------


def _bool_str(val: Any) -> str:
    """Encode a boolish value as OPNsense ``"1"``/``"0"``."""
    return "1" if val else "0"


def _int_or_empty(val: int | None) -> str:
    """Encode an optional int: ``None`` -> ``""`` (OPNsense default), else str."""
    if val is None or val == "":
        return ""
    return str(val)


# ---------------------------------------------------------------------------
# Enum-field helpers
# ---------------------------------------------------------------------------


def make_enum_field(options: dict[str, str], selected_key: str) -> dict[str, dict]:
    """Build a GUI enum dict from *options*, marking *selected_key* selected.

    Each option becomes ``{"selected": 0|1, "value": label}``. When
    *selected_key* is empty no option is selected (OPNsense "unset" state).
    """
    return {
        key: {"selected": 1 if key == selected_key else 0, "value": label}
        for key, label in options.items()
    }


def _set_enum_selection(field: dict[str, Any], selected_key: str) -> dict[str, dict]:
    """Copy a template enum dict, flipping ``selected`` to *selected_key*.

    Preserves the template's option keys and ``value`` labels. If
    *selected_key* is not among the template options it is appended.
    """
    result: dict[str, dict] = {}
    for key, meta in field.items():
        new_meta = dict(meta) if isinstance(meta, dict) else {"value": str(meta)}
        new_meta["selected"] = 1 if key == selected_key else 0
        result[key] = new_meta
    if selected_key and selected_key not in result:
        result[selected_key] = {"selected": 1, "value": selected_key}
    return result


def _enum_field(
    default_options: dict[str, str],
    selected_key: str,
    template_field: Any = None,
) -> dict[str, dict]:
    """Build an enum field, preferring a template's option set when present."""
    if isinstance(template_field, dict) and template_field:
        return _set_enum_selection(template_field, selected_key)
    options = dict(default_options)
    if selected_key and selected_key not in options:
        options[selected_key] = selected_key
    return make_enum_field(options, selected_key)


def _optional_enum_field(
    value: str | None,
    default_options: dict[str, str],
    template_field: Any = None,
) -> dict[str, dict] | str:
    """Enum field for an optional value; cleared selection -> ``{}``/``""``.

    When *value* is falsy and a template enum dict exists, all selections are
    cleared (preserving options); otherwise an empty string is returned, both
    of which normalize back to ``None``.
    """
    if value:
        return _enum_field(default_options, value, template_field)
    if isinstance(template_field, dict):
        return _set_enum_selection(template_field, "")
    return ""


# ---------------------------------------------------------------------------
# Pipe
# ---------------------------------------------------------------------------


def serialize_pipe(
    flat: FlatShaperPipe, template: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Convert a :class:`FlatShaperPipe` to a GUI pipe payload.

    Bandwidth/weight/enabled and optional ints are encoded as strings; enum
    fields (bandwidth metric, mask, scheduler) become GUI enum dicts. When
    *template* is given, unmapped keys are preserved.
    """
    template = template or {}
    payload: dict[str, Any] = dict(template)

    payload["uuid"] = flat.get("uuid", "")
    payload["enabled"] = _bool_str(flat.get("enabled", False))
    payload["description"] = flat.get("description", "")
    payload["bandwidth"] = str(flat.get("bandwidth", "") or "")
    payload["bandwidthMetric"] = _enum_field(
        BANDWIDTH_METRIC_OPTIONS,
        flat.get("bandwidth_metric", ""),
        template.get("bandwidthMetric"),
    )
    payload["queue"] = flat.get("number", "")
    payload["mask"] = _enum_field(
        MASK_OPTIONS, flat.get("mask", ""), template.get("mask")
    )
    payload["scheduler"] = _enum_field(
        SCHEDULER_OPTIONS, flat.get("scheduler", ""), template.get("scheduler")
    )
    payload["codel_enable"] = _bool_str(flat.get("codel_enable", False))
    payload["codel_target"] = _int_or_empty(flat.get("codel_target_ms"))
    payload["codel_interval"] = _int_or_empty(flat.get("codel_interval_ms"))
    payload["codel_ecn_enable"] = _bool_str(flat.get("codel_ecn_enable", False))
    payload["fqcodel_quantum"] = _int_or_empty(flat.get("fqcodel_quantum"))
    payload["fqcodel_limit"] = _int_or_empty(flat.get("fqcodel_limit"))
    payload["fqcodel_flows"] = _int_or_empty(flat.get("fqcodel_flows"))
    payload["pie_enable"] = _bool_str(flat.get("pie_enable", False))
    return payload


def merge_flat_into_pipe(
    existing_gui: dict[str, Any], flat: FlatShaperPipe
) -> dict[str, Any]:
    """Merge flat pipe changes into a fetched ``get_pipe`` GUI dict."""
    return serialize_pipe(flat, template=existing_gui)


# ---------------------------------------------------------------------------
# Queue
# ---------------------------------------------------------------------------


def serialize_queue(
    flat: FlatShaperQueue,
    pipe_descriptions: dict[str, str],
    template: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Convert a :class:`FlatShaperQueue` to a GUI queue payload.

    The ``pipe`` field is an enum keyed by pipe UUID; *pipe_descriptions* maps
    pipe UUID -> description for building option labels when no template
    supplies them.
    """
    template = template or {}
    payload: dict[str, Any] = dict(template)

    payload["uuid"] = flat.get("uuid", "")
    payload["enabled"] = _bool_str(flat.get("enabled", False))
    payload["description"] = flat.get("description", "")
    payload["weight"] = str(flat.get("weight", "") or "")
    payload["pipe"] = _enum_field(
        pipe_descriptions, flat.get("pipe_uuid", ""), template.get("pipe")
    )
    payload["mask"] = _enum_field(
        MASK_OPTIONS, flat.get("mask", ""), template.get("mask")
    )
    payload["codel_enable"] = _bool_str(flat.get("codel_enable", False))
    payload["codel_target"] = _int_or_empty(flat.get("codel_target_ms"))
    payload["codel_interval"] = _int_or_empty(flat.get("codel_interval_ms"))
    payload["codel_ecn_enable"] = _bool_str(flat.get("codel_ecn_enable", False))
    payload["pie_enable"] = _bool_str(flat.get("pie_enable", False))
    return payload


def merge_flat_into_queue(
    existing_gui: dict[str, Any],
    flat: FlatShaperQueue,
    pipe_descriptions: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Merge flat queue changes into a fetched ``get_queue`` GUI dict."""
    return serialize_queue(flat, pipe_descriptions or {}, template=existing_gui)


# ---------------------------------------------------------------------------
# Rule
# ---------------------------------------------------------------------------


def serialize_rule(
    flat: FlatShaperRule,
    target_descriptions: dict[str, str],
    template: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Convert a :class:`FlatShaperRule` to a GUI rule payload.

    The ``target`` field is an enum keyed by queue/pipe UUID;
    *target_descriptions* maps target UUID -> description for option labels.
    Interface and DSCP, which carry no canonical option set here, fall back to
    the template or a single-option enum.
    """
    template = template or {}
    payload: dict[str, Any] = dict(template)

    payload["uuid"] = flat.get("uuid", "")
    payload["enabled"] = _bool_str(flat.get("enabled", False))
    payload["description"] = flat.get("description", "")
    payload["sequence"] = str(flat.get("sequence", "") or "")
    payload["interface"] = _enum_field(
        {}, flat.get("interface", ""), template.get("interface")
    )
    payload["interface2"] = _optional_enum_field(
        flat.get("interface2"), {}, template.get("interface2")
    )
    payload["proto"] = _enum_field(
        PROTO_OPTIONS, flat.get("proto", ""), template.get("proto")
    )
    payload["direction"] = _enum_field(
        DIRECTION_OPTIONS, flat.get("direction", ""), template.get("direction")
    )
    payload["source"] = flat.get("source", "any")
    payload["source_port"] = flat.get("source_port") or ""
    payload["destination"] = flat.get("destination", "any")
    payload["destination_port"] = flat.get("destination_port") or ""
    payload["dscp"] = _optional_enum_field(flat.get("dscp"), {}, template.get("dscp"))
    payload["target"] = _enum_field(
        target_descriptions, flat.get("target_uuid", ""), template.get("target")
    )
    return payload


def merge_flat_into_rule(
    existing_gui: dict[str, Any],
    flat: FlatShaperRule,
    target_descriptions: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Merge flat rule changes into a fetched ``get_rule`` GUI dict."""
    return serialize_rule(flat, target_descriptions or {}, template=existing_gui)


# ---------------------------------------------------------------------------
# REST API POST bodies (set_pipe / add_pipe / …)
#
# OPNsense traffic shaper write endpoints expect:
#   {"pipe": {...}} | {"queue": {...}} | {"rule": {...}}
# with enum fields as plain strings (not GUI ``{option: {selected, value}}``).
# ---------------------------------------------------------------------------


def _selected_enum_key(field: Any) -> str:
    """Return the selected option key from a GUI enum dict, or passthrough str."""
    if not isinstance(field, dict):
        return str(field or "")
    for key, meta in field.items():
        if isinstance(meta, dict) and meta.get("selected"):
            return str(key)
    selected = field.get("selected")
    if selected is not None:
        return str(selected)
    return ""


def flatten_gui_post_body(gui_body: dict[str, Any]) -> dict[str, Any]:
    """Convert a GUI-shaped inner body to REST API scalar strings."""
    flattened: dict[str, Any] = {}
    for key, value in gui_body.items():
        if isinstance(value, dict) and value and all(
            isinstance(v, dict) and "selected" in v for v in value.values()
        ):
            flattened[key] = _selected_enum_key(value)
        else:
            flattened[key] = value
    return flattened


def wrap_pipe_api_post(gui_inner: dict[str, Any]) -> dict[str, Any]:
    """Wrap a GUI pipe body for ``add_pipe`` / ``set_pipe`` POST."""
    return {"pipe": flatten_gui_post_body(gui_inner)}


def wrap_queue_api_post(gui_inner: dict[str, Any]) -> dict[str, Any]:
    """Wrap a GUI queue body for ``add_queue`` / ``set_queue`` POST."""
    return {"queue": flatten_gui_post_body(gui_inner)}


def wrap_rule_api_post(gui_inner: dict[str, Any]) -> dict[str, Any]:
    """Wrap a GUI rule body for ``add_rule`` / ``set_rule`` POST."""
    return {"rule": flatten_gui_post_body(gui_inner)}


def serialize_pipe_api_post(
    flat: FlatShaperPipe, template: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Flat pipe → wrapped REST API POST body."""
    return wrap_pipe_api_post(serialize_pipe(flat, template=template))


def merge_flat_into_pipe_api_post(
    existing_gui: dict[str, Any], flat: FlatShaperPipe
) -> dict[str, Any]:
    """Merge flat pipe changes into wrapped REST API POST body."""
    return wrap_pipe_api_post(merge_flat_into_pipe(existing_gui, flat))


def serialize_queue_api_post(
    flat: FlatShaperQueue,
    pipe_descriptions: dict[str, str],
    template: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Flat queue → wrapped REST API POST body."""
    return wrap_queue_api_post(
        serialize_queue(flat, pipe_descriptions, template=template)
    )


def merge_flat_into_queue_api_post(
    existing_gui: dict[str, Any],
    flat: FlatShaperQueue,
    pipe_descriptions: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Merge flat queue changes into wrapped REST API POST body."""
    return wrap_queue_api_post(
        merge_flat_into_queue(existing_gui, flat, pipe_descriptions)
    )


def serialize_rule_api_post(
    flat: FlatShaperRule,
    target_descriptions: dict[str, str],
    template: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Flat rule → wrapped REST API POST body."""
    return wrap_rule_api_post(
        serialize_rule(flat, target_descriptions, template=template)
    )


def merge_flat_into_rule_api_post(
    existing_gui: dict[str, Any],
    flat: FlatShaperRule,
    target_descriptions: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Merge flat rule changes into wrapped REST API POST body."""
    return wrap_rule_api_post(
        merge_flat_into_rule(existing_gui, flat, target_descriptions)
    )
