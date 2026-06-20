"""Shared write-path pure helpers for the traffic shaper feature.

No I/O; no OPNsense API calls.  Session-scoped in-process state (tokens).
"""

from __future__ import annotations

import secrets
import time
from typing import Any

from opnsense_mcp.utils.shaper_serialize import (
    merge_flat_into_pipe,
    merge_flat_into_queue,
    merge_flat_into_rule,
)
from opnsense_mcp.utils.shaper_types import (
    DEFAULT_WAN_INTERFACES,
    TOOL_STATUS_SUCCESS,
    FlatShaperPipe,
    FlatShaperQueue,
    FlatShaperRule,
    make_tool_response,
)

# ---------------------------------------------------------------------------
# Session-scoped delete confirmation tokens
# ---------------------------------------------------------------------------

# Map: (resource_type, uuid) -> {"token": str, "expires": float}
_delete_tokens: dict[tuple[str, str], dict[str, Any]] = {}


_DELETE_TOKEN_TTL_SECONDS: int = 300  # 5 minutes


def _clean_expired_tokens() -> None:
    """Remove expired confirmation tokens (session-scoped cleanup)."""
    now = time.time()
    expired = [key for key, data in _delete_tokens.items() if data["expires"] <= now]
    for key in expired:
        del _delete_tokens[key]


def issue_delete_confirm_token(resource_type: str, uuid: str) -> dict[str, str]:
    """Issue a one-time-use confirmation token for deleting a shaper resource.

    Returns a dict with ``token`` and a human-readable ``message`` that the
    agent can use to instruct the user before proceeding with deletion.

    *resource_type* should be one of ``"pipe"``, ``"queue"``, or ``"rule"``.
    """
    _clean_expired_tokens()

    token = secrets.token_hex(8)
    key: tuple[str, str] = (resource_type, uuid)
    _delete_tokens[key] = {
        "token": token,
        "expires": time.time() + _DELETE_TOKEN_TTL_SECONDS,
    }

    return {
        "token": token,
        "message": (
            f"Confirmation required to delete {resource_type} '{uuid}'. "
            f"Use the token ``{token}`` in a follow-up delete call. "
            f"Token expires in {_DELETE_TOKEN_TTL_SECONDS}s."
        ),
    }


def validate_delete_confirm_token(
    resource_type: str, uuid: str, confirm: str | None
) -> bool:
    """Validate a delete confirmation token.

    Returns ``True`` if the token is valid and was consumed (one-time use),
    otherwise ``False``.
    """
    _clean_expired_tokens()

    key: tuple[str, str] = (resource_type, uuid)
    stored = _delete_tokens.get(key)
    if stored is None:
        return False

    # One-time use: consume the token
    del _delete_tokens[key]

    expected_token = stored["token"]
    return confirm == expected_token


# ---------------------------------------------------------------------------
# Idempotency detection
# ---------------------------------------------------------------------------


def next_shaper_rule_sequence(rule_rows: list[dict[str, Any]]) -> int:
    """Return the next unused rule sequence number from search rows."""
    max_seq = 0
    for row in rule_rows:
        raw = row.get("sequence")
        if raw in (None, ""):
            continue
        try:
            max_seq = max(max_seq, int(raw))
        except (TypeError, ValueError):
            continue
    return max_seq + 1 if max_seq else 1


def detect_idempotent_set(
    existing_flat: dict[str, Any], proposed_flat: dict[str, Any]
) -> bool:
    """Return ``True`` when *existing_flat* and *proposed_flat* are equivalent.

    Only the fields present in the TypedDicts are compared; extra keys are
    ignored.  None is treated as equal to an empty string ("") per OPNsense
    normalization conventions.
    """
    # Keys that matter for pipe comparison
    pipe_keys = {
        "uuid",
        "number",
        "description",
        "enabled",
        "bandwidth",
        "bandwidth_metric",
        "scheduler",
        "mask",
        "codel_enable",
        "codel_target_ms",
        "codel_interval_ms",
        "codel_ecn_enable",
        "fqcodel_quantum",
        "fqcodel_limit",
        "fqcodel_flows",
        "pie_enable",
    }

    queue_keys = {
        "uuid",
        "description",
        "enabled",
        "pipe_uuid",
        "weight",
        "mask",
        "codel_enable",
        "codel_target_ms",
        "codel_interval_ms",
        "codel_ecn_enable",
        "pie_enable",
    }

    rule_keys = {
        "uuid",
        "description",
        "enabled",
        "interface",
        "interface2",
        "direction",
        "proto",
        "source",
        "source_port",
        "destination",
        "destination_port",
        "dscp",
        "target_uuid",
        "sequence",
    }

    def _same_value(a: Any, b: Any) -> bool:
        """Compare two values with None / empty-string equivalence."""
        if a is None and (b == "" or b is None):
            return True
        if b is None and (a == "" or a is None):
            return True
        if isinstance(a, bool) or isinstance(b, bool):
            # Coerce int/str bools
            try:
                return _parse_boolish(a) == _parse_boolish(b)
            except (ValueError, TypeError):
                return False
        return a == b

    def _compare_keys(keys: set[str], existing: dict, proposed: dict) -> bool:
        for key in keys:
            if key not in existing or key not in proposed:
                continue
            if not _same_value(existing[key], proposed[key]):
                return False
        return True

    # Determine which type we're dealing with by presence of characteristic keys
    if "uuid" in existing_flat and "bandwidth" in existing_flat:
        return _compare_keys(pipe_keys, existing_flat, proposed_flat)
    if "uuid" in existing_flat and "pipe_uuid" in existing_flat:
        return _compare_keys(queue_keys, existing_flat, proposed_flat)
    if "uuid" in existing_flat and "direction" in existing_flat:
        return _compare_keys(rule_keys, existing_flat, proposed_flat)
    # Fall back to set comparison of all values
    return dict(sorted(existing_flat.items())) == dict(sorted(proposed_flat.items()))


def _parse_boolish(val: Any) -> bool:
    """Coerce OPNsense boolish values ("0"/"1", bool, int) to bool."""
    if isinstance(val, bool):
        return val
    if isinstance(val, int):
        return val != 0
    if isinstance(val, str):
        return val.lower() in {"1", "true"}
    raise ValueError(f"Cannot parse {val!r} as bool")


# ---------------------------------------------------------------------------
# Bandwidth guardrails
# ---------------------------------------------------------------------------


def validate_pipe_bandwidth(
    bandwidth_mbit: int | float,
    line_rate_mbit: int | float,
    *,
    isp_rate_mbit: int | float | None = None,
) -> list[str]:
    """Return a list of hints/errors for pipe bandwidth configuration.

    Rules:
    - Bandwidth > line rate -> error (can exceed physical capacity).
    - Optional ISP rate check: warn when bandwidth exceeds 95 % of reference
      ISP rate (opinionated best-practice guardrail).
    """
    hints: list[str] = []

    if bandwidth_mbit > line_rate_mbit:
        hints.append(
            f"error: Pipe bandwidth ({bandwidth_mbit:.0f} Mbit) exceeds WAN "
            f"interface line rate ({line_rate_mbit:.0f} Mbit). "
            "Reduce to avoid oversubscription."
        )

    if isp_rate_mbit is not None and isp_rate_mbit > 0:
        pct = (bandwidth_mbit / isp_rate_mbit) * 100
        if pct > 95:
            hints.append(
                f"warning: Pipe bandwidth ({bandwidth_mbit:.0f} Mbit) exceeds "
                f"95 % of reference ISP rate ({isp_rate_mbit:.0f} Mbit). "
                "Best practice: cap at ~85-95 %."
            )

    return hints


def warn_lan_interface(
    interface_name: str,
    wan_allowlist: frozenset[str] | None = None,
) -> str | None:
    """Return a warning string when *interface_name* is not in the WAN allowlist."""
    allowed = wan_allowlist if wan_allowlist is not None else DEFAULT_WAN_INTERFACES
    if interface_name.lower() not in {i.lower() for i in allowed}:
        return (
            f"warning: Shaper rule targets non-WAN interface "
            f"'{interface_name}'. LAN shaping is discouraged."
        )
    return None


# ---------------------------------------------------------------------------
# API result validation (restore / mutation helpers)
# ---------------------------------------------------------------------------


def bufferbloat_shaped_rate_mbit(line_rate_mbit: float) -> int:
    """Return 85% of line rate in Mbit/s, rounded to nearest integer."""
    return round(line_rate_mbit * 0.85)


def shaper_api_result_ok(resp: dict[str, Any]) -> tuple[bool, str | None]:
    """Return whether an OPNsense shaper API response indicates success."""
    if not isinstance(resp, dict):
        return False, "invalid response"
    if resp.get("error"):
        return False, str(resp.get("error"))
    status = str(resp.get("status", "ok")).lower()
    if status and status not in ("ok", "done", "success"):
        return False, f"status={status}"
    return True, None


# ---------------------------------------------------------------------------
# Apply envelope builder
# ---------------------------------------------------------------------------


def build_mutation_response(
    structured: dict[str, Any],
    summary: str,
    *,
    snapshot_id: str | None = None,
    hints: list[str] | None = None,
    status: str = TOOL_STATUS_SUCCESS,
) -> dict[str, Any]:
    """Wrap *structured*/*summary* using :func:`make_tool_response`.

    This is a thin convenience wrapper so tool implementations don't need to
    import :mod:`shaper_types` directly.  Returns the same dict shape that
    MCP tools return.
    """
    return make_tool_response(
        status=status,
        structured=structured,
        summary=summary,
        hints=hints if hints is not None else [],
        snapshot_id=snapshot_id,
    )


def pending_apply_fields(
    apply: bool,
    reconfigure_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the ``structured`` portion reflecting apply/pending state.

    When *apply* is ``True`` and a successful reconfigure ran, returns status
    ``"applied"`` with the reconfigure result.  Otherwise marks the change as
    pending.
    """
    if apply and reconfigure_result:
        # Check for success in the reconfigure response
        ok = reconfigure_result.get("status") == "ok" or (
            isinstance(reconfigure_result, dict) and not reconfigure_result.get("error")
        )
        return {
            "applied": ok,
            "pending_changes": not ok,
            "reconfigure_result": reconfigure_result,
        }

    # Not applied (either apply=False or no reconfigure ran)
    return {
        "applied": False,
        "pending_changes": True,
        "reconfigure_result": None,
    }


# ---------------------------------------------------------------------------
# Merge flat into template - thin delegates to serialize helpers
# ---------------------------------------------------------------------------


def merge_flat_into_shaper_pipe(
    existing_gui: dict[str, Any],
    flat: FlatShaperPipe,
) -> dict[str, Any]:
    """Merge a flat pipe record into a fetched ``get_pipe`` GUI dict.

    Delegates to :func:`shaper_serialize.merge_flat_into_pipe`.
    """
    return merge_flat_into_pipe(existing_gui, flat)


def merge_flat_into_shaper_queue(
    existing_gui: dict[str, Any],
    flat: FlatShaperQueue,
    pipe_descriptions: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Merge a flat queue record into a fetched ``get_queue`` GUI dict.

    Delegates to :func:`shaper_serialize.merge_flat_into_queue`.
    """
    return merge_flat_into_queue(existing_gui, flat, pipe_descriptions)


def merge_flat_into_shaper_rule(
    existing_gui: dict[str, Any],
    flat: FlatShaperRule,
    target_descriptions: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Merge a flat rule record into a fetched ``get_rule`` GUI dict.

    Delegates to :func:`shaper_serialize.merge_flat_into_rule`.
    """
    return merge_flat_into_rule(existing_gui, flat, target_descriptions)


# ---------------------------------------------------------------------------
# Public API surface
# ---------------------------------------------------------------------------

__all__ = [
    "issue_delete_confirm_token",
    "validate_delete_confirm_token",
    "detect_idempotent_set",
    "validate_pipe_bandwidth",
    "warn_lan_interface",
    "build_mutation_response",
    "pending_apply_fields",
    "bufferbloat_shaped_rate_mbit",
    "shaper_api_result_ok",
    "merge_flat_into_shaper_pipe",
    "merge_flat_into_shaper_queue",
    "merge_flat_into_shaper_rule",
]
