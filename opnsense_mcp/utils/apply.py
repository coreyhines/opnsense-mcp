"""Applying staged changes, as a phase distinct from writing them.

Two problems this exists to fix, both found by adversarial review.

The reconfigure call sat inside the same ``try`` as the write it followed, so a
failure applying was caught by the write's handler and reported as though the
write had failed. For a delete that inverts the truth: the record is gone and
the caller is told it is not, so the natural next move is to try again.

And nothing checked what reconfigure answered. ``ApiMutableServiceControllerBase``
returns a ``{"status": ...}`` document, while the client only raises on
``{"result": "failed"}``, so a configd failure at HTTP 200 was invisible and the
tool reported the change as applied.

Callers should catch :class:`ApplyError` separately from write errors, keep
``status`` as success, and report ``applied: False`` with the reason.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# What a healthy reconfigure answers with. OPNsense is inconsistent about
# case and trailing whitespace, hence the normalisation at the call.
APPLY_OK = frozenset({"ok", "success", "running", "done"})


class ApplyError(Exception):
    """The write succeeded; applying it did not."""


async def run_apply(client: Any, endpoint: str) -> dict[str, Any]:
    """Reconfigure, and raise :class:`ApplyError` unless it reports success.

    Transport failures are converted too: from the caller's point of view "the
    apply did not happen" is the same outcome whether the request failed or the
    service reported an error, and both leave the write in place.
    """
    try:
        response = await client._make_request("POST", endpoint, call_class="apply")
    except Exception as exc:  # noqa: BLE001
        raise ApplyError(f"{endpoint} did not complete: {exc}") from exc

    status = ""
    if isinstance(response, dict):
        status = str(response.get("status", "")).strip().lower()
    if status not in APPLY_OK:
        raise ApplyError(
            f"{endpoint} reported {status or response!r} rather than success"
        )
    return response if isinstance(response, dict) else {}
