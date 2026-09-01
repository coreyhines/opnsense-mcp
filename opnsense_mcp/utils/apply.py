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

from opnsense_mcp.utils.api import ConnectionError, RequestError, ResponseError

logger = logging.getLogger(__name__)

# What a healthy reconfigure answers with. OPNsense is inconsistent about
# case and trailing whitespace, hence the normalisation at the call.
APPLY_OK = frozenset({"ok", "success", "running", "done"})

# An explicit refusal, whatever key carries it.
APPLY_FAILED = frozenset({"failed", "failure", "error"})

# Which key holds that answer is not consistent either.
# `ApiMutableServiceControllerBase::reconfigureAction` returns {"status": ...};
# WireGuard's ServiceController overrides it and returns {"result": ...}; and
# unbound's restart answers {"response": ...}. Reading only "status" made the
# other two read as failures, which is the direction that teaches a caller to
# ignore `applied: false` -- the one signal reconcile_npt and apply_ula rely on.
STATUS_KEYS = ("status", "result", "response")


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
    except (RequestError, ResponseError, ConnectionError, TimeoutError) as exc:
        # Only genuine transport/API failures become "the apply did not happen".
        # A programming error (AttributeError, TypeError) is a bug in this code
        # and must surface as itself with its traceback, not be downgraded to a
        # benign-looking apply miss.
        raise ApplyError(f"{endpoint} did not complete: {exc}") from exc

    reported = (
        {
            key: str(response[key]).strip().lower()
            for key in STATUS_KEYS
            if key in response
        }
        if isinstance(response, dict)
        else {}
    )

    # A mixed answer is refused rather than resolved in favour of the good half:
    # picking the success out of {"status": "ok", "result": "failed"} is exactly
    # the reading this module exists to prevent.
    if any(value in APPLY_FAILED for value in reported.values()):
        raise ApplyError(f"{endpoint} reported {response!r} rather than success")
    if not any(value in APPLY_OK for value in reported.values()):
        # Includes the payload that carries no status at all: silence is not
        # consent, because the write has already happened by this point.
        raise ApplyError(f"{endpoint} reported {response!r} rather than success")
    return response if isinstance(response, dict) else {}
