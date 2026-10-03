"""Adapt a bound request callable into the client shape apply helpers expect.

DHCP providers store ``client._make_request`` (or a fake of it), not the client.
``opnsense_mcp.utils.apply.run_apply`` needs an object with ``_make_request`` so
the apply rides ``call_class="apply"`` and reads the service status document.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine


class RequestCallableClient:
    """Thin wrapper so a request callable looks like a client to apply helpers."""

    def __init__(
        self,
        make_request: Callable[..., Coroutine[Any, Any, Any]],
    ) -> None:
        """Store the request callable as ``_make_request``."""
        self._make_request = make_request
