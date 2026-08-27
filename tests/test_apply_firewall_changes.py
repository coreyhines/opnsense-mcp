"""Applying firewall changes without a savepoint endpoint that does not exist.

`apply_firewall_changes` created a savepoint, read a revision out of it, and
applied against that revision. On 26.7.2 `/api/firewall/filter/savepoint` is a
404, so the call failed every time — after the rule create or delete it was
meant to finish had already succeeded. Rule operations reported failure while
working, which is the most misleading result available and a plausible reason
someone once wrote an SSH fallback for firewall rules.

`/api/firewall/filter/apply` works on its own. The savepoint is an optimisation
for rollback, not a prerequisite, so its absence must not fail the apply.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from opnsense_mcp.utils.api import OPNsenseClient, RequestError


def _client() -> OPNsenseClient:
    config = {"firewall_host": "192.0.2.1", "api_key": "k", "api_secret": "s"}
    with (
        patch.object(OPNsenseClient, "_detect_endpoint", return_value=None),
        patch("opnsense_mcp.utils.api.requests.Session") as sess_cls,
    ):
        sess_cls.side_effect = lambda: MagicMock()
        return OPNsenseClient(config)


def _stub(client: OPNsenseClient, responses: dict[str, Any]) -> list[str]:
    calls: list[str] = []

    async def fake(method: str, endpoint: str, **kwargs: Any) -> Any:
        calls.append(endpoint)
        for key, value in responses.items():
            if key in endpoint:
                if isinstance(value, Exception):
                    raise value
                return value
        return {"status": "ok"}

    client._make_request = AsyncMock(side_effect=fake)
    return calls


def test_apply_succeeds_when_savepoint_is_not_available() -> None:
    """A 404 on savepoint is this firmware's normal state, not a failure."""
    client = _client()
    calls = _stub(
        client,
        {
            "savepoint": RequestError("HTTP 404: Endpoint not found"),
            "apply": {"status": "OK\n\n"},
        },
    )

    result = asyncio.run(client.apply_firewall_changes())

    # The method's own contract is {"revision", "result"}, not the raw status.
    assert result["result"] == "success"
    assert result["revision"] is None
    assert any(c.endswith("/apply") for c in calls)


def test_apply_still_uses_a_savepoint_when_one_is_offered() -> None:
    """Where rollback exists, keep using it."""
    client = _client()
    calls = _stub(
        client,
        {"savepoint": {"revision": "12345"}, "apply": {"status": "ok"}},
    )

    asyncio.run(client.apply_firewall_changes())

    assert any(c.endswith("/apply/12345") for c in calls)


def test_a_failing_apply_is_still_an_error() -> None:
    """Tolerating a missing savepoint must not tolerate a failed apply."""
    client = _client()
    _stub(
        client,
        {
            "savepoint": RequestError("HTTP 404: Endpoint not found"),
            "apply": {"status": "failed", "message": "pf syntax error"},
        },
    )

    with pytest.raises(Exception, match="pf syntax error"):
        asyncio.run(client.apply_firewall_changes())
