"""Applying firewall changes without a savepoint endpoint that does not exist.

`apply_firewall_changes` created a savepoint, read a revision out of it, and
applied against that revision. On 26.7.2 `/api/firewall/filter/savepoint` is a
404, so the call failed every time — after the rule create or delete it was
meant to finish had already succeeded. Rule operations reported failure while
working, which is the most misleading result available and a plausible reason
someone once wrote an SSH fallback for firewall rules.

The savepoint is gone rather than made optional. `cancel_firewall_rollback`
existed with no callers, so whichever way OPNsense's rollback protocol works,
this implemented half of it: a savepoint was taken, an apply was made against
its revision, and nothing ever confirmed or cancelled the result. Half a
rollback protocol is wrong regardless of its semantics, and the path cannot be
exercised on firmware where the endpoint does not exist.

`/api/firewall/filter/apply` works on its own, which is what the tools use.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from opnsense_mcp.utils.api import OPNsenseClient, ResponseError


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


def test_apply_goes_straight_to_apply() -> None:
    """One call, no savepoint, no revision in the path."""
    client = _client()
    calls = _stub(client, {"apply": {"status": "OK\n\n"}})

    result = asyncio.run(client.apply_firewall_changes())

    assert result["result"] == "success"
    assert calls == ["/api/firewall/filter/apply"]


def test_no_savepoint_is_requested() -> None:
    """Taking one and never confirming it is the half-protocol this removed."""
    client = _client()
    calls = _stub(client, {"apply": {"status": "ok"}})

    asyncio.run(client.apply_firewall_changes())

    assert not [c for c in calls if "savepoint" in c or "ollback" in c]


def test_a_failing_apply_is_still_an_error() -> None:
    """Dropping the savepoint must not soften a genuine apply failure."""
    client = _client()
    _stub(client, {"apply": {"status": "failed", "message": "pf syntax error"}})

    with pytest.raises(Exception, match="pf syntax error"):
        asyncio.run(client.apply_firewall_changes())


# --- toggle ---------------------------------------------------------------


def test_toggle_accepts_the_response_the_api_actually_sends() -> None:
    """toggleRule answers with the new state, not with "ok".

    Observed live: {"result": "Disabled", "changed": true}. The client required
    result == "ok" and raised otherwise, so every toggle reported failure while
    having flipped the rule. Same shape as the savepoint bug: the operation
    worked and the caller was told it had not.
    """
    for payload in (
        {"result": "Disabled", "changed": True},
        {"result": "Enabled", "changed": True},
        {"result": "ok"},
        {"result": "Disabled", "changed": False},
    ):
        client = _client()
        _stub(client, {"toggleRule": payload})

        result = asyncio.run(client.toggle_firewall_rule("uuid-1", enabled=False))

        assert result["uuid"] == "uuid-1", payload


def test_toggle_still_fails_when_the_api_says_it_failed() -> None:
    """Widening what counts as success must not accept an actual failure."""
    client = _client()
    _stub(client, {"toggleRule": {"result": "failed", "message": "no such rule"}})

    with pytest.raises(Exception, match="no such rule"):
        asyncio.run(client.toggle_firewall_rule("uuid-1", enabled=False))


def test_toggle_fails_on_a_response_that_is_not_a_mapping() -> None:
    """A string reply is not a widened success case."""
    client = _client()
    _stub(client, {"toggleRule": "not json"})

    with pytest.raises(ResponseError, match="Toggle failed"):
        asyncio.run(client.toggle_firewall_rule("uuid-1", enabled=True))
