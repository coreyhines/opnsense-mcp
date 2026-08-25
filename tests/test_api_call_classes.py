"""Wave 2a: request call classes.

Every request used one 5s timeout. `reconfigure` and `apply` routinely exceed
that, so a timeout read as failure while the firewall kept applying, and a retry
duplicated the object. The session lock was also held across send and receive, so
one long call serialised every other tool sharing the client.

Call classes give each kind of request its own timeout, and route the long ones
onto a second session so they stop blocking reads.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from opnsense_mcp.utils.api import CALL_CLASS_TIMEOUTS, OPNsenseClient


def _client() -> OPNsenseClient:
    config = {"firewall_host": "192.0.2.1", "api_key": "k", "api_secret": "s"}
    with (
        patch.object(OPNsenseClient, "_detect_endpoint", return_value=None),
        patch("opnsense_mcp.utils.api.requests.Session") as sess_cls,
    ):
        sess_cls.side_effect = lambda: MagicMock()
        return OPNsenseClient(config)


def _capture(client: OPNsenseClient) -> dict[str, Any]:
    """Record what the underlying session was asked to do."""
    seen: dict[str, Any] = {}

    def fake_request(method: str, url: str, **kwargs: Any) -> MagicMock:
        seen["method"] = method
        seen["url"] = url
        seen["timeout"] = kwargs.get("timeout")
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"result": "ok"}
        return resp

    for sess in {id(s): s for s in (client.session, client.long_session)}.values():
        sess.request.side_effect = fake_request
    return seen


def test_call_class_timeouts_are_defined() -> None:
    """Read stays at 5s; writes and applies get room to finish."""
    assert CALL_CLASS_TIMEOUTS["read"] == 5
    assert CALL_CLASS_TIMEOUTS["write"] >= 30
    assert CALL_CLASS_TIMEOUTS["apply"] >= 120
    assert CALL_CLASS_TIMEOUTS["download"] >= 60


@pytest.mark.asyncio
async def test_read_is_the_default_and_keeps_5s() -> None:
    client = _client()
    seen = _capture(client)

    await client._make_request("GET", "/api/core/system/status")

    assert seen["timeout"] == 5


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("call_class", "expected"),
    [("write", 30), ("apply", 120), ("download", 60)],
)
async def test_call_class_selects_its_timeout(call_class: str, expected: int) -> None:
    client = _client()
    seen = _capture(client)

    await client._make_request(
        "POST", "/api/firewall/filter/apply", call_class=call_class
    )

    assert seen["timeout"] == expected


@pytest.mark.asyncio
async def test_explicit_timeout_still_wins() -> None:
    """A caller that names a timeout is not overridden by its class."""
    client = _client()
    seen = _capture(client)

    await client._make_request(
        "POST", "/api/firewall/filter/apply", call_class="apply", timeout=7
    )

    assert seen["timeout"] == 7


@pytest.mark.asyncio
async def test_long_calls_use_a_separate_session() -> None:
    """Long calls must not sit on the session that reads share."""
    client = _client()

    assert client.long_session is not client.session

    for call_class in ("write", "apply", "download"):
        assert client._session_for(call_class) is client.long_session
    assert client._session_for("read") is client.session


@pytest.mark.asyncio
async def test_read_lock_is_not_held_during_long_calls() -> None:
    """The read lock stays free while an apply is in flight."""
    client = _client()
    observed: dict[str, bool] = {}

    def fake_request(method: str, url: str, **kwargs: Any) -> MagicMock:
        # acquire() returns False when another thread already holds it.
        got = client._session_lock.acquire(blocking=False)
        observed["read_lock_free"] = got
        if got:
            client._session_lock.release()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"result": "ok"}
        return resp

    client.long_session.request.side_effect = fake_request

    await client._make_request("POST", "/api/firewall/filter/apply", call_class="apply")

    assert observed["read_lock_free"] is True


def test_unknown_call_class_is_rejected() -> None:
    """A typo must not silently fall back to a 5s timeout on an apply."""
    client = _client()

    with pytest.raises(ValueError, match="call_class"):
        client._timeout_for("aply")
