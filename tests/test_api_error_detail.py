"""HTTP error bodies must reach the caller.

OPNsense puts a precise, actionable message in the body of a 4xx or 5xx:

    {"errorMessage": "Interface locked, unset lock first before removal",
     "errorTitle": "locked", "errorLevel": "error"}

The client raised `HTTP error: 500 Server Error` and discarded it, which turned
a three-command fix into a dead end and an orphaned interface on a live
firewall. Nothing about the failure was opaque except what the client chose to
show.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

from opnsense_mcp.utils.api import OPNsenseClient, RequestError


def _client() -> OPNsenseClient:
    config = {"firewall_host": "192.0.2.1", "api_key": "k", "api_secret": "s"}
    with (
        patch.object(OPNsenseClient, "_detect_endpoint", return_value=None),
        patch("opnsense_mcp.utils.api.requests.Session") as sess_cls,
    ):
        sess_cls.side_effect = lambda: MagicMock()
        return OPNsenseClient(config)


def _response(status: int, payload: Any, text: str = "") -> MagicMock:
    response = MagicMock()
    response.status_code = status
    response.text = text or ""
    if payload is None:
        response.json.side_effect = ValueError("not json")
    else:
        response.json.return_value = payload
    error = requests.exceptions.HTTPError(f"{status} Server Error: for url: /x")
    error.response = response
    response.raise_for_status.side_effect = error
    return response


def _run(client: OPNsenseClient, response: MagicMock) -> str:
    client.session.request = MagicMock(return_value=response)
    client.long_session.request = MagicMock(return_value=response)
    with pytest.raises(RequestError) as caught:
        import asyncio

        asyncio.run(client._make_request("POST", "/api/x/y/del_item/opt12"))
    return str(caught.value)


def test_the_error_message_from_the_body_is_surfaced() -> None:
    """This exact body is what a locked interface returns."""
    client = _client()
    message = _run(
        client,
        _response(
            500,
            {
                "errorMessage": "Interface locked, unset lock first before removal",
                "errorTitle": "locked",
                "errorLevel": "error",
            },
        ),
    )

    assert "Interface locked" in message
    assert "unset lock first" in message


def test_the_status_code_is_kept_alongside_it() -> None:
    """The code says whether to retry; the message says what to fix."""
    client = _client()
    message = _run(client, _response(500, {"errorMessage": "boom"}))

    assert "500" in message


def test_a_validation_body_is_surfaced_too() -> None:
    """Field-level rejections arrive under a different key."""
    client = _client()
    message = _run(
        client,
        _response(400, {"validations": {"interface.if": "Option [] not in list."}}),
    )

    assert "interface.if" in message
    assert "not in list" in message


def test_a_body_that_is_not_json_falls_back_to_its_text() -> None:
    client = _client()
    message = _run(client, _response(502, None, text="<html>Bad Gateway</html>"))

    assert "502" in message
    assert "Bad Gateway" in message


def test_an_empty_body_still_reports_the_status() -> None:
    """No detail available is a different answer from detail withheld."""
    client = _client()
    message = _run(client, _response(503, None, text=""))

    assert "503" in message
