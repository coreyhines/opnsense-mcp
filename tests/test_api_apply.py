"""Client-layer apply sites must read what reconfigure answered.

``ApiMutableServiceControllerBase`` returns ``{"status": ...}`` at HTTP 200.
The client used to raise only on ``{"result": "failed"}``, so a configd refusal
was invisible. These tests pin each of the three client apply sites against
exactly that shape — not an exception, not ``result: failed``.

Reverting a site to bare ``_make_request(..., call_class="apply")`` without
reading ``status`` makes the matching test fail.
"""

from __future__ import annotations

import asyncio
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


def test_apply_firewall_changes_rejects_failed_status_at_http_200() -> None:
    """Filter apply must not treat ``{"status": "failed"}`` as success.

    This method *is* the apply (no prior write in the client). Failure stays an
    exception so ``apply_fw_changes`` cannot report ``applied: True``. A bare
    ``_make_request`` return would yield a dict and this test would fail.
    """
    client = _client()
    client._make_request = AsyncMock(
        return_value={"status": "failed", "message": "pf syntax error"}
    )

    with pytest.raises(ResponseError):
        asyncio.run(client.apply_firewall_changes())


def test_apply_firewall_changes_success_reports_applied() -> None:
    """Happy path gains an ``applied`` flag for callers that inspect the dict."""
    client = _client()
    client._make_request = AsyncMock(return_value={"status": "ok"})

    result = asyncio.run(client.apply_firewall_changes())

    assert result["result"] == "success"
    assert result["applied"] is True


def test_reconfigure_unbound_failed_status_reports_not_applied() -> None:
    """Unbound reconfigure at HTTP 200 with failed status must not look live.

    Returns ``applied: False`` without raising so write+reconfigure callers
    (``mkdns`` / ``rmdns``) are not forced to treat the miss as a write error.
    Those tools still hard-code ``applied: True`` today — out of scope here.
    """
    client = _client()
    client._make_request = AsyncMock(return_value={"status": "failed"})

    result = asyncio.run(client.reconfigure_unbound())

    assert result["applied"] is False
    assert "apply_error" in result
    assert result["status"] == "failed"


def test_reconfigure_unbound_success_reports_applied() -> None:
    """Healthy reconfigure is explicitly applied."""
    client = _client()
    client._make_request = AsyncMock(return_value={"status": "ok"})

    result = asyncio.run(client.reconfigure_unbound())

    assert result["applied"] is True


def test_restart_unbound_failed_status_reports_not_applied() -> None:
    """Unbound restart refusal at HTTP 200 must report ``applied: False``.

    No retry — restart briefly interrupts DNS. Same return shape as reconfigure.
    """
    client = _client()
    client._make_request = AsyncMock(return_value={"status": "failed"})

    result = asyncio.run(client.restart_unbound())

    assert result["applied"] is False
    assert "apply_error" in result
    assert result["status"] == "failed"
    # Single attempt: run_apply issues one POST; no retry wrapper.
    assert client._make_request.await_count == 1


def test_restart_unbound_success_reports_applied() -> None:
    """Healthy restart is explicitly applied, still a single call."""
    client = _client()
    client._make_request = AsyncMock(return_value={"status": "ok"})

    result = asyncio.run(client.restart_unbound())

    assert result["applied"] is True
    assert client._make_request.await_count == 1
