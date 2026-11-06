"""OPNSENSE_SSL_VERIFY reaches the firewall sessions, and nothing global changes.

The client hard-coded ``session.verify = False`` whatever the config said, and
replaced ``ssl.create_default_context`` with a ``CERT_NONE`` context, which
turned verification off for every library in the process.
"""

from __future__ import annotations

import ssl
from typing import Any
from unittest.mock import patch

import pytest

from opnsense_mcp.utils.api import OPNsenseClient

_BASE = {"firewall_host": "192.0.2.1", "api_key": "k", "api_secret": "s"}


def _client(**extra: Any) -> OPNsenseClient:
    with patch.object(OPNsenseClient, "_detect_endpoint", return_value=None):
        return OPNsenseClient({**_BASE, **extra})


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        ({}, False),
        ({"verify_ssl": False}, False),
        ({"verify_ssl": True}, True),
        ({"verify_ssl": False, "ca_bundle": "/etc/ca.pem"}, "/etc/ca.pem"),
        ({"ca_bundle": None, "verify_ssl": True}, True),
    ],
)
def test_both_sessions_use_the_configured_verify(
    extra: dict[str, Any], expected: bool | str
) -> None:
    """Reads and writes run on separate sessions; both must honour the config."""
    client = _client(**extra)
    assert client.session.verify == expected
    assert client.long_session.verify == expected


def test_building_a_client_leaves_the_stdlib_default_context_alone() -> None:
    """Other libraries in the process must keep verifying certificates."""
    before = ssl.create_default_context
    _client()
    assert ssl.create_default_context is before
    assert ssl.create_default_context().verify_mode == ssl.CERT_REQUIRED


def test_server_passes_the_env_through(monkeypatch: pytest.MonkeyPatch) -> None:
    """OPNSENSE_SSL_VERIFY and OPNSENSE_CA_BUNDLE reach the client config."""
    from opnsense_mcp import server

    monkeypatch.setenv("OPNSENSE_FIREWALL_HOST", "192.0.2.1")
    monkeypatch.setenv("OPNSENSE_API_KEY", "k")
    monkeypatch.setenv("OPNSENSE_API_SECRET", "s")
    monkeypatch.setenv("OPNSENSE_SSL_VERIFY", "true")
    monkeypatch.setenv("OPNSENSE_CA_BUNDLE", "/etc/fw-ca.pem")
    monkeypatch.delenv("OPNSENSE_USE_MOCK", raising=False)
    with patch.object(OPNsenseClient, "_detect_endpoint", return_value=None):
        client = server.get_opnsense_client({})
    assert isinstance(client, OPNsenseClient)
    assert client.session.verify == "/etc/fw-ca.pem"
