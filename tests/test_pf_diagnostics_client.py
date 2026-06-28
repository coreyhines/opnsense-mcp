"""Tests for PF diagnostics API client methods."""

from __future__ import annotations

from typing import Any

import pytest

from opnsense_mcp.utils.api import OPNsenseClient


class DummyClient(OPNsenseClient):
    """OPNsense client with request recording for unit tests."""

    def __init__(self) -> None:
        """Avoid real OPNsense client initialization."""
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.responses: list[Any] = []

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        **kwargs: str | dict[str, str] | list[str] | int | bool | None,
    ) -> Any:
        """Record request arguments and return queued responses."""
        self.calls.append((method, endpoint, kwargs))
        return self.responses.pop(0)


@pytest.mark.asyncio
async def test_get_pf_states_uses_query_states_endpoint() -> None:
    """PF row listing uses query_states, not metadata-only pf_states."""
    client = DummyClient()
    client.responses.append({"rows": [{"src_addr": "10.0.0.2"}], "total": 1})

    result = await client.get_pf_states(limit=10)

    assert result["rows"][0]["src_addr"] == "10.0.0.2"
    assert client.calls == [
        (
            "POST",
            "/api/diagnostics/firewall/query_states",
            {"data": {"current": 1, "rowCount": 10}},
        )
    ]


@pytest.mark.asyncio
async def test_get_pf_states_clamps_limit() -> None:
    """Very large state requests are capped before reaching OPNsense."""
    client = DummyClient()
    client.responses.append({"rows": []})

    await client.get_pf_states(limit=9000)

    assert client.calls[0][2]["data"] == {"current": 1, "rowCount": 5000}


@pytest.mark.asyncio
async def test_get_pf_state_table_meta_uses_pf_states_endpoint() -> None:
    """The pf_states endpoint is kept for current/limit metadata."""
    client = DummyClient()
    client.responses.append({"current": "6183", "limit": "1621700"})

    result = await client.get_pf_state_table_meta()

    assert result["current"] == "6183"
    assert client.calls[0][:2] == ("GET", "/api/diagnostics/firewall/pf_states")


@pytest.mark.asyncio
async def test_get_pf_statistics_returns_raw_payload() -> None:
    """The statistics endpoint can return an empty list on current firmware."""
    client = DummyClient()
    client.responses.append([])

    result = await client.get_pf_statistics()

    assert result == []
    assert client.calls[0][:2] == ("GET", "/api/diagnostics/firewall/pf_statistics")
