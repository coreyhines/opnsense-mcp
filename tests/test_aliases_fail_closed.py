"""#65: `aliases` must fail closed, not report success with an empty list.

Falsification targets:

- ``OPNsenseClient.search_aliases`` used to swallow every exception and
  return ``[]``; a dead request was indistinguishable from "no aliases".
  It must raise so the caller can tell the two apart.
- ``AliasesTool`` against a failing transport must return ``status: error``,
  never ``status: success`` with ``aliases: []``.
- A genuinely empty alias table must still succeed with an empty list.
"""

from __future__ import annotations

from typing import Any

import pytest

from opnsense_mcp.tools.aliases import AliasesTool
from opnsense_mcp.utils.api import APIError, OPNsenseClient, RequestError


class FailingTransport:
    """A ``_make_request`` that fails the way the live endpoint did."""

    def __init__(self, error: Exception) -> None:
        self.error = error
        self.calls = 0

    async def __call__(self, method: str, endpoint: str, **kwargs: Any) -> Any:
        self.calls += 1
        raise self.error


def _raw_client(transport: FailingTransport) -> OPNsenseClient:
    """An OPNsenseClient whose only capability is the failing transport."""
    client = OPNsenseClient.__new__(OPNsenseClient)
    client._make_request = transport  # type: ignore[method-assign]
    return client


# ---------------------------------------------------------------------------
# Client layer: the swallow is the root cause
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_aliases_raises_on_transport_failure() -> None:
    """Old code returned [] here; the tool then reported success with 0 aliases."""
    transport = FailingTransport(RequestError("HTTP 500: API error: lock timeout"))
    client = _raw_client(transport)

    with pytest.raises(APIError):
        await client.search_aliases()

    assert transport.calls == 1


@pytest.mark.asyncio
async def test_search_aliases_preserves_api_error_type() -> None:
    """APIErrors pass through untouched so callers can react to specifics."""
    transport = FailingTransport(RequestError("HTTP 502 bad gateway"))
    client = _raw_client(transport)

    with pytest.raises(RequestError, match="502"):
        await client.search_aliases()


# ---------------------------------------------------------------------------
# Tool layer: fail closed end to end
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_aliases_tool_errors_instead_of_succeeding_empty() -> None:
    """The shape of the defect: success + [] read as 'no aliases exist'."""
    transport = FailingTransport(RequestError("HTTP 500: API error: lock timeout"))
    tool = AliasesTool(_raw_client(transport))

    result = await tool.execute({})

    assert result["status"] == "error"
    assert result["error"]
    assert result.get("aliases") != []
    assert result.get("count") != 0


@pytest.mark.asyncio
async def test_aliases_tool_errors_with_search_param_too() -> None:
    """The failure is not masked when a search filter is also supplied."""
    transport = FailingTransport(RequestError("connection reset"))
    tool = AliasesTool(_raw_client(transport))

    result = await tool.execute({"search": "lan"})

    assert result["status"] == "error"
    assert result["error"]
    assert "aliases" not in result


@pytest.mark.asyncio
async def test_aliases_tool_still_succeeds_on_genuinely_empty_listing() -> None:
    """Empty must mean 'no aliases', not 'the request died'."""
    client = OPNsenseClient.__new__(OPNsenseClient)

    async def make_request(method: str, endpoint: str, **kwargs: Any) -> dict[str, Any]:
        return {"rows": [], "total": 0}

    client._make_request = make_request  # type: ignore[method-assign]
    tool = AliasesTool(client)

    result = await tool.execute({})

    assert result["status"] == "success"
    assert result["aliases"] == []
    assert result["count"] == 0


@pytest.mark.asyncio
async def test_aliases_tool_success_with_rows_and_search() -> None:
    """The happy path with a server-side filter is unchanged."""
    client = OPNsenseClient.__new__(OPNsenseClient)

    async def make_request(method: str, endpoint: str, **kwargs: Any) -> dict[str, Any]:
        assert (kwargs.get("json") or {}).get("searchPhrase") == "lan"
        return {"rows": [{"name": "lan_hosts"}], "total": 1}

    client._make_request = make_request  # type: ignore[method-assign]
    tool = AliasesTool(client)

    result = await tool.execute({"search": "lan"})

    assert result["status"] == "success"
    assert result["count"] == 1
    assert result["aliases"][0]["name"] == "lan_hosts"
