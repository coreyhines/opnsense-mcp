"""Tests for PfStatesTool and PfStatisticsTool."""

from __future__ import annotations

from typing import Any

import pytest

from opnsense_mcp.tools.pf_diagnostics import PfStatesTool, PfStatisticsTool

_SAMPLE_ROW = {
    "iface": "em0",
    "proto": "tcp",
    "ipproto": "inet",
    "src_addr": "10.0.0.5",
    "src_port": "54321",
    "dst_addr": "1.2.3.4",
    "dst_port": "443",
    "state": "ESTABLISHED:ESTABLISHED",
    "age": "10",
    "expires": "86400",
    "pkts": [100, 200],
    "bytes": [5000, 10000],
    "rule": "1",
    "id": "abc123",
    "label": "",
    "descr": "",
    "nat_addr": None,
    "nat_port": None,
    "gateway": "",
    "flags": "",
    "direction": "in",
    "interface": "em0",
}

_STATES_PAYLOAD = {"rows": [_SAMPLE_ROW], "total": 6183, "rowCount": 1, "current": 6183}
_META_PAYLOAD = {"current": "6183", "limit": "1621700"}
_STATS_EMPTY: list[Any] = []
_STATS_DICT = {"counters": {"state_inserts": 42, "state_removals": 10}}


class FakeClient:
    """Minimal async fake client for tool tests."""

    def __init__(
        self,
        states: Any = None,
        meta: Any = None,
        statistics: Any = None,
        raise_on: str | None = None,
    ) -> None:
        self._states = states if states is not None else _STATES_PAYLOAD
        self._meta = meta if meta is not None else _META_PAYLOAD
        self._statistics = statistics if statistics is not None else _STATS_EMPTY
        self._raise_on = raise_on

    async def get_pf_states(self, limit: int = 100) -> Any:
        if self._raise_on in ("states", "all"):
            raise RuntimeError("states API error")
        return self._states

    async def get_pf_state_table_meta(self) -> Any:
        if self._raise_on in ("meta", "all"):
            raise RuntimeError("meta API error")
        return self._meta

    async def get_pf_statistics(self) -> Any:
        if self._raise_on in ("statistics", "all"):
            raise RuntimeError("statistics API error")
        return self._statistics


# ---------------------------------------------------------------------------
# PfStatesTool — success path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pf_states_success_envelope() -> None:
    """Success returns all required envelope keys with correct types."""
    tool = PfStatesTool(FakeClient())
    result = await tool.execute({})

    assert result["status"] == "success"
    assert isinstance(result["states"], list)
    assert isinstance(result["summary"], dict)
    assert result["source_shape"] == "rows"
    assert isinstance(result["truncated"], bool)
    assert isinstance(result["warnings"], list)
    assert isinstance(result["filters_applied"], dict)
    assert result["raw_included"] is False


@pytest.mark.asyncio
async def test_pf_states_no_raw_in_output_states() -> None:
    """State rows in the output never expose the raw field."""
    tool = PfStatesTool(FakeClient())
    result = await tool.execute({})

    for state in result["states"]:
        assert "raw" not in state


@pytest.mark.asyncio
async def test_pf_states_maps_fields_correctly() -> None:
    """Normalized state fields map from raw OPNsense keys."""
    tool = PfStatesTool(FakeClient())
    result = await tool.execute({})

    state = result["states"][0]
    assert state["protocol"] == "tcp"
    assert state["src"] == "10.0.0.5"
    assert state["dst"] == "1.2.3.4"
    assert state["src_port"] == 54321
    assert state["dst_port"] == 443
    assert state["interface"] == "em0"


@pytest.mark.asyncio
async def test_pf_states_summary_included_by_default() -> None:
    """Summary is computed and non-empty by default."""
    tool = PfStatesTool(FakeClient())
    result = await tool.execute({})

    assert "total_states" in result["summary"]
    assert "by_protocol" in result["summary"]


@pytest.mark.asyncio
async def test_pf_states_summary_disabled() -> None:
    """summary=False skips computation and returns empty dict."""
    tool = PfStatesTool(FakeClient())
    result = await tool.execute({"summary": False})

    assert result["summary"] == {}


@pytest.mark.asyncio
async def test_pf_states_truncated_flag() -> None:
    """Truncated is True when API total exceeds requested limit."""
    client = FakeClient(states=_STATES_PAYLOAD, meta=_META_PAYLOAD)
    tool = PfStatesTool(client)
    # total=6183 rows but limit=10 → truncated
    result = await tool.execute({"limit": 10})

    assert result["truncated"] is True


@pytest.mark.asyncio
async def test_pf_states_not_truncated_when_total_fits() -> None:
    """Truncated is False when total <= limit."""
    small_payload = {"rows": [_SAMPLE_ROW], "total": 1, "rowCount": 1, "current": 1}
    tool = PfStatesTool(FakeClient(states=small_payload))
    result = await tool.execute({"limit": 100})

    assert result["truncated"] is False


# ---------------------------------------------------------------------------
# PfStatesTool — filtering
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pf_states_filter_src_ip_match() -> None:
    """src_ip filter returns only matching rows."""
    tool = PfStatesTool(FakeClient())
    result = await tool.execute({"src_ip": "10.0.0.5"})
    assert len(result["states"]) == 1


@pytest.mark.asyncio
async def test_pf_states_filter_src_ip_no_match() -> None:
    """src_ip filter returns empty list when no match."""
    tool = PfStatesTool(FakeClient())
    result = await tool.execute({"src_ip": "192.168.99.1"})
    assert result["states"] == []


@pytest.mark.asyncio
async def test_pf_states_filter_dst_ip() -> None:
    """dst_ip filter matches destination address."""
    tool = PfStatesTool(FakeClient())
    result = await tool.execute({"dst_ip": "1.2.3.4"})
    assert len(result["states"]) == 1


@pytest.mark.asyncio
async def test_pf_states_filter_ip_matches_src_or_dst() -> None:
    """ip filter matches either src or dst."""
    tool = PfStatesTool(FakeClient())
    result_src = await tool.execute({"ip": "10.0.0.5"})
    result_dst = await tool.execute({"ip": "1.2.3.4"})
    result_none = await tool.execute({"ip": "9.9.9.9"})

    assert len(result_src["states"]) == 1
    assert len(result_dst["states"]) == 1
    assert result_none["states"] == []


@pytest.mark.asyncio
async def test_pf_states_filter_protocol() -> None:
    """protocol filter is case-insensitive."""
    tool = PfStatesTool(FakeClient())
    assert len((await tool.execute({"protocol": "tcp"}))["states"]) == 1
    assert len((await tool.execute({"protocol": "TCP"}))["states"]) == 1
    assert (await tool.execute({"protocol": "udp"}))["states"] == []


@pytest.mark.asyncio
async def test_pf_states_filter_dst_port() -> None:
    """dst_port filter matches integer port value."""
    tool = PfStatesTool(FakeClient())
    assert len((await tool.execute({"dst_port": 443}))["states"]) == 1
    assert (await tool.execute({"dst_port": 80}))["states"] == []


@pytest.mark.asyncio
async def test_pf_states_filter_interface() -> None:
    """interface filter is case-insensitive."""
    tool = PfStatesTool(FakeClient())
    assert len((await tool.execute({"interface": "em0"}))["states"]) == 1
    assert len((await tool.execute({"interface": "EM0"}))["states"]) == 1
    assert (await tool.execute({"interface": "vtnet0"}))["states"] == []


@pytest.mark.asyncio
async def test_pf_states_filter_state_substring() -> None:
    """state filter matches as substring."""
    tool = PfStatesTool(FakeClient())
    assert len((await tool.execute({"state": "ESTABLISHED"}))["states"]) == 1
    assert (await tool.execute({"state": "SYN_SENT"}))["states"] == []


@pytest.mark.asyncio
async def test_pf_states_filters_recorded_in_envelope() -> None:
    """Applied filters are echoed in filters_applied."""
    tool = PfStatesTool(FakeClient())
    result = await tool.execute({"src_ip": "10.0.0.5", "protocol": "tcp", "limit": 50})

    fa = result["filters_applied"]
    assert fa["src_ip"] == "10.0.0.5"
    assert fa["protocol"] == "tcp"
    assert fa["limit"] == 50


# ---------------------------------------------------------------------------
# PfStatesTool — limit validation and clamping
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pf_states_limit_zero_returns_error() -> None:
    """limit=0 returns status=error."""
    tool = PfStatesTool(FakeClient())
    result = await tool.execute({"limit": 0})

    assert result["status"] == "error"
    assert "limit" in result["error"]


@pytest.mark.asyncio
async def test_pf_states_limit_negative_returns_error() -> None:
    """Negative limit returns status=error."""
    tool = PfStatesTool(FakeClient())
    result = await tool.execute({"limit": -5})

    assert result["status"] == "error"
    assert result["states"] == []


@pytest.mark.asyncio
async def test_pf_states_limit_above_max_clamped() -> None:
    """limit > 5000 is clamped to 5000 with limit_capped=True and a warning."""
    tool = PfStatesTool(FakeClient())
    result = await tool.execute({"limit": 9999})

    assert result["status"] == "success"
    assert result["filters_applied"]["limit"] == 5000
    assert result["filters_applied"]["limit_capped"] is True
    assert any("clamped" in w for w in result["warnings"])


@pytest.mark.asyncio
async def test_pf_states_limit_exactly_5000_not_clamped() -> None:
    """limit=5000 is accepted as-is without capping."""
    tool = PfStatesTool(FakeClient())
    result = await tool.execute({"limit": 5000})

    assert result["status"] == "success"
    assert result["filters_applied"].get("limit_capped") is None
    assert result["warnings"] == []


@pytest.mark.asyncio
async def test_pf_states_invalid_limit_type_returns_error() -> None:
    """Non-integer limit returns status=error."""
    tool = PfStatesTool(FakeClient())
    result = await tool.execute({"limit": "not_a_number"})

    assert result["status"] == "error"
    assert "invalid limit" in result["error"]


# ---------------------------------------------------------------------------
# PfStatesTool — client errors
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pf_states_client_error_returns_error_envelope() -> None:
    """Client exception produces status=error with concise message."""
    tool = PfStatesTool(FakeClient(raise_on="states"))
    result = await tool.execute({})

    assert result["status"] == "error"
    assert "states API error" in result["error"]
    assert result["states"] == []


@pytest.mark.asyncio
async def test_pf_states_no_client_returns_error() -> None:
    """Missing client returns status=error immediately."""
    tool = PfStatesTool(None)
    result = await tool.execute({})

    assert result["status"] == "error"
    assert "No client" in result["error"]


# ---------------------------------------------------------------------------
# PfStatisticsTool — success path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pf_statistics_success_envelope() -> None:
    """Success returns required keys."""
    tool = PfStatisticsTool(FakeClient())
    result = await tool.execute({})

    assert result["status"] == "success"
    assert "state_table" in result
    assert "counters" in result
    assert "health" in result
    assert "warnings" in result


@pytest.mark.asyncio
async def test_pf_statistics_empty_payload_fallback() -> None:
    """Empty pf_statistics payload falls back to state table metadata."""
    tool = PfStatisticsTool(FakeClient(statistics=_STATS_EMPTY, meta=_META_PAYLOAD))
    result = await tool.execute({})

    assert result["status"] == "success"
    assert result["state_table"]["current"] == 6183
    assert result["state_table"]["limit"] == 1_621_700
    assert result["health"]["level"] == "ok"
    assert any("no counter rows" in w for w in result["warnings"])


@pytest.mark.asyncio
async def test_pf_statistics_with_counters() -> None:
    """Dict payload populates counters field."""
    tool = PfStatisticsTool(FakeClient(statistics=_STATS_DICT, meta=_META_PAYLOAD))
    result = await tool.execute({})

    assert result["status"] == "success"
    assert result["counters"]["state_inserts"] == 42


@pytest.mark.asyncio
async def test_pf_statistics_raw_excluded_by_default() -> None:
    """Raw payload is not included unless include_raw=True."""
    tool = PfStatisticsTool(FakeClient())
    result = await tool.execute({})

    assert "raw" not in result


@pytest.mark.asyncio
async def test_pf_statistics_include_raw() -> None:
    """include_raw=True adds raw key to result."""
    tool = PfStatisticsTool(FakeClient(statistics=_STATS_DICT))
    result = await tool.execute({"include_raw": True})

    assert "raw" in result
    assert result["raw"] == _STATS_DICT


@pytest.mark.asyncio
async def test_pf_statistics_include_raw_false_explicit() -> None:
    """include_raw=False omits raw key."""
    tool = PfStatisticsTool(FakeClient(statistics=_STATS_DICT))
    result = await tool.execute({"include_raw": False})

    assert "raw" not in result


# ---------------------------------------------------------------------------
# PfStatisticsTool — client errors
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pf_statistics_client_error_returns_error_envelope() -> None:
    """Client exception returns status=error with message."""
    tool = PfStatisticsTool(FakeClient(raise_on="all"))
    result = await tool.execute({})

    assert result["status"] == "error"
    assert "statistics API error" in result["error"]


@pytest.mark.asyncio
async def test_pf_statistics_no_client_returns_error() -> None:
    """Missing client returns status=error immediately."""
    tool = PfStatisticsTool(None)
    result = await tool.execute({})

    assert result["status"] == "error"
    assert "No client" in result["error"]
