"""Tests for PF diagnostics normalization helpers."""

from __future__ import annotations

import json
from pathlib import Path

from opnsense_mcp.utils.pf_diagnostics import (
    filter_pf_states,
    normalize_pf_state,
    normalize_pf_states_payload,
    normalize_pf_statistics,
    summarize_pf_states,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "phase0-diagnostics"


def load_states_payload() -> dict:
    """Load live-shaped query_states payload."""
    return json.loads((FIXTURE_DIR / "query_states_sample.json").read_text())


def test_normalize_pf_states_payload_rows_shape() -> None:
    """query_states rows are detected and returned with source shape."""
    rows, shape = normalize_pf_states_payload(load_states_payload())

    assert shape == "rows"
    assert len(rows) == 10


def test_normalize_pf_state_maps_endpoints_and_counters() -> None:
    """Live-shaped PF state keys map to stable endpoint and counter fields."""
    rows, _shape = normalize_pf_states_payload(load_states_payload())

    state = normalize_pf_state(rows[0])

    assert state["protocol"] == "udp"
    assert state["src"] == rows[0]["src_addr"]
    assert state["dst"] == rows[0]["dst_addr"]
    assert state["src_port"] == int(rows[0]["src_port"])
    assert state["dst_port"] == int(rows[0]["dst_port"])
    assert state["packets"] == sum(rows[0]["pkts"])
    assert state["bytes"] == sum(rows[0]["bytes"])
    assert state["raw"] == rows[0]


def test_filter_pf_states_matches_endpoint_fields() -> None:
    """Filtering applies to normalized exact fields and IP OR semantics."""
    rows, _shape = normalize_pf_states_payload(load_states_payload())
    states = [normalize_pf_state(row) for row in rows]
    first = states[0]

    assert filter_pf_states(states, src_ip=first["src"]) == [first]
    assert first in filter_pf_states(states, ip=first["dst"])
    assert first in filter_pf_states(states, protocol=first["protocol"])
    assert first in filter_pf_states(states, dst_port=first["dst_port"])
    assert filter_pf_states(states, state="no_traffic") == [first]


def test_summarize_pf_states_counts_common_dimensions() -> None:
    """PF state summary includes protocol, source, destination, and table health."""
    payload = load_states_payload()
    states = [normalize_pf_state(row) for row in payload["rows"]]

    summary = summarize_pf_states(
        states,
        total_states=payload["total"],
        limit=1_621_700,
        requested_limit=5,
    )

    assert summary["total_states"] == payload["total"]
    assert summary["returned_states"] == len(states)
    assert summary["truncated"] is True
    assert summary["by_protocol"]["tcp"] >= 1
    assert summary["top_sources"]
    assert summary["top_destination_ports"]
    assert summary["state_table"]["health"]["level"] == "ok"


def test_normalize_pf_statistics_empty_payload_falls_back_to_meta() -> None:
    """Empty pf_statistics payload still reports state table pressure."""
    stats = normalize_pf_statistics(
        [], state_table_meta={"current": "6183", "limit": "1621700"}
    )

    assert stats["state_table"]["current"] == 6183
    assert stats["state_table"]["limit"] == 1_621_700
    assert stats["health"]["level"] == "ok"
    assert stats["warnings"] == ["pf_statistics endpoint returned no counter rows"]
