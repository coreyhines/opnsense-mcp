"""Tests for opnsense_mcp/utils/shaper_interpret.py — bucket 2a."""

from __future__ import annotations

import pytest

from opnsense_mcp.utils.shaper_interpret import (
    RUNTIME_SCHEDULER_ALIASES,
    clear_baselines,
    format_statistics_summary,
    fqcodel_statistics_layout_ok,
    get_baseline,
    interpret_statistics,
    scheduler_matches,
    store_baseline,
)
from opnsense_mcp.utils.shaper_types import InterpretationResult

# ---------------------------------------------------------------------------
# Shared fixture data
# ---------------------------------------------------------------------------

# Phase 0 spike: config fq_codel, runtime inner FIFO with expected FQ-CoDel layout
STATS_DRIFT = {
    "status": "ok",
    "items": [
        {
            "type": "pipe",
            "uuid": "e93038e5-1234",
            "description": "Download pipe",
            "pipe": "10000",
            "id": 10000,
            "bw": "1776 Mbit/s",
            "scheduler": {"sched_type": "FIFO"},
            "flowset": {"sched_nr": "10000"},
        },
        {
            "type": "pipe",
            "uuid": "f9b19d27-5678",
            "description": "Upload pipe",
            "pipe": "10001",
            "id": 10001,
            "bw": "325 Mbit/s",
            "scheduler": {"sched_type": "FIFO"},
            "flowset": {"sched_nr": "10001"},
        },
        {
            "type": "rule",
            "rule_uuid": "690c995b-abc",
            "description": "Download Rule",
            "pkts": 3200000,
            "bytes": 2500000000,
            "accessed": "2026-06-20",
        },
        {
            "type": "rule",
            "rule_uuid": "5122c31a-def",
            "description": "Upload Rule",
            "pkts": 2800000,
            "bytes": 2200000000,
            "accessed": "2026-06-20",
        },
    ],
}

# True drift: config fq_codel but runtime FIFO without FQ-CoDel flowset layout
STATS_TRUE_DRIFT = {
    "status": "ok",
    "items": [
        {
            "type": "pipe",
            "uuid": "e93038e5-1234",
            "description": "Download pipe",
            "bw": "1776 Mbit/s",
            "scheduler": {"sched_type": "FIFO"},
        },
        {
            "type": "rule",
            "rule_uuid": "690c995b-abc",
            "description": "Download Rule",
            "pkts": 3200000,
            "bytes": 2500000000,
            "accessed": "2026-06-20",
        },
    ],
}

# Config pipes with fq_codel — matches STATS_DRIFT pipes by uuid
PIPES_FQ_CODEL = [
    {"uuid": "e93038e5-1234", "scheduler": "fq_codel", "description": "Download pipe"},
    {"uuid": "f9b19d27-5678", "scheduler": "fq_codel", "description": "Upload pipe"},
]

# No drift: runtime FQ_CODEL matches config fq_codel
STATS_NO_DRIFT = {
    "status": "ok",
    "items": [
        {
            "type": "pipe",
            "uuid": "e93038e5-1234",
            "description": "Download pipe",
            "bw": "1776 Mbit/s",
            "scheduler": {"sched_type": "FQ_CODEL"},
        },
        {
            "type": "rule",
            "rule_uuid": "690c995b-abc",
            "description": "Download Rule",
            "pkts": 3200000,
            "bytes": 2500000000,
            "accessed": "2026-06-20",
        },
    ],
}

# Rule with zero pkts — should trigger warning
STATS_ZERO_PKTS = {
    "status": "ok",
    "items": [
        {
            "type": "rule",
            "rule_uuid": "690c995b-abc",
            "description": "Download Rule",
            "pkts": 0,
            "bytes": 0,
            "accessed": "",
        },
    ],
}

# Healthy stats: no pipes provided, rules have traffic
STATS_HEALTHY = {
    "status": "ok",
    "items": [
        {
            "type": "rule",
            "rule_uuid": "690c995b-abc",
            "description": "Download Rule",
            "pkts": 100,
            "bytes": 50000,
            "accessed": "2026-06-20",
        },
    ],
}

PIPES_ECN_ON = [
    {
        "uuid": "e93038e5-1234",
        "scheduler": "fq_codel",
        "description": "Download pipe",
        "bandwidth": 1776,
        "bandwidth_metric": "Mbit",
        "codel_ecn_enable": True,
    },
]

STATS_FLOWSET_DROPS = {
    "status": "ok",
    "items": [
        {
            "type": "pipe",
            "uuid": "e93038e5-1234",
            "description": "Download pipe",
            "bw": "1776 Mbit/s",
            "scheduler": {"sched_type": "FQ_CODEL"},
            "flowset": [{"drops": 42}],
        },
    ],
}

STATS_FLOWSET_DROPS_DICT = {
    "status": "ok",
    "items": [
        {
            "type": "pipe",
            "uuid": "e93038e5-1234",
            "description": "Download pipe",
            "pipe": "10000",
            "bw": "1776 Mbit/s",
            "scheduler": {"sched_type": "FIFO"},
            "flowset": {"sched_nr": "10000", "drops": 7},
        },
    ],
}

STATS_DROPTAIL_LOAD = {
    "status": "ok",
    "items": [
        {
            "type": "pipe",
            "uuid": "e93038e5-1234",
            "description": "Download pipe",
            "bw": "1776 Mbit/s",
            "scheduler": {"sched_type": "FIFO", "queue_params": "droptail"},
        },
        {
            "type": "rule",
            "rule_uuid": "690c995b-abc",
            "description": "Download Rule",
            "pkts": 150_000,
            "bytes": 2500000000,
            "accessed": "2026-06-20",
        },
    ],
}

STATS_QUEUE_FLOWS = {
    "status": "ok",
    "items": [
        {
            "type": "queue",
            "uuid": "q-1",
            "description": "Download queue",
            "flows": 12,
        },
    ],
}

STATS_ECN_RUNTIME_OFF = {
    "status": "ok",
    "items": [
        {
            "type": "pipe",
            "uuid": "e93038e5-1234",
            "description": "Download pipe",
            "bw": "1776 Mbit/s",
            "scheduler": {"sched_type": "FQ_CODEL", "codel_ecn_enable": False},
        },
    ],
}

STATS_BW_MISMATCH = {
    "status": "ok",
    "items": [
        {
            "type": "pipe",
            "uuid": "e93038e5-1234",
            "description": "Download pipe",
            "bw": "1500 Mbit/s",
            "scheduler": {"sched_type": "FQ_CODEL"},
        },
    ],
}


# ---------------------------------------------------------------------------
# Teardown helper: clear baselines between tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_baselines():
    clear_baselines()
    yield
    clear_baselines()


# ---------------------------------------------------------------------------
# RUNTIME_SCHEDULER_ALIASES
# ---------------------------------------------------------------------------


def test_runtime_scheduler_aliases_contains_fq_codel():
    assert "fq_codel" in RUNTIME_SCHEDULER_ALIASES


def test_runtime_scheduler_aliases_contains_fifo():
    assert "fifo" in RUNTIME_SCHEDULER_ALIASES


def test_runtime_scheduler_aliases_values_are_strings():
    for key, val in RUNTIME_SCHEDULER_ALIASES.items():
        assert isinstance(key, str), f"key {key!r} not str"
        assert isinstance(val, str), f"value {val!r} for key {key!r} not str"


# ---------------------------------------------------------------------------
# scheduler_matches
# ---------------------------------------------------------------------------


def test_scheduler_matches_fq_codel_fifo_is_drift():
    # The critical finding from Phase 0: config fq_codel vs runtime FIFO
    assert scheduler_matches("fq_codel", "FIFO") is False


def test_scheduler_matches_fq_codel_fq_codel_no_drift():
    assert scheduler_matches("fq_codel", "FQ_CODEL") is True


def test_scheduler_matches_fifo_fifo_no_drift():
    assert scheduler_matches("fifo", "FIFO") is True


def test_scheduler_matches_case_insensitive_config():
    # Runtime strings are uppercase in OPNsense stats; config keys lowercase
    assert scheduler_matches("fq_codel", "fq_codel") is True


def test_scheduler_matches_empty_config_returns_false():
    assert scheduler_matches("", "FIFO") is False


def test_scheduler_matches_empty_runtime_returns_false():
    assert scheduler_matches("fifo", "") is False


# ---------------------------------------------------------------------------
# interpret_statistics — scheduler drift (critical)
# ---------------------------------------------------------------------------


def test_interpret_statistics_drift_verdict_is_critical():
    result = interpret_statistics(STATS_TRUE_DRIFT, pipes=PIPES_FQ_CODEL)
    assert result.verdict == "critical"


def test_interpret_statistics_fqcodel_layout_not_drift():
    result = interpret_statistics(STATS_DRIFT, pipes=PIPES_FQ_CODEL)
    drift_hints = [h for h in result.hints if "SCHEDULER_DRIFT" in h]
    assert drift_hints == []
    assert result.verdict != "critical"


def test_fqcodel_statistics_layout_ok_matches_pipe_number():
    pipe = STATS_DRIFT["items"][0]
    assert fqcodel_statistics_layout_ok(pipe, "fq_codel") is True
    assert fqcodel_statistics_layout_ok(pipe, "fifo") is False


def test_interpret_statistics_drift_hint_references_scheduler_drift():
    result = interpret_statistics(STATS_TRUE_DRIFT, pipes=PIPES_FQ_CODEL)
    drift_hints = [
        h for h in result.hints if "drift" in h.lower() or "SCHEDULER_DRIFT" in h
    ]
    assert len(drift_hints) >= 1


def test_interpret_statistics_drift_hint_names_a_pipe():
    result = interpret_statistics(STATS_TRUE_DRIFT, pipes=PIPES_FQ_CODEL)
    pipe_hints = [
        h
        for h in result.hints
        if "Download pipe" in h or "Upload pipe" in h or "pipe" in h.lower()
    ]
    assert len(pipe_hints) >= 1


def test_interpret_statistics_no_drift_no_critical_verdict():
    pipes_matching = [
        {
            "uuid": "e93038e5-1234",
            "scheduler": "fq_codel",
            "description": "Download pipe",
        },
    ]
    result = interpret_statistics(STATS_NO_DRIFT, pipes=pipes_matching)
    assert result.verdict != "critical"


def test_interpret_statistics_no_drift_no_drift_hints():
    pipes_matching = [
        {
            "uuid": "e93038e5-1234",
            "scheduler": "fq_codel",
            "description": "Download pipe",
        },
    ]
    result = interpret_statistics(STATS_NO_DRIFT, pipes=pipes_matching)
    drift_hints = [h for h in result.hints if "drift" in h.lower()]
    assert drift_hints == []


def test_interpret_statistics_no_pipes_arg_skips_drift_check():
    # Without config pipes we cannot detect drift — no critical hint
    result = interpret_statistics(STATS_DRIFT)
    drift_hints = [h for h in result.hints if "drift" in h.lower()]
    assert drift_hints == []


# ---------------------------------------------------------------------------
# interpret_statistics — zero pkts (warning)
# ---------------------------------------------------------------------------


def test_interpret_statistics_zero_pkts_verdict_is_warning():
    result = interpret_statistics(STATS_ZERO_PKTS)
    assert result.verdict in ("warning", "critical")


def test_interpret_statistics_zero_pkts_hint_present():
    result = interpret_statistics(STATS_ZERO_PKTS)
    zero_hints = [
        h
        for h in result.hints
        if "zero" in h.lower() or "pkts" in h.lower() or "RULE_PKTS_ZERO" in h
    ]
    assert len(zero_hints) >= 1


def test_interpret_statistics_nonzero_pkts_no_zero_hint():
    result = interpret_statistics(STATS_DRIFT)
    zero_hints = [h for h in result.hints if "zero" in h.lower() and "pkt" in h.lower()]
    assert zero_hints == []


# ---------------------------------------------------------------------------
# interpret_statistics — BR-fix-b hints (drops, util, ECN)
# ---------------------------------------------------------------------------


def test_interpret_statistics_flowset_drops_hint():
    result = interpret_statistics(STATS_FLOWSET_DROPS)
    assert any("[PIPE_FLOWSET_DROPS]" in h for h in result.hints)
    assert result.verdict == "warning"


def test_interpret_statistics_flowset_drops_dict_format():
    result = interpret_statistics(STATS_FLOWSET_DROPS_DICT)
    assert any("[PIPE_FLOWSET_DROPS]" in h for h in result.hints)
    assert any("7 drop" in h for h in result.hints)


def test_interpret_statistics_single_queue_flow_no_hint():
    stats = {
        "status": "ok",
        "items": [
            {
                "type": "queue",
                "uuid": "q-1",
                "description": "Download queue",
                "flows": 1,
            },
        ],
    }
    result = interpret_statistics(stats)
    assert not any("[QUEUE_FLOWS_ACTIVE]" in h for h in result.hints)


def test_interpret_statistics_droptail_load_hint():
    result = interpret_statistics(STATS_DROPTAIL_LOAD)
    assert any("[PIPE_DROPTAIL_LOAD]" in h for h in result.hints)
    assert result.verdict == "warning"


def test_interpret_statistics_queue_flows_hint():
    result = interpret_statistics(STATS_QUEUE_FLOWS)
    assert any("[QUEUE_FLOWS_ACTIVE]" in h for h in result.hints)
    assert result.verdict == "warning"


def test_interpret_statistics_ecn_runtime_off_hint():
    result = interpret_statistics(STATS_ECN_RUNTIME_OFF, pipes=PIPES_ECN_ON)
    assert any("[ECN_RUNTIME_OFF]" in h for h in result.hints)
    assert result.verdict == "warning"


def test_interpret_statistics_ecn_ineffective_on_drift():
    result = interpret_statistics(STATS_TRUE_DRIFT, pipes=PIPES_ECN_ON)
    assert any("[ECN_INEFFECTIVE]" in h for h in result.hints)


def test_interpret_statistics_bw_mismatch_hint():
    result = interpret_statistics(STATS_BW_MISMATCH, pipes=PIPES_ECN_ON)
    assert any("[PIPE_BW_MISMATCH]" in h for h in result.hints)
    assert result.verdict == "warning"


# ---------------------------------------------------------------------------
# interpret_statistics — verdict logic
# ---------------------------------------------------------------------------


def test_interpret_statistics_success_when_no_issues():
    result = interpret_statistics(STATS_HEALTHY)
    assert result.verdict == "success"
    assert result.hints == []


def test_interpret_statistics_returns_interpretation_result():
    result = interpret_statistics(STATS_HEALTHY)
    assert isinstance(result, InterpretationResult)


def test_interpret_statistics_rule_stats_populated():
    result = interpret_statistics(STATS_DRIFT)
    assert isinstance(result.rule_stats, dict)
    assert len(result.rule_stats) >= 1


def test_interpret_statistics_rule_stats_keyed_by_uuid():
    result = interpret_statistics(STATS_DRIFT)
    assert "690c995b-abc" in result.rule_stats or "5122c31a-def" in result.rule_stats


def test_interpret_statistics_rule_stats_has_pkts_and_bytes():
    result = interpret_statistics(STATS_DRIFT)
    for stats in result.rule_stats.values():
        assert "pkts" in stats
        assert "bytes" in stats


# ---------------------------------------------------------------------------
# Baseline store — store / get / clear
# ---------------------------------------------------------------------------


def test_store_and_get_baseline_roundtrip():
    store_baseline("base-001", STATS_DRIFT)
    retrieved = get_baseline("base-001")
    assert retrieved == STATS_DRIFT


def test_get_baseline_missing_key_returns_none():
    assert get_baseline("nonexistent") is None


def test_clear_baselines_removes_stored_entries():
    store_baseline("base-a", STATS_DRIFT)
    store_baseline("base-b", STATS_NO_DRIFT)
    clear_baselines()
    assert get_baseline("base-a") is None
    assert get_baseline("base-b") is None


def test_store_baseline_overwrites_existing_key():
    store_baseline("base-x", STATS_DRIFT)
    store_baseline("base-x", STATS_HEALTHY)
    assert get_baseline("base-x") == STATS_HEALTHY


# ---------------------------------------------------------------------------
# interpret_statistics — baseline delta
# ---------------------------------------------------------------------------


def test_interpret_statistics_no_baseline_delta_is_none():
    result = interpret_statistics(STATS_DRIFT)
    assert result.baseline_delta is None


def test_interpret_statistics_missing_baseline_id_returns_none_delta():
    result = interpret_statistics(STATS_DRIFT, baseline_id="nonexistent-baseline")
    assert result.baseline_delta is None


def test_interpret_statistics_with_baseline_delta_not_none():
    store_baseline("base-001", STATS_DRIFT)
    result = interpret_statistics(STATS_DRIFT, baseline_id="base-001")
    assert result.baseline_delta is not None


def test_interpret_statistics_baseline_pkts_delta_correct():
    prior = {
        "status": "ok",
        "items": [
            {
                "type": "rule",
                "rule_uuid": "rule-1",
                "description": "Download Rule",
                "pkts": 1000,
                "bytes": 500000,
                "accessed": "",
            },
        ],
    }
    current = {
        "status": "ok",
        "items": [
            {
                "type": "rule",
                "rule_uuid": "rule-1",
                "description": "Download Rule",
                "pkts": 1500,
                "bytes": 700000,
                "accessed": "",
            },
        ],
    }
    store_baseline("base-delta", prior)
    result = interpret_statistics(current, baseline_id="base-delta")
    assert result.baseline_delta is not None
    rule_delta = result.baseline_delta["rule-1"]
    assert rule_delta["pkts_delta"] == 500
    assert rule_delta["bytes_delta"] == 200000


def test_interpret_statistics_baseline_missing_rule_skips_delta():
    # Baseline has a different rule UUID — no delta entry for current rule
    prior = {
        "status": "ok",
        "items": [
            {
                "type": "rule",
                "rule_uuid": "other-rule",
                "description": "Other Rule",
                "pkts": 1000,
                "bytes": 500000,
                "accessed": "",
            },
        ],
    }
    current = {
        "status": "ok",
        "items": [
            {
                "type": "rule",
                "rule_uuid": "rule-1",
                "description": "Download Rule",
                "pkts": 1500,
                "bytes": 700000,
                "accessed": "",
            },
        ],
    }
    store_baseline("base-mismatch", prior)
    result = interpret_statistics(current, baseline_id="base-mismatch")
    assert result.baseline_delta is not None
    assert "rule-1" not in result.baseline_delta


# ---------------------------------------------------------------------------
# format_statistics_summary
# ---------------------------------------------------------------------------


def test_format_statistics_summary_returns_str():
    result = interpret_statistics(STATS_DRIFT, pipes=PIPES_FQ_CODEL)
    summary = format_statistics_summary(STATS_DRIFT, result)
    assert isinstance(summary, str)


def test_format_statistics_summary_non_empty():
    result = interpret_statistics(STATS_DRIFT, pipes=PIPES_FQ_CODEL)
    summary = format_statistics_summary(STATS_DRIFT, result)
    assert len(summary.strip()) > 0


def test_format_statistics_summary_mentions_scheduler_drift():
    result = interpret_statistics(STATS_TRUE_DRIFT, pipes=PIPES_FQ_CODEL)
    summary = format_statistics_summary(STATS_DRIFT, result)
    assert (
        "drift" in summary.lower()
        or "FIFO" in summary
        or "scheduler" in summary.lower()
    )


def test_format_statistics_summary_includes_rule_info():
    result = interpret_statistics(STATS_DRIFT, pipes=PIPES_FQ_CODEL)
    summary = format_statistics_summary(STATS_DRIFT, result)
    # Must mention at least one rule or packet count
    assert "Rule" in summary or "pkts" in summary.lower() or "3200000" in summary


def test_format_statistics_summary_healthy_no_drift_mention():
    result = interpret_statistics(STATS_HEALTHY)
    summary = format_statistics_summary(STATS_HEALTHY, result)
    assert isinstance(summary, str)
    # No drift hints — summary should not say "drift"
    assert "drift" not in summary.lower()
