"""Tests for opnsense_mcp/utils/shaper_audit_rules.py — bucket 2b."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from opnsense_mcp.utils.shaper_audit_rules import (
    explain_shaper_config,
    format_audit_summary,
    run_audit,
)
from opnsense_mcp.utils.shaper_normalize import (
    normalize_pipe,
    normalize_queue,
    normalize_rule,
)
from opnsense_mcp.utils.shaper_types import AuditResult

FIXTURES = Path(__file__).parent / "fixtures" / "shaper"


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def load_fixture_models() -> tuple[list, list, list, dict]:
    pipes = [normalize_pipe(row) for row in load("search_pipes.json")["rows"]]
    queues = [normalize_queue(row) for row in load("search_queues.json")["rows"]]
    rules = [normalize_rule(row) for row in load("search_rules.json")["rows"]]
    statistics = load("statistics.json")
    return pipes, queues, rules, statistics


# ---------------------------------------------------------------------------
# Fixture baseline audit
# ---------------------------------------------------------------------------


def test_run_audit_fixture_with_statistics_no_scheduler_drift():
    pipes, queues, rules, statistics = load_fixture_models()
    audit = run_audit(
        pipes=pipes,
        queues=queues,
        rules=rules,
        statistics=statistics,
    )
    drift = [f for f in audit.findings if f.code == "SCHEDULER_DRIFT"]
    assert drift == []


def test_run_audit_true_scheduler_drift_without_fqcodel_layout():
    pipes, queues, rules, statistics = load_fixture_models()
    stats_bad = deepcopy(statistics)
    for item in stats_bad["items"]:
        if item.get("type") == "pipe":
            item.pop("flowset", None)
            item.pop("pipe", None)
            item.pop("id", None)
    audit = run_audit(
        pipes=pipes,
        queues=queues,
        rules=rules,
        statistics=stats_bad,
    )
    assert audit.status == "critical"
    drift = [f for f in audit.findings if f.code == "SCHEDULER_DRIFT"]
    assert len(drift) == 2


def test_run_audit_fixture_ipv6_missing():
    pipes, queues, rules, _ = load_fixture_models()
    audit = run_audit(pipes=pipes, queues=queues, rules=rules)
    ipv6 = [f for f in audit.findings if f.code == "IPV6_MISSING"]
    assert len(ipv6) == 1
    assert ipv6[0].severity == "warning"


def test_run_audit_fixture_no_scheduler_drift_without_statistics():
    pipes, queues, rules, _ = load_fixture_models()
    audit = run_audit(pipes=pipes, queues=queues, rules=rules)
    drift = [f for f in audit.findings if f.code == "SCHEDULER_DRIFT"]
    assert drift == []


def test_run_audit_fixture_pipes_present_no_pipes_missing():
    pipes, queues, rules, _ = load_fixture_models()
    audit = run_audit(pipes=pipes, queues=queues, rules=rules)
    missing = [f for f in audit.findings if f.code == "PIPES_MISSING"]
    assert missing == []


def test_run_audit_fixture_rules_target_queues_not_pipes():
    pipes, queues, rules, _ = load_fixture_models()
    audit = run_audit(pipes=pipes, queues=queues, rules=rules)
    bad = [f for f in audit.findings if f.code == "RULE_TARGETS_PIPE"]
    assert bad == []


def test_run_audit_fixture_queues_linked_to_correct_pipes():
    pipes, queues, rules, _ = load_fixture_models()
    audit = run_audit(pipes=pipes, queues=queues, rules=rules)
    wrong = [f for f in audit.findings if f.code == "QUEUE_WRONG_PIPE"]
    assert wrong == []


# ---------------------------------------------------------------------------
# Scheduler drift
# ---------------------------------------------------------------------------


def test_run_audit_scheduler_drift_uses_scheduler_matches():
    pipes, queues, rules, statistics = load_fixture_models()
    stats_bad = deepcopy(statistics)
    for item in stats_bad["items"]:
        if item.get("type") == "pipe":
            item.pop("flowset", None)
            item.pop("pipe", None)
            item.pop("id", None)
    audit = run_audit(
        pipes=pipes,
        queues=queues,
        rules=rules,
        statistics=stats_bad,
    )
    assert any(
        "FIFO" in f.message or "fifo" in f.message.lower() for f in audit.findings
    )


def test_run_audit_no_drift_when_runtime_matches_config():
    pipes, queues, rules, statistics = load_fixture_models()
    stats_ok = deepcopy(statistics)
    for item in stats_ok["items"]:
        if item.get("type") == "pipe":
            item["scheduler"] = {"sched_type": "FQ_CODEL"}
    audit = run_audit(
        pipes=pipes,
        queues=queues,
        rules=rules,
        statistics=stats_ok,
    )
    drift = [f for f in audit.findings if f.code == "SCHEDULER_DRIFT"]
    assert drift == []


# ---------------------------------------------------------------------------
# IPv6 pairing
# ---------------------------------------------------------------------------


def test_run_audit_ipv6_present_when_paired_rules_added():
    pipes, queues, rules, _ = load_fixture_models()
    extra = [
        normalize_rule(
            {
                **load("search_rules.json")["rows"][0],
                "uuid": "v6-download",
                "description": "Download Rule IPv6",
                "proto": "ip6",
            }
        ),
        normalize_rule(
            {
                **load("search_rules.json")["rows"][1],
                "uuid": "v6-upload",
                "description": "Upload Rule IPv6",
                "proto": "ip6",
            }
        ),
    ]
    audit = run_audit(pipes=pipes, queues=queues, rules=rules + extra)
    ipv6 = [f for f in audit.findings if f.code == "IPV6_MISSING"]
    assert ipv6 == []


# ---------------------------------------------------------------------------
# LAN shaping
# ---------------------------------------------------------------------------


def test_run_audit_lan_shaping_warning():
    pipes, queues, rules, _ = load_fixture_models()
    lan_rule = normalize_rule(
        {
            "uuid": "lan-rule-1",
            "description": "LAN shaping rule",
            "enabled": "1",
            "interface": "lan",
            "direction": "in",
            "proto": "ip",
            "target": queues[0]["uuid"],
            "sequence": "99",
            "source": "any",
            "destination": "any",
        }
    )
    audit = run_audit(pipes=pipes, queues=queues, rules=rules + [lan_rule])
    lan = [f for f in audit.findings if f.code == "LAN_SHAPING"]
    assert len(lan) == 1
    assert lan[0].severity == "warning"


# ---------------------------------------------------------------------------
# Bandwidth checks
# ---------------------------------------------------------------------------


def test_run_audit_bw_exceeds_line_rate():
    pipes, queues, rules, _ = load_fixture_models()
    audit = run_audit(
        pipes=pipes,
        queues=queues,
        rules=rules,
        wan_line_rate_mbit=1000.0,
    )
    line = [f for f in audit.findings if f.code == "BW_EXCEEDS_LINE_RATE"]
    assert len(line) >= 1
    assert line[0].severity == "error"


def test_run_audit_bw_isp_rate_warning_when_too_high():
    pipes, queues, rules, _ = load_fixture_models()
    audit = run_audit(
        pipes=pipes,
        queues=queues,
        rules=rules,
        isp_download_mbit=1800.0,
        isp_upload_mbit=400.0,
    )
    isp = [f for f in audit.findings if f.code == "BW_ISP_RATE"]
    assert isp
    assert any(f.severity == "warning" for f in isp)


def test_run_audit_bw_isp_rate_info_in_85_95_band():
    pipes, queues, rules, _ = load_fixture_models()
    audit = run_audit(
        pipes=pipes,
        queues=queues,
        rules=rules,
        isp_download_mbit=2000.0,
    )
    isp = [f for f in audit.findings if f.code == "BW_ISP_RATE"]
    assert any(f.severity == "info" for f in isp)


# ---------------------------------------------------------------------------
# Rule targets pipe / queue wrong pipe
# ---------------------------------------------------------------------------


def test_run_audit_rule_targets_pipe_warning():
    pipes, queues, rules, _ = load_fixture_models()
    bad_rule = normalize_rule(
        {
            **load("search_rules.json")["rows"][0],
            "uuid": "bad-target",
            "description": "Targets pipe directly",
            "target": pipes[0]["uuid"],
        }
    )
    audit = run_audit(pipes=pipes, queues=queues, rules=rules + [bad_rule])
    bad = [f for f in audit.findings if f.code == "RULE_TARGETS_PIPE"]
    assert len(bad) == 1


def test_run_audit_queue_wrong_pipe():
    pipes, queues, rules, _ = load_fixture_models()
    bad_queues = deepcopy(queues)
    bad_queues[0] = normalize_queue(
        {
            **load("search_queues.json")["rows"][0],
            "pipe": pipes[1]["uuid"],
        }
    )
    audit = run_audit(pipes=pipes, queues=bad_queues, rules=rules)
    wrong = [f for f in audit.findings if f.code == "QUEUE_WRONG_PIPE"]
    assert len(wrong) >= 1


def test_run_audit_pipes_missing_when_disabled():
    pipes, queues, rules, _ = load_fixture_models()
    bad_pipes = deepcopy(pipes)
    bad_pipes[0] = normalize_pipe(
        {**load("search_pipes.json")["rows"][0], "enabled": "0"}
    )
    audit = run_audit(pipes=bad_pipes, queues=queues, rules=rules)
    missing = [f for f in audit.findings if f.code == "PIPES_MISSING"]
    assert len(missing) == 1
    assert missing[0].severity == "error"


# ---------------------------------------------------------------------------
# Score aggregation
# ---------------------------------------------------------------------------


def test_run_audit_score_deductions():
    pipes, queues, rules, statistics = load_fixture_models()
    audit = run_audit(
        pipes=pipes,
        queues=queues,
        rules=rules,
        statistics=statistics,
    )
    assert audit.score < 100
    assert audit.score >= 0


def test_run_audit_score_floor_zero():
    """Score never drops below zero regardless of finding count."""
    pipes, queues, rules, statistics = load_fixture_models()
    lan_rule = normalize_rule(
        {
            "uuid": "lan-x",
            "description": "LAN rule",
            "enabled": "1",
            "interface": "lan",
            "direction": "in",
            "proto": "ip",
            "target": queues[0]["uuid"],
            "sequence": "1",
            "source": "any",
            "destination": "any",
        }
    )
    bad_pipes = [
        normalize_pipe({**load("search_pipes.json")["rows"][0], "enabled": "0"}),
        normalize_pipe({**load("search_pipes.json")["rows"][1], "enabled": "0"}),
    ]
    audit = run_audit(
        pipes=bad_pipes,
        queues=queues,
        rules=rules + [lan_rule],
        statistics=statistics,
        wan_line_rate_mbit=100.0,
    )
    assert audit.score >= 0
    assert len(audit.findings) >= 3


def test_run_audit_status_error_without_drift():
    pipes, queues, rules, _ = load_fixture_models()
    audit = run_audit(
        pipes=pipes,
        queues=queues,
        rules=rules,
        wan_line_rate_mbit=100.0,
    )
    assert audit.status == "error"
    assert audit.status != "critical"


# ---------------------------------------------------------------------------
# format_audit_summary + explain_shaper_config
# ---------------------------------------------------------------------------


def test_format_audit_summary_returns_markdown():
    pipes, queues, rules, statistics = load_fixture_models()
    stats_bad = deepcopy(statistics)
    for item in stats_bad["items"]:
        if item.get("type") == "pipe":
            item.pop("flowset", None)
            item.pop("pipe", None)
            item.pop("id", None)
    audit = run_audit(
        pipes=pipes,
        queues=queues,
        rules=rules,
        statistics=stats_bad,
    )
    summary = format_audit_summary(audit)
    assert "**Traffic Shaper Audit**" in summary
    assert "SCHEDULER_DRIFT" in summary
    assert "| Severity |" in summary


def test_format_audit_summary_clean_config():
    audit = AuditResult(findings=[], score=100, status="success", summary_lines=[])
    summary = format_audit_summary(audit)
    assert "No issues found" in summary


def test_explain_shaper_config_returns_plain_language():
    pipes, queues, rules, _ = load_fixture_models()
    text = explain_shaper_config(pipes=pipes, queues=queues, rules=rules)
    assert "download" in text.lower() or "upload" in text.lower()
    assert len(text) > 50


def test_explain_shaper_config_mentions_audit_critical():
    pipes, queues, rules, statistics = load_fixture_models()
    stats_bad = deepcopy(statistics)
    for item in stats_bad["items"]:
        if item.get("type") == "pipe":
            item.pop("flowset", None)
            item.pop("pipe", None)
            item.pop("id", None)
    audit = run_audit(
        pipes=pipes,
        queues=queues,
        rules=rules,
        statistics=stats_bad,
    )
    text = explain_shaper_config(
        pipes=pipes,
        queues=queues,
        rules=rules,
        audit=audit,
    )
    assert "scheduler" in text.lower() or "configuration" in text.lower()
