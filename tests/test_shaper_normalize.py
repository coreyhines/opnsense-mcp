"""Tests for opnsense_mcp/utils/shaper_normalize.py — bucket 1a."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opnsense_mcp.utils.shaper_normalize import (
    normalize_pipe,
    normalize_queue,
    normalize_rule,
    parse_boolish,
    pipes_from_settings_get,
    queues_from_settings_get,
    rules_from_settings_get,
    selected_bandwidth_metric,
    selected_enum,
)

FIXTURES = Path(__file__).parent / "fixtures" / "shaper"


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


# ---------------------------------------------------------------------------
# parse_boolish
# ---------------------------------------------------------------------------


def test_parse_boolish_string_one():
    assert parse_boolish("1") is True


def test_parse_boolish_string_zero():
    assert parse_boolish("0") is False


def test_parse_boolish_true():
    assert parse_boolish(True) is True


def test_parse_boolish_false():
    assert parse_boolish(False) is False


def test_parse_boolish_int_one():
    assert parse_boolish(1) is True


def test_parse_boolish_int_zero():
    assert parse_boolish(0) is False


def test_parse_boolish_string_true():
    assert parse_boolish("true") is True


def test_parse_boolish_string_false():
    assert parse_boolish("false") is False


def test_parse_boolish_string_true_uppercase():
    assert parse_boolish("True") is True


def test_parse_boolish_empty_string():
    assert parse_boolish("") is False


# ---------------------------------------------------------------------------
# selected_enum
# ---------------------------------------------------------------------------


def test_selected_enum_returns_selected_key():
    field = {
        "fq_codel": {"selected": 1, "value": "FQ-CoDel"},
        "fifo": {"selected": 0, "value": "FIFO"},
    }
    assert selected_enum(field) == "fq_codel"


def test_selected_enum_returns_other_key():
    field = {
        "fq_codel": {"selected": 0, "value": "FQ-CoDel"},
        "fifo": {"selected": 1, "value": "FIFO"},
    }
    assert selected_enum(field) == "fifo"


def test_selected_enum_empty_dict_returns_empty_string():
    assert selected_enum({}) == ""


def test_selected_enum_none_selected_returns_empty_string():
    field = {
        "fq_codel": {"selected": 0, "value": "FQ-CoDel"},
        "fifo": {"selected": 0, "value": "FIFO"},
    }
    assert selected_enum(field) == ""


def test_selected_enum_string_zero_not_selected():
    field = {
        "fq_codel": {"selected": "0", "value": "FQ-CoDel"},
        "fifo": {"selected": "1", "value": "FIFO"},
    }
    assert selected_enum(field) == "fifo"


def test_selected_enum_wan_interface():
    field = {
        "wan": {"selected": 1, "value": "WAN"},
        "lan": {"selected": 0, "value": "LAN"},
    }
    assert selected_enum(field) == "wan"


# ---------------------------------------------------------------------------
# selected_bandwidth_metric
# ---------------------------------------------------------------------------


def test_selected_bandwidth_metric_mbit():
    field = {
        "bit": {"selected": 0, "value": "bit/s"},
        "Kbit": {"selected": 0, "value": "Kbit/s"},
        "Mbit": {"selected": 1, "value": "Mbit/s"},
        "Gbit": {"selected": 0, "value": "Gbit/s"},
    }
    assert selected_bandwidth_metric(field) == "Mbit"


def test_selected_bandwidth_metric_gbit():
    field = {
        "bit": {"selected": 0, "value": "bit/s"},
        "Kbit": {"selected": 0, "value": "Kbit/s"},
        "Mbit": {"selected": 0, "value": "Mbit/s"},
        "Gbit": {"selected": 1, "value": "Gbit/s"},
    }
    assert selected_bandwidth_metric(field) == "Gbit"


def test_selected_bandwidth_metric_passthrough_string():
    """When field is already a string (search row format), return it directly."""
    assert selected_bandwidth_metric("Mbit") == "Mbit"


# ---------------------------------------------------------------------------
# normalize_pipe — from search row (flat format)
# ---------------------------------------------------------------------------


def test_normalize_pipe_from_search_row_uuid():
    rows = load("search_pipes.json")["rows"]
    pipe = normalize_pipe(rows[0])
    assert pipe["uuid"] == "e93038e5-1234-5678-abcd-000000000001"


def test_normalize_pipe_from_search_row_description():
    rows = load("search_pipes.json")["rows"]
    pipe = normalize_pipe(rows[0])
    assert pipe["description"] == "Download pipe"


def test_normalize_pipe_from_search_row_enabled_bool():
    rows = load("search_pipes.json")["rows"]
    pipe = normalize_pipe(rows[0])
    assert pipe["enabled"] is True
    assert isinstance(pipe["enabled"], bool)


def test_normalize_pipe_from_search_row_bandwidth_int():
    rows = load("search_pipes.json")["rows"]
    pipe = normalize_pipe(rows[0])
    assert pipe["bandwidth"] == 1776
    assert isinstance(pipe["bandwidth"], int)


def test_normalize_pipe_invalid_bandwidth_defaults_to_zero():
    pipe = normalize_pipe({"uuid": "x", "bandwidth": "not-a-number", "enabled": "1"})
    assert pipe["bandwidth"] == 0


def test_normalize_pipe_from_search_row_bandwidth_metric():
    rows = load("search_pipes.json")["rows"]
    pipe = normalize_pipe(rows[0])
    assert pipe["bandwidth_metric"] == "Mbit"


def test_normalize_pipe_from_search_row_scheduler():
    rows = load("search_pipes.json")["rows"]
    pipe = normalize_pipe(rows[0])
    assert pipe["scheduler"] == "fq_codel"


def test_normalize_pipe_from_search_row_mask():
    rows = load("search_pipes.json")["rows"]
    pipe = normalize_pipe(rows[0])
    assert pipe["mask"] == "none"


def test_normalize_pipe_from_search_row_ecn_bool():
    rows = load("search_pipes.json")["rows"]
    pipe = normalize_pipe(rows[0])
    assert pipe["codel_ecn_enable"] is True
    assert isinstance(pipe["codel_ecn_enable"], bool)


def test_normalize_pipe_from_search_row_codel_enable_false():
    rows = load("search_pipes.json")["rows"]
    pipe = normalize_pipe(rows[0])
    assert pipe["codel_enable"] is False


def test_normalize_pipe_from_search_row_empty_fqcodel_quantum_is_none():
    rows = load("search_pipes.json")["rows"]
    pipe = normalize_pipe(rows[0])
    assert pipe["fqcodel_quantum"] is None


def test_normalize_pipe_from_search_row_empty_codel_target_is_none():
    rows = load("search_pipes.json")["rows"]
    pipe = normalize_pipe(rows[0])
    assert pipe["codel_target_ms"] is None


def test_normalize_pipe_upload_bandwidth():
    rows = load("search_pipes.json")["rows"]
    pipe = normalize_pipe(rows[1])
    assert pipe["bandwidth"] == 325
    assert pipe["description"] == "Upload pipe"


# ---------------------------------------------------------------------------
# normalize_pipe — from settings/get pipe (GUI enum format)
# ---------------------------------------------------------------------------


def test_normalize_pipe_from_settings_get_uuid():
    data = load("settings_get.json")
    uuid = "e93038e5-1234-5678-abcd-000000000001"
    row = {"uuid": uuid, **data["ts"]["pipes"][uuid]}
    pipe = normalize_pipe(row)
    assert pipe["uuid"] == uuid


def test_normalize_pipe_from_settings_get_scheduler_resolved():
    data = load("settings_get.json")
    uuid = "e93038e5-1234-5678-abcd-000000000001"
    row = {"uuid": uuid, **data["ts"]["pipes"][uuid]}
    pipe = normalize_pipe(row)
    assert pipe["scheduler"] == "fq_codel"


def test_normalize_pipe_from_settings_get_bandwidth_metric_resolved():
    data = load("settings_get.json")
    uuid = "e93038e5-1234-5678-abcd-000000000001"
    row = {"uuid": uuid, **data["ts"]["pipes"][uuid]}
    pipe = normalize_pipe(row)
    assert pipe["bandwidth_metric"] == "Mbit"


def test_normalize_pipe_from_settings_get_mask_resolved():
    data = load("settings_get.json")
    uuid = "e93038e5-1234-5678-abcd-000000000001"
    row = {"uuid": uuid, **data["ts"]["pipes"][uuid]}
    pipe = normalize_pipe(row)
    assert pipe["mask"] == "none"


def test_normalize_pipe_from_settings_get_bandwidth_int():
    data = load("settings_get.json")
    uuid = "e93038e5-1234-5678-abcd-000000000001"
    row = {"uuid": uuid, **data["ts"]["pipes"][uuid]}
    pipe = normalize_pipe(row)
    assert pipe["bandwidth"] == 1776


def test_normalize_pipe_from_settings_get_ecn_bool():
    data = load("settings_get.json")
    uuid = "e93038e5-1234-5678-abcd-000000000001"
    row = {"uuid": uuid, **data["ts"]["pipes"][uuid]}
    pipe = normalize_pipe(row)
    assert pipe["codel_ecn_enable"] is True


# ---------------------------------------------------------------------------
# normalize_queue — from search row
# ---------------------------------------------------------------------------


def test_normalize_queue_from_search_row_uuid():
    rows = load("search_queues.json")["rows"]
    queue = normalize_queue(rows[0])
    assert queue["uuid"] == "84c6c7d8-1234-5678-abcd-000000000003"


def test_normalize_queue_from_search_row_description():
    rows = load("search_queues.json")["rows"]
    queue = normalize_queue(rows[0])
    assert queue["description"] == "Download queue"


def test_normalize_queue_from_search_row_enabled_bool():
    rows = load("search_queues.json")["rows"]
    queue = normalize_queue(rows[0])
    assert queue["enabled"] is True


def test_normalize_queue_from_search_row_pipe_uuid():
    rows = load("search_queues.json")["rows"]
    queue = normalize_queue(rows[0])
    assert queue["pipe_uuid"] == "e93038e5-1234-5678-abcd-000000000001"


def test_normalize_queue_from_search_row_weight_int():
    rows = load("search_queues.json")["rows"]
    queue = normalize_queue(rows[0])
    assert queue["weight"] == 100
    assert isinstance(queue["weight"], int)


def test_normalize_queue_upload_pipe_uuid():
    rows = load("search_queues.json")["rows"]
    queue = normalize_queue(rows[1])
    assert queue["pipe_uuid"] == "f9b19d27-1234-5678-abcd-000000000002"


# ---------------------------------------------------------------------------
# normalize_queue — from settings/get (GUI enum format)
# ---------------------------------------------------------------------------


def test_normalize_queue_from_settings_get_pipe_uuid_resolved():
    data = load("settings_get.json")
    uuid = "84c6c7d8-1234-5678-abcd-000000000003"
    row = {"uuid": uuid, **data["ts"]["queues"][uuid]}
    queue = normalize_queue(row)
    assert queue["pipe_uuid"] == "e93038e5-1234-5678-abcd-000000000001"


def test_normalize_queue_from_settings_get_mask_resolved():
    data = load("settings_get.json")
    uuid = "84c6c7d8-1234-5678-abcd-000000000003"
    row = {"uuid": uuid, **data["ts"]["queues"][uuid]}
    queue = normalize_queue(row)
    assert queue["mask"] == "none"


# ---------------------------------------------------------------------------
# normalize_rule — from search row
# ---------------------------------------------------------------------------


def test_normalize_rule_from_search_row_uuid():
    rows = load("search_rules.json")["rows"]
    rule = normalize_rule(rows[0])
    assert rule["uuid"] == "690c995b-1234-5678-abcd-000000000005"


def test_normalize_rule_from_search_row_description():
    rows = load("search_rules.json")["rows"]
    rule = normalize_rule(rows[0])
    assert rule["description"] == "Download Rule"


def test_normalize_rule_from_search_row_enabled_bool():
    rows = load("search_rules.json")["rows"]
    rule = normalize_rule(rows[0])
    assert rule["enabled"] is True


def test_normalize_rule_from_search_row_interface():
    rows = load("search_rules.json")["rows"]
    rule = normalize_rule(rows[0])
    assert rule["interface"] == "wan"


def test_normalize_rule_from_search_row_direction():
    rows = load("search_rules.json")["rows"]
    rule = normalize_rule(rows[0])
    assert rule["direction"] == "in"


def test_normalize_rule_from_search_row_proto():
    rows = load("search_rules.json")["rows"]
    rule = normalize_rule(rows[0])
    assert rule["proto"] == "ip"


def test_normalize_rule_from_search_row_target_uuid():
    rows = load("search_rules.json")["rows"]
    rule = normalize_rule(rows[0])
    assert rule["target_uuid"] == "84c6c7d8-1234-5678-abcd-000000000003"


def test_normalize_rule_from_search_row_empty_interface2_is_none():
    rows = load("search_rules.json")["rows"]
    rule = normalize_rule(rows[0])
    assert rule["interface2"] is None


def test_normalize_rule_from_search_row_empty_source_port_is_none():
    rows = load("search_rules.json")["rows"]
    rule = normalize_rule(rows[0])
    assert rule["source_port"] is None


def test_normalize_rule_from_search_row_empty_dscp_is_none():
    rows = load("search_rules.json")["rows"]
    rule = normalize_rule(rows[0])
    assert rule["dscp"] is None


def test_normalize_rule_from_search_row_sequence_int():
    rows = load("search_rules.json")["rows"]
    rule = normalize_rule(rows[0])
    assert rule["sequence"] == 1
    assert isinstance(rule["sequence"], int)


def test_normalize_rule_upload_direction():
    rows = load("search_rules.json")["rows"]
    rule = normalize_rule(rows[1])
    assert rule["direction"] == "out"


# ---------------------------------------------------------------------------
# normalize_rule — from settings/get (GUI enum format)
# ---------------------------------------------------------------------------


def test_normalize_rule_from_settings_get_interface_resolved():
    data = load("settings_get.json")
    uuid = "690c995b-1234-5678-abcd-000000000005"
    row = {"uuid": uuid, **data["ts"]["rules"][uuid]}
    rule = normalize_rule(row)
    assert rule["interface"] == "wan"


def test_normalize_rule_from_settings_get_direction_resolved():
    data = load("settings_get.json")
    uuid = "690c995b-1234-5678-abcd-000000000005"
    row = {"uuid": uuid, **data["ts"]["rules"][uuid]}
    rule = normalize_rule(row)
    assert rule["direction"] == "in"


def test_normalize_rule_from_settings_get_proto_resolved():
    data = load("settings_get.json")
    uuid = "690c995b-1234-5678-abcd-000000000005"
    row = {"uuid": uuid, **data["ts"]["rules"][uuid]}
    rule = normalize_rule(row)
    assert rule["proto"] == "ip"


def test_normalize_rule_from_settings_get_target_uuid_resolved():
    data = load("settings_get.json")
    uuid = "690c995b-1234-5678-abcd-000000000005"
    row = {"uuid": uuid, **data["ts"]["rules"][uuid]}
    rule = normalize_rule(row)
    assert rule["target_uuid"] == "84c6c7d8-1234-5678-abcd-000000000003"


def test_normalize_rule_from_settings_get_empty_interface2_is_none():
    data = load("settings_get.json")
    uuid = "690c995b-1234-5678-abcd-000000000005"
    row = {"uuid": uuid, **data["ts"]["rules"][uuid]}
    rule = normalize_rule(row)
    assert rule["interface2"] is None


def test_normalize_rule_from_settings_get_upload_direction():
    data = load("settings_get.json")
    uuid = "5122c31a-1234-5678-abcd-000000000006"
    row = {"uuid": uuid, **data["ts"]["rules"][uuid]}
    rule = normalize_rule(row)
    assert rule["direction"] == "out"


# ---------------------------------------------------------------------------
# pipes_from_settings_get
# ---------------------------------------------------------------------------


def test_pipes_from_settings_get_count():
    ts = load("settings_get.json")["ts"]
    pipes = pipes_from_settings_get(ts)
    assert len(pipes) == 2


def test_pipes_from_settings_get_uuids():
    ts = load("settings_get.json")["ts"]
    pipes = pipes_from_settings_get(ts)
    uuids = {p["uuid"] for p in pipes}
    assert "e93038e5-1234-5678-abcd-000000000001" in uuids
    assert "f9b19d27-1234-5678-abcd-000000000002" in uuids


def test_pipes_from_settings_get_scheduler_resolved():
    ts = load("settings_get.json")["ts"]
    pipes = pipes_from_settings_get(ts)
    for pipe in pipes:
        assert pipe["scheduler"] == "fq_codel"


def test_pipes_from_settings_get_bandwidths():
    ts = load("settings_get.json")["ts"]
    pipes = pipes_from_settings_get(ts)
    bws = {p["uuid"]: p["bandwidth"] for p in pipes}
    assert bws["e93038e5-1234-5678-abcd-000000000001"] == 1776
    assert bws["f9b19d27-1234-5678-abcd-000000000002"] == 325


# ---------------------------------------------------------------------------
# queues_from_settings_get
# ---------------------------------------------------------------------------


def test_queues_from_settings_get_count():
    ts = load("settings_get.json")["ts"]
    queues = queues_from_settings_get(ts)
    assert len(queues) == 2


def test_queues_from_settings_get_pipe_uuids_resolved():
    ts = load("settings_get.json")["ts"]
    queues = queues_from_settings_get(ts)
    pipe_uuids = {q["pipe_uuid"] for q in queues}
    assert "e93038e5-1234-5678-abcd-000000000001" in pipe_uuids
    assert "f9b19d27-1234-5678-abcd-000000000002" in pipe_uuids


# ---------------------------------------------------------------------------
# rules_from_settings_get
# ---------------------------------------------------------------------------


def test_rules_from_settings_get_count():
    ts = load("settings_get.json")["ts"]
    rules = rules_from_settings_get(ts)
    assert len(rules) == 2


def test_rules_from_settings_get_directions():
    ts = load("settings_get.json")["ts"]
    rules = rules_from_settings_get(ts)
    directions = {r["direction"] for r in rules}
    assert "in" in directions
    assert "out" in directions


def test_rules_from_settings_get_target_uuids():
    ts = load("settings_get.json")["ts"]
    rules = rules_from_settings_get(ts)
    targets = {r["target_uuid"] for r in rules}
    assert "84c6c7d8-1234-5678-abcd-000000000003" in targets
    assert "14cc84dd-1234-5678-abcd-000000000004" in targets


# ---------------------------------------------------------------------------
# Statistics fixture — scheduler drift scenario
# ---------------------------------------------------------------------------


def test_statistics_fixture_loads():
    stats = load("statistics.json")
    assert stats["status"] == "ok"
    assert len(stats["items"]) > 0


def test_statistics_fixture_pipe_scheduler_is_fifo_with_fqcodel_layout():
    """Runtime inner FIFO with flowset.sched_nr == pipe id is expected for fq_codel."""
    stats = load("statistics.json")
    pipes = [i for i in stats["items"] if i.get("type") == "pipe"]
    assert len(pipes) == 2
    for pipe in pipes:
        assert pipe["scheduler"]["sched_type"] == "FIFO"
        assert pipe["flowset"]["sched_nr"] == str(pipe["pipe"])


def test_statistics_fixture_rule_pkts_nonzero():
    stats = load("statistics.json")
    rules = [i for i in stats["items"] if i.get("type") == "rule"]
    assert len(rules) == 2
    for rule in rules:
        assert rule["pkts"] > 0
