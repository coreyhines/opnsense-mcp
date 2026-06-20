"""Tests for opnsense_mcp/utils/shaper_serialize.py — bucket 1b."""

from __future__ import annotations

import json
from pathlib import Path

from opnsense_mcp.utils.shaper_normalize import (
    normalize_pipe,
    normalize_queue,
    normalize_rule,
)
from opnsense_mcp.utils.shaper_serialize import (
    make_enum_field,
    merge_flat_into_pipe,
    merge_flat_into_queue,
    merge_flat_into_rule,
    serialize_pipe,
    serialize_queue,
    serialize_rule,
)

FIXTURES = Path(__file__).parent / "fixtures" / "shaper"


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


# Description maps for enum-by-uuid fields (no template provided).
PIPE_DESCRIPTIONS = {
    "e93038e5-1234-5678-abcd-000000000001": "Download pipe",
    "f9b19d27-1234-5678-abcd-000000000002": "Upload pipe",
}
TARGET_DESCRIPTIONS = {
    "84c6c7d8-1234-5678-abcd-000000000003": "Download queue",
    "14cc84dd-1234-5678-abcd-000000000004": "Upload queue",
}


def settings_pipe(uuid: str) -> dict:
    return load("settings_get.json")["ts"]["pipes"][uuid]


def settings_queue(uuid: str) -> dict:
    return load("settings_get.json")["ts"]["queues"][uuid]


def settings_rule(uuid: str) -> dict:
    return load("settings_get.json")["ts"]["rules"][uuid]


# ---------------------------------------------------------------------------
# make_enum_field
# ---------------------------------------------------------------------------


def test_make_enum_field_marks_selected():
    field = make_enum_field({"fq_codel": "FQ-CoDel", "fifo": "FIFO"}, "fq_codel")
    assert field["fq_codel"]["selected"] == 1
    assert field["fifo"]["selected"] == 0


def test_make_enum_field_preserves_value_labels():
    field = make_enum_field({"Mbit": "Mbit/s"}, "Mbit")
    assert field["Mbit"]["value"] == "Mbit/s"


def test_make_enum_field_none_selected_when_key_absent():
    field = make_enum_field({"in": "in", "out": "out"}, "")
    assert all(meta["selected"] == 0 for meta in field.values())


def test_make_enum_field_all_keys_present():
    field = make_enum_field({"a": "A", "b": "B", "c": "C"}, "b")
    assert set(field) == {"a", "b", "c"}


# ---------------------------------------------------------------------------
# serialize_pipe — scalar encoding
# ---------------------------------------------------------------------------


def test_serialize_pipe_enabled_is_string():
    flat = normalize_pipe(load("search_pipes.json")["rows"][0])
    payload = serialize_pipe(flat)
    assert payload["enabled"] == "1"


def test_serialize_pipe_bandwidth_is_string():
    flat = normalize_pipe(load("search_pipes.json")["rows"][0])
    payload = serialize_pipe(flat)
    assert payload["bandwidth"] == "1776"
    assert isinstance(payload["bandwidth"], str)


def test_serialize_pipe_empty_optional_int_is_empty_string():
    flat = normalize_pipe(load("search_pipes.json")["rows"][0])
    payload = serialize_pipe(flat)
    assert payload["fqcodel_quantum"] == ""
    assert payload["codel_target"] == ""


def test_serialize_pipe_populated_optional_int_is_string():
    flat = normalize_pipe(load("search_pipes.json")["rows"][0])
    flat["codel_target_ms"] = 5
    payload = serialize_pipe(flat)
    assert payload["codel_target"] == "5"


def test_serialize_pipe_scheduler_is_enum_dict():
    flat = normalize_pipe(load("search_pipes.json")["rows"][0])
    payload = serialize_pipe(flat)
    assert payload["scheduler"]["fq_codel"]["selected"] == 1
    assert payload["scheduler"]["fifo"]["selected"] == 0


def test_serialize_pipe_bandwidth_metric_is_enum_dict():
    flat = normalize_pipe(load("search_pipes.json")["rows"][0])
    payload = serialize_pipe(flat)
    assert payload["bandwidthMetric"]["Mbit"]["selected"] == 1


def test_serialize_pipe_number_maps_to_queue_field():
    flat = normalize_pipe(load("search_pipes.json")["rows"][0])
    payload = serialize_pipe(flat)
    assert payload["queue"] == "10000"


def test_serialize_pipe_ecn_string():
    flat = normalize_pipe(load("search_pipes.json")["rows"][0])
    payload = serialize_pipe(flat)
    assert payload["codel_ecn_enable"] == "1"


# ---------------------------------------------------------------------------
# serialize_pipe — round-trip
# ---------------------------------------------------------------------------


def test_round_trip_pipe_from_search_download():
    flat = normalize_pipe(load("search_pipes.json")["rows"][0])
    assert normalize_pipe(serialize_pipe(flat)) == flat


def test_round_trip_pipe_from_search_upload():
    flat = normalize_pipe(load("search_pipes.json")["rows"][1])
    assert normalize_pipe(serialize_pipe(flat)) == flat


def test_round_trip_pipe_from_settings_get():
    uuid = "e93038e5-1234-5678-abcd-000000000001"
    flat = normalize_pipe({"uuid": uuid, **settings_pipe(uuid)})
    assert normalize_pipe(serialize_pipe(flat)) == flat


def test_round_trip_pipe_with_template():
    uuid = "e93038e5-1234-5678-abcd-000000000001"
    flat = normalize_pipe({"uuid": uuid, **settings_pipe(uuid)})
    payload = serialize_pipe(flat, template=settings_pipe(uuid))
    assert normalize_pipe({"uuid": uuid, **payload}) == flat


# ---------------------------------------------------------------------------
# serialize_queue
# ---------------------------------------------------------------------------


def test_serialize_queue_pipe_is_enum_keyed_by_uuid():
    flat = normalize_queue(load("search_queues.json")["rows"][0])
    payload = serialize_queue(flat, PIPE_DESCRIPTIONS)
    pipe_uuid = "e93038e5-1234-5678-abcd-000000000001"
    assert payload["pipe"][pipe_uuid]["selected"] == 1


def test_serialize_queue_pipe_enum_uses_descriptions_as_labels():
    flat = normalize_queue(load("search_queues.json")["rows"][0])
    payload = serialize_queue(flat, PIPE_DESCRIPTIONS)
    pipe_uuid = "e93038e5-1234-5678-abcd-000000000001"
    assert payload["pipe"][pipe_uuid]["value"] == "Download pipe"


def test_serialize_queue_weight_is_string():
    flat = normalize_queue(load("search_queues.json")["rows"][0])
    payload = serialize_queue(flat, PIPE_DESCRIPTIONS)
    assert payload["weight"] == "100"


def test_round_trip_queue_from_search():
    flat = normalize_queue(load("search_queues.json")["rows"][0])
    payload = serialize_queue(flat, PIPE_DESCRIPTIONS)
    assert normalize_queue(payload) == flat


def test_round_trip_queue_from_settings_get():
    uuid = "84c6c7d8-1234-5678-abcd-000000000003"
    flat = normalize_queue({"uuid": uuid, **settings_queue(uuid)})
    payload = serialize_queue(flat, PIPE_DESCRIPTIONS, template=settings_queue(uuid))
    assert normalize_queue({"uuid": uuid, **payload}) == flat


# ---------------------------------------------------------------------------
# serialize_rule
# ---------------------------------------------------------------------------


def test_serialize_rule_enabled_string():
    flat = normalize_rule(load("search_rules.json")["rows"][0])
    payload = serialize_rule(flat, TARGET_DESCRIPTIONS)
    assert payload["enabled"] == "1"


def test_serialize_rule_target_is_enum_keyed_by_uuid():
    flat = normalize_rule(load("search_rules.json")["rows"][0])
    payload = serialize_rule(flat, TARGET_DESCRIPTIONS)
    target_uuid = "84c6c7d8-1234-5678-abcd-000000000003"
    assert payload["target"][target_uuid]["selected"] == 1


def test_serialize_rule_direction_is_enum_dict():
    flat = normalize_rule(load("search_rules.json")["rows"][0])
    payload = serialize_rule(flat, TARGET_DESCRIPTIONS)
    assert payload["direction"]["in"]["selected"] == 1
    assert payload["direction"]["out"]["selected"] == 0


def test_serialize_rule_none_source_port_is_empty_string():
    flat = normalize_rule(load("search_rules.json")["rows"][0])
    payload = serialize_rule(flat, TARGET_DESCRIPTIONS)
    assert payload["source_port"] == ""


def test_serialize_rule_sequence_is_string():
    flat = normalize_rule(load("search_rules.json")["rows"][0])
    payload = serialize_rule(flat, TARGET_DESCRIPTIONS)
    assert payload["sequence"] == "1"


def test_round_trip_rule_from_search_download():
    flat = normalize_rule(load("search_rules.json")["rows"][0])
    payload = serialize_rule(flat, TARGET_DESCRIPTIONS)
    assert normalize_rule(payload) == flat


def test_round_trip_rule_from_search_upload():
    flat = normalize_rule(load("search_rules.json")["rows"][1])
    payload = serialize_rule(flat, TARGET_DESCRIPTIONS)
    assert normalize_rule(payload) == flat


def test_round_trip_rule_from_settings_get():
    uuid = "690c995b-1234-5678-abcd-000000000005"
    flat = normalize_rule({"uuid": uuid, **settings_rule(uuid)})
    payload = serialize_rule(flat, TARGET_DESCRIPTIONS, template=settings_rule(uuid))
    assert normalize_rule({"uuid": uuid, **payload}) == flat


# ---------------------------------------------------------------------------
# merge_flat_into_* — preserve unmapped template fields
# ---------------------------------------------------------------------------


def test_merge_pipe_preserves_unmapped_fields():
    uuid = "e93038e5-1234-5678-abcd-000000000001"
    template = {**settings_pipe(uuid), "origin": "custom-plugin"}
    flat = normalize_pipe({"uuid": uuid, **settings_pipe(uuid)})
    merged = merge_flat_into_pipe(template, flat)
    assert merged["origin"] == "custom-plugin"


def test_merge_pipe_reuses_template_enum_options():
    uuid = "e93038e5-1234-5678-abcd-000000000001"
    template = settings_pipe(uuid)
    flat = normalize_pipe({"uuid": uuid, **template})
    merged = merge_flat_into_pipe(template, flat)
    # Full scheduler option set from the template is retained.
    assert set(merged["scheduler"]) == set(template["scheduler"])


def test_merge_pipe_applies_flat_change():
    uuid = "e93038e5-1234-5678-abcd-000000000001"
    template = settings_pipe(uuid)
    flat = normalize_pipe({"uuid": uuid, **template})
    flat["bandwidth"] = 500
    flat["enabled"] = False
    merged = merge_flat_into_pipe(template, flat)
    assert merged["bandwidth"] == "500"
    assert merged["enabled"] == "0"


def test_merge_pipe_does_not_mutate_template():
    uuid = "e93038e5-1234-5678-abcd-000000000001"
    template = settings_pipe(uuid)
    flat = normalize_pipe({"uuid": uuid, **template})
    flat["scheduler"] = "fifo"
    merge_flat_into_pipe(template, flat)
    # Template scheduler selection is untouched.
    assert template["scheduler"]["fq_codel"]["selected"] == 1
    assert template["scheduler"]["fifo"]["selected"] == 0


def test_merge_queue_preserves_unmapped_fields():
    uuid = "84c6c7d8-1234-5678-abcd-000000000003"
    template = {**settings_queue(uuid), "buckets": "64"}
    flat = normalize_queue({"uuid": uuid, **settings_queue(uuid)})
    merged = merge_flat_into_queue(template, flat)
    assert merged["buckets"] == "64"


def test_merge_queue_round_trips():
    uuid = "84c6c7d8-1234-5678-abcd-000000000003"
    template = settings_queue(uuid)
    flat = normalize_queue({"uuid": uuid, **template})
    merged = merge_flat_into_queue(template, flat)
    assert normalize_queue({"uuid": uuid, **merged}) == flat


def test_merge_rule_preserves_unmapped_fields():
    uuid = "690c995b-1234-5678-abcd-000000000005"
    template = {**settings_rule(uuid), "log": "1"}
    flat = normalize_rule({"uuid": uuid, **settings_rule(uuid)})
    merged = merge_flat_into_rule(template, flat)
    assert merged["log"] == "1"


def test_merge_rule_round_trips():
    uuid = "690c995b-1234-5678-abcd-000000000005"
    template = settings_rule(uuid)
    flat = normalize_rule({"uuid": uuid, **template})
    merged = merge_flat_into_rule(template, flat)
    assert normalize_rule({"uuid": uuid, **merged}) == flat


def test_merge_rule_clears_interface2_when_none():
    uuid = "690c995b-1234-5678-abcd-000000000005"
    template = settings_rule(uuid)
    flat = normalize_rule({"uuid": uuid, **template})
    assert flat["interface2"] is None
    merged = merge_flat_into_rule(template, flat)
    # interface2 normalizes back to None (empty/cleared enum).
    assert normalize_rule({"uuid": uuid, **merged})["interface2"] is None
