"""Writing back an MVC node that contains child collections.

`merge_for_set` overlays changes onto a node read from `get*` and returns every
field for the `set*` POST, because a partial POST resets what it omits. What it
did not handle is a parent node that embeds its children.
"""

from __future__ import annotations

from opnsense_mcp.utils.mvc_merge import merge_for_set

def test_child_collections_are_not_written_back() -> None:
    """A parent node embeds its children; posting them back is a 500.

    quagga/bgp/get returns `neighbors`, `aspaths`, `prefixlists`, `routemaps`,
    `peergroups` and `redistributions` alongside the scalar fields. They are
    separate resources with their own endpoints, and including them in a
    set POST made the model reject the whole write. Enabling BGP failed halfway
    through because of this, leaving FRR on with the default AS.
    """
    node = {
        "enabled": "0",
        "asnumber": "65551",
        "neighbors": {"neighbor": []},
        "aspaths": {"aspath": []},
        "redistributions": {"redistribution": [{"uuid": "x"}]},
    }

    payload = merge_for_set(node, {"enabled": "1"})

    assert payload == {"enabled": "1", "asnumber": "65551"}


def test_enum_fields_are_still_collapsed_not_dropped() -> None:
    """The child-collection rule must not swallow genuine enums."""
    node = {
        "daemons": {
            "bgp": {"value": "bgp", "selected": 1},
            "static": {"value": "static", "selected": 1},
            "ospf": {"value": "ospf", "selected": 0},
        },
        "profile": {
            "traditional": {"value": "traditional", "selected": 1},
            "datacenter": {"value": "datacenter", "selected": 0},
        },
    }

    payload = merge_for_set(node, {})

    assert set(payload["daemons"].split(",")) == {"bgp", "static"}
    assert payload["profile"] == "traditional"


def test_an_empty_enum_survives_as_an_empty_string() -> None:
    """Nothing selected is a value, not an absent field."""
    node = {"bestpath": {"aigp": {"value": "aigp", "selected": 0}}}

    assert merge_for_set(node, {}) == {"bestpath": ""}
