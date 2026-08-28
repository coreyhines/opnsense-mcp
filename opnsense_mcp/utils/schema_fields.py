"""One definition each for the fields that appear across many tools.

Measured on the 31-tool surface: property definitions were 78% of the exposed
schema, and 64% of those characters went on fields restated per tool. `apply`
appeared in seventeen tools as the same boolean with seventeen different
sentences; `uuid` in twelve as "the <thing> uuid".

Only fields whose meaning is genuinely identical everywhere belong here.
`interface` and `source_net` also repeat, but what they select differs by tool,
and that wording is the useful part, so they are deliberately absent.
"""

from __future__ import annotations

from typing import Any

# Deliberately terse. These are read on every tool listing, and the surrounding
# action name already supplies the context a longer sentence would restate.
SHARED_FIELDS: dict[str, dict[str, Any]] = {
    "apply": {
        "type": "boolean",
        "description": (
            "Apply now rather than leaving the change staged. The default "
            "differs by action; action='help' reports each one."
        ),
    },
    "uuid": {
        "type": "string",
        "description": "Record to act on, identified by a list action.",
    },
    "confirm": {
        "type": "string",
        "description": "Token returned by the previous call, to confirm.",
    },
    "enabled": {
        "type": "boolean",
        "description": "Target state, set explicitly rather than flipped.",
    },
    "description": {
        "type": "string",
        "description": "Free-text note stored on the record.",
    },
}


def canonical_property(name: str, spec: dict[str, Any]) -> dict[str, Any]:
    """Return the shared definition for `name`, or `spec` unchanged."""
    return SHARED_FIELDS.get(name, spec)


def is_shared(name: str) -> bool:
    """Does this field mean the same thing in every tool that takes it?"""
    return name in SHARED_FIELDS
