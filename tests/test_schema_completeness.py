"""Every key ``execute`` reads from ``params`` must be in ``input_schema``.

``GroupedTool._build_schema`` advertises the MCP surface from each member's
``input_schema.properties``. A field that ``execute`` reads but the schema does
not declare is unreachable for a strict client: that is how
``MkLoopbackTool``'s track6 refusal shipped and could never be reached (D4).

This walks the registry the same way ``test_guidance_names_are_real.py`` does,
then statically inspects each leaf tool's ``execute`` body. It does not call
the tools.
"""

from __future__ import annotations

from tests._schema_ast import execute_ast, leaf_tools, param_keys_read

# Narrow allowlist for reads that pre-date this check and live outside B3's
# owned files. Each entry is (tool.name, param_key) with a reason. Do not grow
# this to paper over a new tool that forgot its schema — fix the schema.
_ALLOWLIST: frozenset[tuple[str, str]] = frozenset(
    {
        # Optional filter used by execute; schema never declared it. Not B3.
        ("arp", "ipv6"),
        # Optional logical-name resolve; schema is empty. Not B3.
        ("interface_list", "resolve"),
        # Capture mode (text/raw); schema never declared it. Not B3.
        ("packet_capture", "mode"),
        # Internal selector; schema is empty and the tool is ungrouped. Not B3.
        ("system", "action"),
    }
)


def test_every_params_key_execute_reads_is_in_input_schema() -> None:
    """Fail when execute reads a key its own input_schema does not declare."""
    stale: list[str] = []
    for tool in leaf_tools():
        name = getattr(tool, "name", type(tool).__name__)
        schema = getattr(tool, "input_schema", {}) or {}
        declared = set(schema.get("properties") or {})
        execute = execute_ast(tool)
        if execute is None:
            continue
        for key in sorted(param_keys_read(execute) - declared):
            if (name, key) in _ALLOWLIST:
                continue
            stale.append(f"{name}: reads {key!r} but input_schema omits it")

    assert not stale, (
        "execute reads params keys missing from input_schema "
        "(declare them, or add a narrow allowlist entry with a reason): "
        + "; ".join(stale)
    )
