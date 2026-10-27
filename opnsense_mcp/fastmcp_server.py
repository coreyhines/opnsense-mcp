"""FastMCP (HTTP) server, registered from the shared tool registry.

This used to construct 55 tool instances and hand-write a typed wrapper for each
one. That was a second copy of the tool surface, and it had already drifted from
the stdio server's copy: seven tools carried different descriptions or schemas
depending on which transport you asked.

Tools are now registered from `utils.registry`, so both transports serve the
same names, descriptions and schemas by construction. Adding a tool means adding
it to `TOOL_CLASSES`.
"""

from __future__ import annotations

import logging
from typing import Any

from fastmcp import FastMCP
from fastmcp.tools.function_tool import FunctionTool

from opnsense_mcp.build_info import get_build_info
from opnsense_mcp.server import get_opnsense_client
from opnsense_mcp.tools.shaper_audit import (
    AuditShaperConfigTool,
    ExplainShaperConfigTool,
)
from opnsense_mcp.tools.shaper_pipes import (
    AddShaperPipeTool,
    DeleteShaperPipeTool,
    GetShaperPipeTool,
    ListShaperPipesTool,
    SetShaperPipeTool,
    ToggleShaperPipeTool,
)
from opnsense_mcp.tools.shaper_presets import ApplyShaperPresetTool
from opnsense_mcp.tools.shaper_queues import (
    AddShaperQueueTool,
    DeleteShaperQueueTool,
    GetShaperQueueTool,
    ListShaperQueuesTool,
    SetShaperQueueTool,
    ToggleShaperQueueTool,
)
from opnsense_mcp.tools.shaper_rules import (
    AddShaperRuleTool,
    DeleteShaperRuleTool,
    GetShaperRuleTool,
    ListShaperRulesTool,
    SetShaperRuleTool,
    ToggleShaperRuleTool,
)
from opnsense_mcp.tools.shaper_service import ApplyShaperTool, ShaperStatisticsTool
from opnsense_mcp.tools.shaper_settings import GetShaperSettingsTool
from opnsense_mcp.tools.shaper_snapshot import RestoreShaperSnapshotTool
from opnsense_mcp.utils.env import load_opnsense_env
from opnsense_mcp.utils.registry import build_tools
from opnsense_mcp.utils.tool_groups import build_groups

logger = logging.getLogger(__name__)

SHAPER_TOOL_CLASSES: tuple[type, ...] = (
    AddShaperPipeTool,
    AddShaperQueueTool,
    AddShaperRuleTool,
    ApplyShaperPresetTool,
    ApplyShaperTool,
    AuditShaperConfigTool,
    DeleteShaperPipeTool,
    DeleteShaperQueueTool,
    DeleteShaperRuleTool,
    ExplainShaperConfigTool,
    GetShaperPipeTool,
    GetShaperQueueTool,
    GetShaperRuleTool,
    GetShaperSettingsTool,
    ListShaperPipesTool,
    ListShaperQueuesTool,
    ListShaperRulesTool,
    RestoreShaperSnapshotTool,
    SetShaperPipeTool,
    SetShaperQueueTool,
    SetShaperRuleTool,
    ShaperStatisticsTool,
    ToggleShaperPipeTool,
    ToggleShaperQueueTool,
    ToggleShaperRuleTool,
)

INSTRUCTIONS = (
    "OPNsense firewall management. Most tools are grouped by resource and take "
    "an `action`: pick the object, then the verb. Call action='help' on any of "
    "them for that resource's per-action fields, defaults and rules, including "
    "which actions need a confirmation token. Write actions that change firewall "
    "state generally stage by default and take an `apply` flag; reads do not."
)


def build_shaper_tools(client: Any) -> dict[str, Any]:
    """Instantiate the traffic-shaper tools, keyed by tool name."""
    return {cls.name: cls(client) for cls in SHAPER_TOOL_CLASSES}


def _make_handler(tool: Any):
    """Wrap a tool's execute() as a FastMCP callable.

    FastMCP derives a schema from a function signature, which is why this file
    used to carry a typed wrapper per tool. Passing `parameters` explicitly lets
    the tool's own `input_schema` be the schema instead, so there is one
    definition rather than two.
    """

    async def handler(**kwargs: Any) -> str:
        return str(await tool.execute(kwargs))

    handler.__name__ = tool.name
    return handler


# Strict MCP clients reject tool schemas that declare `"type": "array"`
# without `"items"`; a Featherless-backed validator refused every call while
# building for such a tool. Seven advertised properties were bare. The four
# whose handlers parse structured values get explicit item types here; the
# rest (plain string lists) fall through to the walker's string default.
_ARRAY_ITEM_OVERRIDES: dict[tuple[str, str], dict[str, Any]] = {
    ("alias", "content"): {"type": "string"},
    ("ipv6", "records"): {"type": "object"},
    ("ipv6", "domains"): {"type": "string"},
    ("ipv6", "public_names"): {"type": "string"},
}


def _ensure_array_items(tool_name: str, schema: dict[str, Any]) -> None:
    """Recursively add a JSON-Schema ``items`` to every array without one."""
    seen = [schema]
    while seen:
        node = seen.pop()
        if not isinstance(node, dict):
            continue
        props = node.get("properties")
        if isinstance(props, dict):
            for pname, p in props.items():
                if not isinstance(p, dict):
                    continue
                if p.get("type") == "array" and "items" not in p:
                    items = _ARRAY_ITEM_OVERRIDES.get((tool_name, pname))
                    if items is None:
                        items = {"type": "string"}
                        logger.warning(
                            "schema normalizer: %s.%s array had no items schema; "
                            "defaulting to string — add an explicit override",
                            tool_name,
                            pname,
                        )
                    p["items"] = items
                seen.append(p)
        if isinstance(node.get("items"), dict):
            seen.append(node["items"])


def register_tools(mcp: FastMCP, tools: dict[str, Any]) -> None:
    """Register every tool on *mcp* from its own metadata."""
    for name, tool in tools.items():
        _ensure_array_items(name, getattr(tool, "input_schema", {}))
        mcp.add_tool(
            FunctionTool(
                name=name,
                description=getattr(tool, "description", name),
                parameters=getattr(
                    tool,
                    "input_schema",
                    {"type": "object", "properties": {}, "required": []},
                ),
                fn=_make_handler(tool),
            )
        )


def build_mcp_server() -> FastMCP:
    """Build the FastMCP server with every registered tool."""
    load_opnsense_env()
    client = get_opnsense_client({})

    tools = build_tools(client, extra=build_shaper_tools(client))
    exposed = build_groups(tools)

    # Without an explicit version FastMCP reports its own, so `server/discover`
    # answered serverInfo.version = "4.0.0b5" and a client could not tell which
    # build of this server it was talking to.
    build_info = get_build_info()
    mcp = FastMCP(
        "opnsense-mcp",
        instructions=INSTRUCTIONS,
        version=build_info["package_version"],
    )
    register_tools(mcp, exposed)
    logger.info("Registered %d tools from %d operations", len(exposed), len(tools))
    return mcp
