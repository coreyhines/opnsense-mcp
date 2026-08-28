"""Wave 4: documentation and schema claims that no longer match the code.

None of these can corrupt a firewall. They mislead the reader instead, which
for a tool surface an agent reads before acting is its own kind of defect: the
README's tool list is the closest thing this project has to an interface
contract, and it advertised a tool that had been deleted.
"""

from __future__ import annotations

import pathlib
import re

from opnsense_mcp.tools.interface_address import SetInterfaceAddressTool

REPO = pathlib.Path(__file__).resolve().parent.parent


def _exposed_names() -> set[str]:
    from opnsense_mcp.fastmcp_server import build_shaper_tools
    from opnsense_mcp.utils.mock_api import MockOPNsenseClient
    from opnsense_mcp.utils.registry import build_tools
    from opnsense_mcp.utils.tool_groups import build_groups

    client = MockOPNsenseClient(
        {"development": {"mock_data_path": str(REPO / "examples" / "mock_data")}}
    )
    tools = build_tools(client, extra=build_shaper_tools(client))
    exposed = build_groups(tools)
    names = set(tools) | set(exposed)
    for group in exposed.values():
        members = getattr(group, "members", None)
        if members:
            names.update(members)
    return names


def test_no_document_advertises_a_tool_that_does_not_exist() -> None:
    """The README listed ssh_fw_rule for a full day after it was removed.

    An agent reading that list calls a name the registry raises KeyError on.
    """
    known = _exposed_names()
    # Tool names are snake_case and appear in backticks in these documents.
    candidates = re.compile(r"`([a-z][a-z0-9_]{4,})`")
    stale: list[str] = []

    for doc in (REPO / "README.md", *(REPO / "docs").rglob("*.md")):
        text = doc.read_text()
        for name in candidates.findall(text):
            # Only judge names that look like this project's tools: a verb we
            # use, or a name the registry once knew.
            if name.startswith(("mk_", "rm_", "list_", "set_", "toggle_", "ssh_")):
                if name not in known:
                    stale.append(f"{doc.relative_to(REPO)}: {name}")

    assert not stale, "documents reference tools that do not exist: " + ", ".join(stale)


def test_the_group_docstring_states_the_real_counts() -> None:
    """It said 13 names and 104 operations well after both had moved."""
    from opnsense_mcp.utils import tool_groups

    exposed_count = len(
        [
            n
            for n in _exposed_names()
            if n in tool_groups.GROUPS or n in tool_groups.UNGROUPED
        ]
    )
    doc = tool_groups.__doc__ or ""
    numbers = {int(n) for n in re.findall(r"\b(\d{2,4})\b", doc)}

    assert exposed_count in numbers, (
        f"the module docstring cites {sorted(numbers)} but the surface is "
        f"{exposed_count} names"
    )


def test_the_schema_declares_that_the_interface_gets_enabled() -> None:
    """It sets enable=1 unconditionally, which no description mentioned.

    A model asked to "set an address on opt5" would also bring up an interface
    an operator had deliberately disabled.
    """
    blob = (
        SetInterfaceAddressTool.description
        + " "
        + str(SetInterfaceAddressTool.input_schema)
    ).lower()

    # "enabl" rather than "enable": the description says "enabling".
    assert "enabl" in blob


def test_a_zero_prefix_is_refused() -> None:
    """/0 on an interface claims the whole address space."""
    import asyncio
    from unittest.mock import AsyncMock, MagicMock, patch

    from opnsense_mcp.utils.api import OPNsenseClient

    with (
        patch.object(OPNsenseClient, "_detect_endpoint", return_value=None),
        patch("opnsense_mcp.utils.api.requests.Session") as sess_cls,
    ):
        sess_cls.side_effect = lambda: MagicMock()
        client = OPNsenseClient(
            {"firewall_host": "192.0.2.1", "api_key": "k", "api_secret": "s"}
        )

    async def fake(method: str, endpoint: str, **kwargs: object) -> object:
        if "search_item" in endpoint:
            return {"rows": [{"uuid": "opt12", "if": "lo1"}]}
        return {"interface": {"descr": "", "if": {}, "lock": "0"}}

    client._make_request = AsyncMock(side_effect=fake)
    tool = SetInterfaceAddressTool(client)
    tool._ssh = MagicMock()

    result = asyncio.run(
        tool.execute(
            {"interface": "opt12", "address": "198.51.100.2", "subnet_bits": 0}
        )
    )

    assert result["status"] == "error"
    assert "subnet_bits" in result["error"]
