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


_NOT_TOOLS = frozenset(
    {
        "del_item",
        "rule_uuid",
        "snapshot_id",
        "client_id",
        "created_at",
        "local_path",
        "max_results",
        "preview_bytes",
        "row_count",
        "sort_by",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "include_down",
        "include_raw",
        "include_rules",
        "summary_only",
        "warnings_only",
        "fetch_all",
        "no_matches",
        "partial_success",
        "bufferbloat_wan",
        # Config keys, params, device names, env vars — tool-shaped but not
        # tools. This is where false positives belong now that the check no
        # longer filters by verb (which blinded it to removed verb families).
        "api_key",
        "api_secret",
        "firewall_host",
        "verify_ssl",
        "max_retries",
        "source_net",
        "source_port",
        "destination_net",
        "destination_port",
        "start_addr",
        "end_addr",
        "password_hash",
        "secret_key",
        "token_expire_minutes",
        "proxy_pass",
        "package_manager",
        "ax0_vlan2",
        "ax0_vlan100",
    }
)


def _tracked_docs() -> list:
    """Only files git tracks. Untracked scratch (tmp_bucket_*.md) is not ours."""
    import subprocess

    out = subprocess.run(
        [
            "git",
            "-C",
            str(REPO),
            "ls-files",
            "*.md",
            "*.mdc",
            "deploy/*.example",
            "examples/*.example",
        ],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    return [REPO / line for line in out.splitlines() if line.strip()]


def test_no_document_advertises_a_tool_that_does_not_exist() -> None:
    """README listed ssh_fw_rule for a day after removal; a first version of
    this test missed it, its prefix filter a hand-picked list exempting 44 of
    112 names.

    A tool-shaped name (a live verb prefix plus a noun) in a tracked document,
    neither a known tool nor an allowlisted non-tool, is a finding.
    """
    known = _exposed_names()
    candidates = re.compile(r"`([a-z][a-z0-9]+(?:_[a-z0-9]+)+)`")
    stale: list[str] = []

    for doc in _tracked_docs():
        try:
            text = doc.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        for name in candidates.findall(text):
            # No verb filter: deriving verbs from surviving tools blinded this
            # to a fully-removed verb family, which is exactly the removal case
            # (ssh_fw_rule) it exists to catch. Any backticked snake_case name
            # that is not a live tool and not an allowlisted non-tool is a
            # finding; genuine non-tools go in _NOT_TOOLS.
            # A test function name is never a tool, and documenting which
            # test enforces what is worth doing. Excluding the class beats
            # adding each one to _NOT_TOOLS as the ledger grows.
            if name in known or name in _NOT_TOOLS or name.startswith("test_"):
                continue
            stale.append(f"{doc.relative_to(REPO)}: {name}")

    assert not stale, (
        "documents reference names that look like tools but are not registered "
        "(fix the doc, or add a genuine non-tool to _NOT_TOOLS): "
        + ", ".join(sorted(set(stale)))
    )


def test_the_group_docstring_states_the_real_counts() -> None:
    """It said 13 names and 104 operations after both had moved.

    A first version collected every 2-4 digit number and checked the count was
    somewhere among them, so it passed on a docstring claiming 999 operations
    behind 42 names. Each number is now bound to its own sentence.
    """
    from opnsense_mcp.fastmcp_server import build_shaper_tools
    from opnsense_mcp.utils import tool_groups
    from opnsense_mcp.utils.mock_api import MockOPNsenseClient
    from opnsense_mcp.utils.registry import build_tools
    from opnsense_mcp.utils.tool_groups import build_groups

    client = MockOPNsenseClient(
        {"development": {"mock_data_path": str(REPO / "examples" / "mock_data")}}
    )
    tools = build_tools(client, extra=build_shaper_tools(client))
    operations = len(tools)
    names = len(build_groups(tools))

    doc = tool_groups.__doc__ or ""
    gives = re.search(r"instead gives (\d+)", doc)
    result = re.search(r"Result: (\d+) operations behind (\d+) names", doc)

    assert gives and int(gives.group(1)) == names, f"'instead gives' != {names}"
    assert result, "the docstring lost its 'Result:' summary line"
    assert int(result.group(1)) == operations, f"operations != {operations}"
    assert int(result.group(2)) == names, f"names != {names}"


def test_the_schema_declares_that_the_interface_gets_enabled() -> None:
    """It sets enable=1 unconditionally, which no description mentioned.

    Asserted against the description a client sees, via whole words rather than
    a truncated substring dodging enable/enabling — the rule-2 trick CLAUDE.md
    forbids.
    """
    words = re.findall(r"[a-z]+", SetInterfaceAddressTool.description.lower())

    assert any(w.startswith("enabl") for w in words), (
        "the description must state the interface is enabled: "
        + SetInterfaceAddressTool.description
    )


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
