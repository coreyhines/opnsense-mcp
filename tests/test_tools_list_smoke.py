"""The post-deploy tools/list smoke catches what left Cursor with zero tools.

Issues #53 and #55: a stale image advertised a type union and Cursor loaded
nothing, while every repo test passed. `opnsense_mcp/deploy_smoke.py` reads
the running server. These pin its checks, and one run against a real local
server proves it can speak MCP at all.
"""

from __future__ import annotations

import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from opnsense_mcp import deploy_smoke as smoke

REPO = Path(__file__).resolve().parents[1]


def _tool(props: dict) -> dict:
    return {"name": "t", "inputSchema": {"type": "object", "properties": props}}


def test_a_clean_schema_has_no_problems() -> None:
    tools = [
        _tool(
            {
                "a": {"type": "string"},
                "b": {"type": "array", "items": {"type": "string"}},
            }
        )
    ]
    assert smoke.schema_problems(tools) == []


@pytest.mark.parametrize(
    "props",
    [
        {"ipv6": {"type": ["integer", "string"]}},
        {"content": {"type": "array"}},
        {"constructor": {"type": "string"}},
        {"outer": {"type": "object", "properties": {"__proto__": {"type": "string"}}}},
        {
            "rows": {
                "type": "array",
                "items": {"type": "object", "properties": {"x": {"type": "array"}}},
            }
        },
    ],
    ids=["union", "itemless-array", "constructor", "nested-proto", "nested-itemless"],
)
def test_each_cursor_breaking_shape_is_reported(props: dict) -> None:
    assert len(smoke.schema_problems([_tool(props)])) == 1


def test_forbidden_names_match_the_server_guard() -> None:
    """The script cannot import the package, so the copy is pinned here."""
    from opnsense_mcp.utils.grouped_tool import FORBIDDEN_WIRE_KEYS

    assert smoke.FORBIDDEN_PROPERTY_NAMES == FORBIDDEN_WIRE_KEYS


def test_a_missing_key_is_unreadable_not_a_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MCP_SECRET_KEY", raising=False)
    assert smoke.main(["http://127.0.0.1:9/mcp"]) == 2


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://host/mcp", "mcp"])
def test_a_non_http_url_is_refused_before_any_read(
    url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """urllib opens file:// too; the smoke must not read local files."""
    monkeypatch.setenv("MCP_SECRET_KEY", "k")
    with pytest.raises(ValueError):
        smoke.fetch(url, "k")
    assert smoke.main([url]) == 2


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def live_server() -> tuple[str, str]:
    """A real mock-mode server, the same entry point the image runs."""
    key, port = secrets.token_hex(24), _free_port()
    env = {**os.environ, "OPNSENSE_USE_MOCK": "1", "MCP_SECRET_KEY": key}
    proc = subprocess.Popen(
        [
            sys.executable,
            "main.py",
            "--transport",
            "streamable-http",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=REPO,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}/mcp"
    try:
        for _ in range(100):
            with socket.socket() as s:
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    break
            time.sleep(0.1)
        else:
            pytest.skip("mock server did not start")
        yield url, key
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_the_smoke_passes_against_the_current_server(
    live_server: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    url, key = live_server
    monkeypatch.setenv("MCP_SECRET_KEY", key)
    assert smoke.main([url, "--min-tools", "15"]) == 0


def test_a_wrong_expected_version_fails(
    live_server: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The stale-image case: a server that runs, but not the build wanted."""
    url, key = live_server
    monkeypatch.setenv("MCP_SECRET_KEY", key)
    assert smoke.main([url, "--expect-version", "0.0.0-not-this"]) == 1


def test_a_wrong_bearer_is_unreadable(
    live_server: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    url, _ = live_server
    monkeypatch.setenv("MCP_SECRET_KEY", "wrong")
    assert smoke.main([url]) == 2


def test_the_module_runs_with_python_dash_m_and_imports_nothing_from_the_package() -> (
    None
):
    """The deploy job runs it in the container; keep it free of package imports."""
    import ast

    tree = ast.parse((REPO / "opnsense_mcp" / "deploy_smoke.py").read_text())
    imported = {
        (n.module or "").split(".")[0]
        if isinstance(n, ast.ImportFrom)
        else a.name.split(".")[0]
        for n in ast.walk(tree)
        if isinstance(n, (ast.Import, ast.ImportFrom))
        for a in (n.names if isinstance(n, ast.Import) else [None])
    }
    assert "opnsense_mcp" not in imported
    result = subprocess.run(
        [sys.executable, "-m", "opnsense_mcp.deploy_smoke", "--help"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
