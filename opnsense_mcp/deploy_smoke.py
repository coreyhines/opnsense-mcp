#!/usr/bin/env python3
"""Post-deploy smoke: the running server's tools/list is one Cursor can load.

Issue #53: a stale image on strongpod still advertised a type union, and
Cursor showed the server connected with zero tools. Every repo test was green,
because tests check the code, not the deployment. This checks the deployment:
it speaks MCP to the live endpoint and fails on the schema shapes that make
Cursor/Zod drop every tool.

    python3 -m opnsense_mcp.deploy_smoke [URL] [--min-tools 15] [--expect-version 1.3.2]

It ships in the image, so a deploy job can run it inside the container it
just started, against that container's own listener and bearer:

    podman exec opnsense-mcp-app python3 -m opnsense_mcp.deploy_smoke \\
        --min-tools 15 --expect-version 1.3.2

URL defaults to http://127.0.0.1:8765/mcp. The bearer comes from
MCP_SECRET_KEY in the environment, never argv, so it does not show in the
process list and never leaves the container. Standard library only.
Exit 0 when clean, 1 on findings, 2 when the endpoint could not be read.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
import urllib.request
from typing import Any

# Mirrors opnsense_mcp.utils.grouped_tool.FORBIDDEN_WIRE_KEYS; a test keeps
# the two equal. Not imported, so this module stays stdlib-only.
FORBIDDEN_PROPERTY_NAMES = frozenset({"constructor", "__proto__", "prototype"})


def schema_problems(tools: list[dict[str, Any]]) -> list[str]:
    """Every shape in *tools* known to make Cursor load zero tools."""
    problems: list[str] = []

    def walk(path: str, node: Any) -> None:
        if isinstance(node, dict):
            kind = node.get("type")
            if isinstance(kind, list):
                problems.append(f"{path}: type union {kind!r}")
            if kind == "array" and not isinstance(node.get("items"), dict):
                problems.append(f"{path}: array without items")
            props = node.get("properties")
            if isinstance(props, dict):
                for bad in sorted(FORBIDDEN_PROPERTY_NAMES & set(props)):
                    problems.append(f"{path}.properties: forbidden name {bad!r}")
            for key, value in node.items():
                walk(f"{path}.{key}", value)
        elif isinstance(node, list):
            for i, value in enumerate(node):
                walk(f"{path}[{i}]", value)

    for tool in tools:
        walk(str(tool.get("name", "?")), tool.get("inputSchema") or {})
    return problems


def _post(
    url: str, key: str, body: dict, session: str | None
) -> tuple[Any, str | None]:
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if session:
        headers["Mcp-Session-Id"] = session
    request = urllib.request.Request(url, json.dumps(body).encode(), headers)
    # Scheme restricted to http(s) by _require_http before any request.
    with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310  # nosec B310  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        sid = response.headers.get("Mcp-Session-Id") or session
        text = response.read().decode()
    if not text.strip():
        return None, sid
    if text.lstrip().startswith("{"):
        return json.loads(text), sid
    for line in text.splitlines():
        if line.startswith("data:"):
            return json.loads(line[5:]), sid
    return None, sid


def _require_http(url: str) -> None:
    """Refuse anything but http(s): urllib also opens file:// and ftp://."""
    if urllib.parse.urlsplit(url).scheme not in {"http", "https"}:
        raise ValueError(f"only http(s) endpoints are accepted, not {url!r}")


def fetch(url: str, key: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """initialize, then tools/list. Returns (serverInfo, tools)."""
    _require_http(url)
    init, sid = _post(
        url,
        key,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "tools-list-smoke", "version": "1"},
            },
        },
        None,
    )
    _post(url, key, {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid)
    listed, _ = _post(
        url, key, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, sid
    )
    return init["result"].get("serverInfo") or {}, listed["result"]["tools"]


def main(argv: list[str] | None = None) -> int:
    """Run the smoke against one endpoint."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("url", nargs="?", default="http://127.0.0.1:8765/mcp")
    parser.add_argument("--min-tools", type=int, default=1)
    parser.add_argument(
        "--expect-version",
        help="fail unless serverInfo.version equals this (catches a stale image)",
    )
    args = parser.parse_args(argv)

    key = os.environ.get("MCP_SECRET_KEY", "")
    if not key:
        print("error: MCP_SECRET_KEY is not set", file=sys.stderr)
        return 2
    try:
        info, tools = fetch(args.url, key)
    except Exception as exc:  # noqa: BLE001
        print(
            f"error: could not read tools/list from {args.url}: {exc}", file=sys.stderr
        )
        return 2

    problems = schema_problems(tools)
    if len(tools) < args.min_tools:
        problems.append(
            f"{len(tools)} tools listed, expected at least {args.min_tools}"
        )
    version = str(info.get("version", ""))
    if args.expect_version and version != args.expect_version:
        problems.append(
            f"server reports version {version!r}, expected {args.expect_version!r}"
        )

    for problem in problems:
        print(f"FAIL {problem}", file=sys.stderr)
    if problems:
        return 1
    print(
        f"ok: {len(tools)} tools, version {version or '?'}, no Cursor-breaking shapes"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
