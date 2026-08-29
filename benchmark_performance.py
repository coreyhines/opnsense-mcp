#!/usr/bin/env python3
"""
OPNsense MCP Tools Performance Benchmark
========================================

This script benchmarks all OPNsense MCP tools to establish baseline performance
and track performance over time.

Usage:
    python benchmark_performance.py
    python benchmark_performance.py --output results.json
    python benchmark_performance.py --verbose
    python benchmark_performance.py --check-shapes
"""

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, Optional

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))

from opnsense_mcp.server import get_opnsense_client
from opnsense_mcp.tools.arp import ARPTool
from opnsense_mcp.tools.dhcp import DHCPTool
from opnsense_mcp.tools.fw_rules import FwRulesTool
from opnsense_mcp.tools.get_logs import GetLogsTool
from opnsense_mcp.tools.interface_list import InterfaceListTool
from opnsense_mcp.tools.lldp import LLDPTool
from opnsense_mcp.tools.shaper_audit import (
    AuditShaperConfigTool,
    ExplainShaperConfigTool,
)
from opnsense_mcp.tools.shaper_pipes import ListShaperPipesTool
from opnsense_mcp.tools.shaper_queues import ListShaperQueuesTool
from opnsense_mcp.tools.shaper_rules import ListShaperRulesTool
from opnsense_mcp.tools.shaper_service import ShaperStatisticsTool
from opnsense_mcp.tools.shaper_settings import GetShaperSettingsTool
from opnsense_mcp.tools.system import SystemTool


class PerformanceBenchmark:
    """Benchmark OPNsense MCP tools performance."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "environment": self._get_environment_info(),
            "tools": {},
        }
        self.client = get_opnsense_client({})

    def _get_environment_info(self) -> dict[str, Any]:
        """Get environment information for the benchmark."""
        return {
            "python_version": sys.version,
            "platform": sys.platform,
            "working_directory": str(Path.cwd()),
            "opnsense_host": os.environ.get("OPNSENSE_FIREWALL_HOST", "Not set"),
            "opnsense_api_key": (
                "Set" if os.environ.get("OPNSENSE_API_KEY") else "Not set"
            ),
            "opnsense_api_secret": (
                "Set" if os.environ.get("OPNSENSE_API_SECRET") else "Not set"
            ),
        }

    def _log(self, message: str, level: str = "INFO"):
        """Log a message if verbose mode is enabled."""
        if self.verbose:
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            print(f"[{timestamp}] {level}: {message}")

    async def _benchmark_tool(
        self, tool_name: str, tool_class, args: dict = None
    ) -> dict[str, Any]:
        """Benchmark a single tool and return performance metrics."""
        if args is None:
            args = {}

        self._log(f"Benchmarking {tool_name}...")

        start_time = time.time()
        start_cpu = time.process_time()

        try:
            tool = tool_class(self.client)
            result = await tool.execute(args)

            end_time = time.time()
            end_cpu = time.process_time()

            response_time = end_time - start_time
            cpu_time = end_cpu - start_cpu

            # Calculate data size
            data_size = len(json.dumps(result, default=str).encode("utf-8"))

            metrics = {
                "success": True,
                "response_time_seconds": round(response_time, 4),
                "cpu_time_seconds": round(cpu_time, 4),
                "data_size_bytes": data_size,
                "data_size_mb": round(data_size / (1024 * 1024), 4),
                "error": None,
                "result_summary": self._summarize_result(result),
            }

            self._log(
                f"{tool_name} completed in {response_time:.3f}s, {data_size} bytes"
            )

        except Exception as e:
            end_time = time.time()
            end_cpu = time.process_time()

            response_time = end_time - start_time
            cpu_time = end_cpu - start_cpu

            metrics = {
                "success": False,
                "response_time_seconds": round(response_time, 4),
                "cpu_time_seconds": round(cpu_time, 4),
                "data_size_bytes": 0,
                "data_size_mb": 0,
                "error": str(e),
                "result_summary": None,
            }

            self._log(f"{tool_name} failed: {e}", "ERROR")

        return metrics

    def _summarize_result(self, result: Any) -> dict[str, Any]:
        """Create a summary of the tool result."""
        if isinstance(result, dict):
            summary = {}
            for key, value in result.items():
                if isinstance(value, list):
                    summary[f"{key}_count"] = len(value)
                elif isinstance(value, dict):
                    summary[f"{key}_keys"] = list(value.keys())[:5]  # First 5 keys
                else:
                    summary[key] = str(value)[:100]  # First 100 chars
            return summary
        return {"type": type(result).__name__, "value": str(result)[:100]}

    async def run_benchmark(self) -> dict[str, Any]:
        """Run the complete benchmark suite."""
        self._log("Starting OPNsense MCP Tools Performance Benchmark")

        # Define tools to benchmark
        tools_to_test = [
            ("system", SystemTool, {}),
            ("arp", ARPTool, {}),
            ("dhcp", DHCPTool, {}),
            ("lldp", LLDPTool, {}),
            ("interface_list", InterfaceListTool, {}),
            ("fw_rules", FwRulesTool, {"limit": 10}),
            ("firewall_logs", GetLogsTool, {"limit": 10}),
            ("list_shaper_pipes", ListShaperPipesTool, {}),
            ("list_shaper_queues", ListShaperQueuesTool, {}),
            ("list_shaper_rules", ListShaperRulesTool, {}),
            ("get_shaper_settings", GetShaperSettingsTool, {}),
            ("shaper_statistics", ShaperStatisticsTool, {}),
            ("audit_shaper_config", AuditShaperConfigTool, {}),
            ("explain_shaper_config", ExplainShaperConfigTool, {}),
        ]

        # Test each tool
        for tool_name, tool_class, args in tools_to_test:
            self._log(f"Testing {tool_name}...")
            metrics = await self._benchmark_tool(tool_name, tool_class, args)
            self.results["tools"][tool_name] = metrics

        # Calculate overall statistics
        self._calculate_overall_stats()

        self._log("Benchmark completed")
        return self.results

    def _calculate_overall_stats(self):
        """Calculate overall performance statistics."""
        successful_tools = [m for m in self.results["tools"].values() if m["success"]]

        if successful_tools:
            response_times = [m["response_time_seconds"] for m in successful_tools]
            data_sizes = [m["data_size_bytes"] for m in successful_tools]

            self.results["overall_stats"] = {
                "total_tools_tested": len(self.results["tools"]),
                "successful_tools": len(successful_tools),
                "failed_tools": len(self.results["tools"]) - len(successful_tools),
                "success_rate": round(
                    len(successful_tools) / len(self.results["tools"]) * 100, 2
                ),
                "avg_response_time": round(
                    sum(response_times) / len(response_times), 4
                ),
                "min_response_time": round(min(response_times), 4),
                "max_response_time": round(max(response_times), 4),
                "total_data_transferred": sum(data_sizes),
                "avg_data_size": round(sum(data_sizes) / len(data_sizes), 2),
            }
        else:
            self.results["overall_stats"] = {
                "total_tools_tested": len(self.results["tools"]),
                "successful_tools": 0,
                "failed_tools": len(self.results["tools"]),
                "success_rate": 0,
                "error": "No tools completed successfully",
            }

    def print_summary(self):
        """Print a human-readable summary of the benchmark results."""
        print("\n" + "=" * 60)
        print("OPNsense MCP Tools Performance Benchmark Results")
        print("=" * 60)

        # Environment info
        env = self.results["environment"]
        print("\nEnvironment:")
        print(f"  Python: {env['python_version'].split()[0]}")
        print(f"  Platform: {env['platform']}")
        print(f"  OPNsense Host: {env['opnsense_host']}")
        print(f"  API Key: {env['opnsense_api_key']}")
        print(f"  API Secret: {env['opnsense_api_secret']}")

        # Overall stats
        if "overall_stats" in self.results:
            stats = self.results["overall_stats"]
            print("\nOverall Performance:")
            print(f"  Tools Tested: {stats['total_tools_tested']}")
            print(f"  Successful: {stats['successful_tools']}")
            print(f"  Failed: {stats['failed_tools']}")
            print(f"  Success Rate: {stats['success_rate']}%")

            if "avg_response_time" in stats:
                print(f"  Avg Response Time: {stats['avg_response_time']}s")
                print(f"  Min Response Time: {stats['min_response_time']}s")
                print(f"  Max Response Time: {stats['max_response_time']}s")
                print(f"  Total Data: {stats['total_data_transferred']:,} bytes")
                print(f"  Avg Data Size: {stats['avg_data_size']:,} bytes")

        # Individual tool results
        print("\nIndividual Tool Results:")
        print("-" * 60)
        for tool_name, metrics in self.results["tools"].items():
            status = "✅ PASS" if metrics["success"] else "❌ FAIL"
            response_time = f"{metrics['response_time_seconds']}s"
            data_size = f"{metrics['data_size_bytes']:,} bytes"

            print(f"{tool_name:15} {status:8} {response_time:>8} {data_size:>12}")

            if not metrics["success"] and metrics["error"]:
                print(f"  Error: {metrics['error']}")

        print("\n" + "=" * 60)


# ---------------------------------------------------------------------------
# Response-shape drift
# ---------------------------------------------------------------------------
#
# Two normalizers were tested against hand-written fixtures using key names
# OPNsense does not emit, so the suite stayed green while `fw_rule list`
# reported every rule as any->any and the DHCP subnet selector matched
# nothing. Captured fixtures fix the ones we know about; this catches the
# next rename, which no offline test can see.
#
# It lives here rather than in tests/ on purpose: it opens a live connection,
# and a probe named test_* at the collection path means a routine `pytest`
# run dials the firewall.
#
# MVC select fields look like ``{"opt13": {"selected": 1, "value": "..."}}``.
# The shape check compares only the outer field names on a node (or row),
# not the option keys inside a select. Normalizers read those outer names;
# option sets change whenever interfaces or plugins are added and would
# produce constant false drift without teaching us anything about the
# contract the tools depend on.

FIXTURE_DIR = Path(__file__).parent / "tests" / "fixtures" / "opnsense-26.7.3"


@dataclass(frozen=True)
class ShapeSource:
    """One API response whose shape is tracked against a fixture.

    ``kind="rows"`` is a bootgrid ``{"rows": [...]}`` payload; ``kind="node"``
    is a ``get_*`` response wrapping fields under ``root_key``.
    """

    method: str
    endpoint: str
    body: dict[str, Any] | None = None
    kind: Literal["rows", "node"] = "rows"
    root_key: str | None = None


# Bootgrid search endpoints return ``{"rows": [...]}`` — ``_row_keys`` unions
# every row's keys. ``get_*`` endpoints return ``{<root_key>: {...}}`` —
# ``_node_keys`` takes the field names of that single node. Declaring the
# kind here is what stops a node fixture from comparing empty-to-empty.
SHAPE_SOURCES: dict[str, ShapeSource] = {
    "filter_searchrule_rows.json": ShapeSource(
        "POST",
        "/api/firewall/filter/searchRule",
        {"current": 1, "rowCount": 5},
        kind="rows",
    ),
    "dnsmasq_search_range_rows.json": ShapeSource(
        "GET",
        "/api/dnsmasq/settings/search_range",
        None,
        kind="rows",
    ),
    "radvd_get_entry.json": ShapeSource(
        "GET",
        "/api/radvd/settings/get_entry",
        None,
        kind="node",
        root_key="entries",
    ),
    "unbound_gethostoverride.json": ShapeSource(
        "GET",
        "/api/unbound/settings/getHostOverride",
        None,
        kind="node",
        root_key="host",
    ),
    "npt_get_rule_blank.json": ShapeSource(
        "GET",
        "/api/firewall/npt/get_rule",
        None,
        kind="node",
        root_key="rule",
    ),
    "vip_get_item_blank.json": ShapeSource(
        "GET",
        "/api/interfaces/vip_settings/get_item",
        None,
        kind="node",
        root_key="vip",
    ),
}


def _row_keys(payload: Any) -> set[str]:
    """Union of the keys across every row of a bootgrid response."""
    rows = payload.get("rows") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return set()
    return (
        set().union(*(set(r) for r in rows if isinstance(r, dict))) if rows else set()
    )


def _node_keys(payload: Any, root_key: str) -> tuple[set[str] | None, str | None]:
    """Extract outer field names of the node under ``root_key``.

    Returns ``(keys, error)``. A missing or non-dict root key is the D1
    pattern (fixture said ``entry``, firewall sends ``entries``): return
    ``(None, message)`` so the caller reports drift instead of comparing
    two empty sets.
    """
    if not isinstance(payload, dict):
        return None, f"payload is not a dict (got {type(payload).__name__})"

    if root_key not in payload:
        present = sorted(k for k in payload if isinstance(k, str))
        return None, (
            f"root key {root_key!r} missing from response; "
            f"top-level keys present: {present}"
        )

    node = payload[root_key]
    if not isinstance(node, dict):
        return None, (
            f"node at root key {root_key!r} is not a dict (got {type(node).__name__})"
        )

    # Outer field names only — see module note on MVC selects.
    return set(node), None


def _keys_for_source(
    payload: Any, source: ShapeSource
) -> tuple[set[str] | None, str | None]:
    """Dispatch key extraction for a declared shape source."""
    if source.kind == "node":
        if not source.root_key:
            return None, "node-shaped source declares no root_key"
        return _node_keys(payload, source.root_key)
    return _row_keys(payload), None


def compare_shape_keys(
    expected: set[str] | None,
    live: set[str] | None,
    *,
    kind: Literal["rows", "node"],
    expected_error: str | None = None,
    live_error: str | None = None,
) -> list[tuple[str, str]]:
    """Compare extracted key sets for one shape source.

    Returns a list of ``(status, detail)`` findings. Status is one of
    ``ok``, ``drift``, ``stale``, ``empty``, or ``error``. An empty list is
    not used; success is a single ``("ok", ...)`` entry.

    For ``kind="node"``, an empty-vs-empty comparison is never ``ok``: that
    is how a missing root key used to hide behind two empty sets.
    """
    findings: list[tuple[str, str]] = []
    if expected_error is not None or live_error is not None:
        parts = [p for p in (expected_error, live_error) if p]
        findings.append(("error", "; ".join(parts)))
        return findings

    assert expected is not None and live is not None

    if kind == "node" and not expected and not live:
        findings.append(
            (
                "error",
                "node source produced empty key sets on both sides; "
                "refusing to treat empty-vs-empty as a match",
            )
        )
        return findings

    if kind == "rows" and not live:
        findings.append(("empty", "returned no rows to compare"))
        return findings

    if kind == "node" and not live:
        findings.append(("error", "node source produced an empty live key set"))
        return findings

    gone = sorted(expected - live)
    added = sorted(live - expected)
    if gone:
        findings.append(
            ("drift", f"fixture keys the firewall no longer sends: {', '.join(gone)}")
        )
    if added:
        findings.append(
            ("stale", f"firewall keys missing from the fixture: {', '.join(added)}")
        )
    if not findings:
        findings.append(("ok", f"{len(expected)} keys match"))
    return findings


async def check_response_shapes(verbose: bool = False) -> int:
    """Diff live response keys against the captured fixtures.

    Returns 0 when every fixture still matches the firewall, 1 otherwise. A
    key the firewall no longer sends is a defect waiting to happen; a key it
    sends that the fixture lacks means the fixture is stale.
    """
    client = get_opnsense_client({})
    if client is None:
        print("No OPNsense client available; cannot check response shapes.")
        return 1

    drifted = 0
    for filename, source in SHAPE_SOURCES.items():
        fixture_path = FIXTURE_DIR / filename
        if not fixture_path.exists():
            print(f"MISSING  {filename}: no captured fixture to compare against")
            drifted += 1
            continue

        expected, expected_err = _keys_for_source(
            json.loads(fixture_path.read_text()), source
        )
        try:
            live_payload = (
                await client._make_request(
                    source.method, source.endpoint, json=source.body
                )
                if source.body is not None
                else await client._make_request(source.method, source.endpoint)
            )
            live, live_err = _keys_for_source(live_payload, source)
        except Exception as exc:  # noqa: BLE001
            print(f"ERROR    {filename}: {source.endpoint} failed: {exc}")
            drifted += 1
            continue

        findings = compare_shape_keys(
            expected,
            live,
            kind=source.kind,
            expected_error=expected_err,
            live_error=live_err,
        )
        for status, detail in findings:
            if status == "ok":
                print(f"OK       {filename}: {detail}")
            elif status == "empty":
                print(f"EMPTY    {filename}: {source.endpoint} {detail}")
            elif status == "drift":
                print(f"DRIFT    {filename}: {detail}")
                drifted += 1
            elif status == "stale":
                print(f"STALE    {filename}: {detail}")
                drifted += 1
            else:
                print(f"DRIFT    {filename}: {detail}")
                drifted += 1
        if verbose and any(s != "ok" and s != "empty" for s, _ in findings):
            if expected is not None and live is not None:
                print(f"         expected={sorted(expected)}")
                print(f"         live    ={sorted(live)}")

    return 1 if drifted else 0


async def main():
    """Main benchmark function."""
    parser = argparse.ArgumentParser(
        description="Benchmark OPNsense MCP tools performance"
    )
    parser.add_argument("--output", "-o", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Quiet output (no summary)"
    )
    parser.add_argument(
        "--check-shapes",
        action="store_true",
        help=(
            "Diff live API response keys against the captured fixtures and "
            "exit; fails when a field is renamed, added or removed upstream"
        ),
    )

    args = parser.parse_args()

    if args.check_shapes:
        return await check_response_shapes(verbose=args.verbose)

    # Create benchmark instance
    benchmark = PerformanceBenchmark(verbose=args.verbose)

    # Run benchmark
    results = await benchmark.run_benchmark()

    # Save results if output file specified
    if args.output:
        output_path = Path(args.output)
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"Results saved to {output_path}")

    # Print summary unless quiet mode
    if not args.quiet:
        benchmark.print_summary()

    # Return appropriate exit code
    if results.get("overall_stats", {}).get("success_rate", 0) < 100:
        return 1  # Some tools failed
    return 0  # All tools passed


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
