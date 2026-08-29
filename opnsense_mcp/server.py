#!/usr/bin/env python3
"""OPNsense MCP Server - Main entry point for the MCP server."""

from __future__ import annotations

import logging
import os
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import Any


def _discover_project_root() -> Path | None:
    """Return repo root (directory with pyproject.toml and opnsense_mcp/), if any."""
    here = Path(__file__).resolve()
    for d in here.parents:
        if (d / "pyproject.toml").is_file() and (d / "opnsense_mcp").is_dir():
            return d
    return None


def _ensure_runtime_deps() -> None:
    """Install third-party deps when the interpreter has no venv packages (hosted MCP)."""
    try:
        import pydantic  # noqa: F401
    except ImportError:
        pass
    else:
        return

    pip = [sys.executable, "-m", "pip"]
    try:
        subprocess.run(  # nosec B603
            [*pip, "--version"], check=True, capture_output=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        subprocess.run(  # nosec B603
            [sys.executable, "-m", "ensurepip", "--upgrade", "--default-pip"],
            check=True,
        )

    install = [*pip, "install", "--no-cache-dir"]
    root = _discover_project_root()
    if root is not None:
        req = root / "requirements.txt"
        if req.is_file():
            subprocess.run(  # nosec B603
                [*install, "-r", str(req)], cwd=str(root), check=True
            )
            return
        subprocess.run(  # nosec B603
            [*install, str(root)], cwd=str(root), check=True
        )
        return

    # Last resort: no requirements.txt on disk, so take the pins from this
    # package's own metadata rather than a third hand-maintained copy. The
    # copy that used to live here had drifted to `fastmcp>=0.1.0`, which
    # cannot speak any protocol this server implements.
    try:
        from importlib.metadata import requires as _requires

        pins = [
            spec.split(";")[0].strip()
            for spec in (_requires("opnsense-mcp") or [])
            if "extra ==" not in spec
        ]
    except Exception:  # noqa: BLE001 - bootstrap must not fail on metadata
        pins = []

    if not pins:
        # This runs at import, before logging is configured, so stderr it is.
        print(
            "opnsense-mcp: cannot bootstrap dependencies, no requirements.txt "
            "found and package metadata is unavailable; install the package "
            "first",
            file=sys.stderr,
        )
        return

    subprocess.run([*install, *pins], check=True)  # nosec B603


_ensure_runtime_deps()

import asyncio
import json

from opnsense_mcp.build_info import get_build_info
from opnsense_mcp.tools.aliases import AliasesTool
from opnsense_mcp.tools.arp import ARPTool
from opnsense_mcp.tools.dhcp import DHCPTool
from opnsense_mcp.tools.dhcp_host_move import MoveDhcpHostTool
from opnsense_mcp.tools.dhcp_hosts import ListDhcpHostsTool
from opnsense_mcp.tools.dhcp_lease_delete import DHCPLeaseDeleteTool
from opnsense_mcp.tools.dhcp_subnet_dns import (
    ListDhcpSubnetDnsTool,
    SetDhcpSubnetDnsTool,
)
from opnsense_mcp.tools.dns import DNSTool
from opnsense_mcp.tools.firewall_logs import FirewallLogsTool
from opnsense_mcp.tools.flush_dns import FlushDnsTool
from opnsense_mcp.tools.fw_rules import FwRulesTool
from opnsense_mcp.tools.gateway_status import GatewayStatusTool
from opnsense_mcp.tools.interface_health import InterfaceHealthTool
from opnsense_mcp.tools.interface_list import InterfaceListTool
from opnsense_mcp.tools.lldp import LLDPTool
from opnsense_mcp.tools.mk_dhcp_host import MkDhcpHostTool
from opnsense_mcp.tools.mkdns import MkdnsTool
from opnsense_mcp.tools.mkfw_rule import MkfwRuleTool
from opnsense_mcp.tools.packet_capture import PacketCaptureTool2 as PacketCaptureTool
from opnsense_mcp.tools.pf_diagnostics import PfStatesTool, PfStatisticsTool
from opnsense_mcp.tools.rm_dhcp_host import RmDhcpHostTool
from opnsense_mcp.tools.rmdns import RmdnsTool
from opnsense_mcp.tools.rmfw_rule import RmfwRuleTool
from opnsense_mcp.tools.set_fw_rule import SetFwRuleTool
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
from opnsense_mcp.tools.system import SystemTool
from opnsense_mcp.tools.toggle_dhcp_range import ToggleDhcpRangeTool
from opnsense_mcp.tools.toggle_fw_rule import ToggleFwRuleTool
from opnsense_mcp.utils.api import OPNsenseClient
from opnsense_mcp.utils.env import load_opnsense_env
from opnsense_mcp.utils.mock_api import MockOPNsenseClient
from opnsense_mcp.utils.registry import build_tools, dispatch, list_tools_payload
from opnsense_mcp.utils.tool_groups import build_groups

logger = logging.getLogger(__name__)

# Load credentials from home dotenv files (see utils/env.load_opnsense_env)
load_opnsense_env()


def get_opnsense_client(config: dict[str, Any]) -> Any:
    """Get an OPNsense client instance based on environment variables."""
    host = os.getenv("OPNSENSE_FIREWALL_HOST")  # Use correct env var name
    api_key = os.getenv("OPNSENSE_API_KEY")
    api_secret = os.getenv("OPNSENSE_API_SECRET")
    ssl_verify = os.getenv("OPNSENSE_SSL_VERIFY", "false").lower() == "true"

    # SSH configuration
    ssh_host = os.getenv("OPNSENSE_SSH_HOST", host)  # Default to firewall host
    ssh_user = os.getenv("OPNSENSE_SSH_USER", "root")
    ssh_key = os.getenv("OPNSENSE_SSH_KEY")

    if host and api_key and api_secret:
        logger.info("Using real OPNsense client")
        client = OPNsenseClient(
            {
                "firewall_host": host,
                "api_key": api_key,
                "api_secret": api_secret,
                "verify_ssl": ssl_verify,
            }
        )

        # Add SSH configuration to the client
        client.ssh_config = {
            "host": ssh_host,
            "user": ssh_user,
            "key": ssh_key,
        }

        logger.info(f"SSH Config: host={ssh_host}, user={ssh_user}, key={ssh_key}")

        return client

    logger.warning("No OPNsense credentials found, using mock client")
    workspace_root = Path(__file__).parent.parent
    mock_data_path = workspace_root / "examples" / "mock_data"
    config = {"development": {"mock_data_path": str(mock_data_path)}}
    return MockOPNsenseClient(config)


def format_log_response(logs: list) -> dict[str, Any]:
    """Format logs into an MCP protocol response."""
    log_entries = []
    for log in logs:
        description = f"{log.action.upper()} {log.protocol} "
        description += f"{log.src_ip}:{log.src_port} -> "
        description += f"{log.dst_ip}:{log.dst_port}"
        if log.description:
            description += f" ({log.description})"

        log_entries.append(
            {
                "text": description,
                "type": "text",
                "timestamp": log.timestamp.isoformat(),
                "metadata": {
                    "src_ip": log.src_ip,
                    "dst_ip": log.dst_ip,
                    "action": log.action,
                    "protocol": log.protocol,
                },
            }
        )

    return {
        "jsonrpc": "2.0",
        "result": {
            "type": "log_entries",
            "entries": log_entries,
        },
    }


def _post_process(tool_name: str, arguments: dict[str, Any], result: Any) -> Any:
    """Tool-specific handling the generic dispatch cannot cover.

    Only packet_capture needs this: when asked for raw output it attaches a
    preview of the captured file. Kept out of the tool so the tool stays a
    plain execute(), and kept here so the dispatch loop stays uniform.
    """
    if tool_name != "packet_capture":
        return result

    if result is None:
        return {
            "status": "error",
            "error": "Tool returned no response",
            "guidance": (
                "The packet capture tool failed to return a response. "
                "This may indicate an internal error."
            ),
        }

    wants_raw = arguments.get("raw")
    fetched = (
        isinstance(result, dict)
        and arguments.get("action") == "fetch"
        and result.get("status") == "success"
    )
    if wants_raw and fetched:
        try:
            with open(result["local_file"], "rb") as handle:
                result["raw_preview"] = handle.read(1000).hex()
        except Exception as exc:  # noqa: BLE001 - preview is best effort
            result["raw_preview_error"] = str(exc)
    return result


# Newest first: a client picking from `server/discover` should land on
# 2026-07-28. The older two stay listed because clients still open with
# `initialize` during the deprecation window.
SUPPORTED_PROTOCOL_VERSIONS: tuple[str, ...] = (
    "2026-07-28",
    "2025-11-25",
    "2025-03-26",
)


async def handle_message(
    message: dict[str, Any],
    tools: dict[str, Any] | None = None,
    shaper_tools: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Handle incoming MCP messages and route them to appropriate tools.

    ``shaper_tools`` maps traffic-shaper tool names to instances so the stdio
    server exposes the same surface as the FastMCP/HTTP server. It is keyword
    optional for backward compatibility with existing direct callers/tests.
    """
    method = message.get("method")
    msg_id = message.get("id")

    # MCP 2026-07-28 replaces the initialize/initialized handshake with an
    # on-demand `server/discover`. `initialize` is kept below because clients on
    # 2025-11-25 still open with it throughout the deprecation window, and this
    # dispatcher holds no session state either way: every request is answered
    # from the registry, so nothing here needs a handshake to have happened.
    if method == "server/discover":
        build_info = get_build_info()
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "supportedVersions": list(SUPPORTED_PROTOCOL_VERSIONS),
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {
                    "name": build_info["name"],
                    "version": build_info["package_version"],
                    "git_commit": build_info["git_commit"],
                    "git_ref": build_info["git_ref"],
                    "build_time": build_info["build_time"],
                },
                "instructions": (
                    "OPNsense firewall management. Most tools are grouped by "
                    "resource and take an `action`: pick the object, then the "
                    "verb. Call action='help' on any of them for that "
                    "resource's per-action fields, defaults and rules."
                ),
            },
        }

    # Forgiving protocolVersion handling
    if method == "initialize":
        protocol_version = message.get("params", {}).get("protocolVersion")
        if not protocol_version or protocol_version == "undefined":
            protocol_version = "2024-11-05"
        build_info = get_build_info()
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": protocol_version,
                "serverInfo": {
                    "name": build_info["name"],
                    "version": build_info["package_version"],
                    "git_commit": build_info["git_commit"],
                    "git_ref": build_info["git_ref"],
                    "build_time": build_info["build_time"],
                },
                "capabilities": {"tools": {"listChanged": False}},
            },
        }

    # Handle notifications/initialized to prevent red indicator
    if method == "notifications/initialized":
        # Do not respond to notifications (no id)
        if msg_id is None:
            return None

    # Handle initialized notification properly
    if method == "initialized":
        # This is a notification, not a request, so no response needed
        # Just log it and continue
        logger.info("Received initialized notification")
        return None

    # Support both tools/list and ListOfferings
    if method in ("tools/list", "ListOfferings"):
        registered = dict(tools or {})
        if shaper_tools:
            registered.update(shaper_tools)
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {"tools": list_tools_payload(registered)},
        }

    # Support both tools/call and tool/call
    if method in ("tools/call", "tool/call"):
        params = message.get("params", {})
        if not params:
            # For tool/call, some clients may use top-level keys
            params = message
        tool_name = params.get("name") or params.get("tool") or ""
        arguments = params.get("arguments") or params.get("args") or {}

        registered = dict(tools or {})
        if shaper_tools:
            registered.update(shaper_tools)

        if tool_name not in registered:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32601,
                    "message": f"Tool not found: {tool_name}",
                },
            }

        try:
            result = await dispatch(registered, tool_name, arguments)
        except Exception as exc:  # noqa: BLE001 - surfaced to the caller as text
            logger.exception("Tool %s failed", tool_name)
            result = {
                "status": "error",
                "error": f"{tool_name} failed: {exc}",
            }

        result = _post_process(tool_name, arguments, result)
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {"content": [{"type": "text", "text": str(result)}]},
        }

    return None


def error_response(
    code: int, message: str, msg_id: str | None = None
) -> dict[str, Any]:
    """Create a JSON-RPC error response."""
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {
            "code": code,
            "message": message,
        },
    }


def main() -> None:
    """Main entry point for the MCP server."""
    # Configure logging
    log_level = os.environ.get("LOG_LEVEL", "INFO")
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        stream=sys.stderr,
    )

    # Initialize client
    client = get_opnsense_client({})

    # Every non-shaper tool comes from the registry.
    tools = build_tools(client)

    # Traffic-shaper tool surface (parity with FastMCP/HTTP server).
    shaper_tool_instances: list[Any] = [
        ListShaperPipesTool(client),
        GetShaperPipeTool(client),
        AddShaperPipeTool(client),
        SetShaperPipeTool(client),
        ToggleShaperPipeTool(client),
        DeleteShaperPipeTool(client),
        ListShaperQueuesTool(client),
        GetShaperQueueTool(client),
        AddShaperQueueTool(client),
        SetShaperQueueTool(client),
        ToggleShaperQueueTool(client),
        DeleteShaperQueueTool(client),
        ListShaperRulesTool(client),
        GetShaperRuleTool(client),
        AddShaperRuleTool(client),
        SetShaperRuleTool(client),
        ToggleShaperRuleTool(client),
        DeleteShaperRuleTool(client),
        GetShaperSettingsTool(client),
        ShaperStatisticsTool(client),
        ApplyShaperTool(client),
        RestoreShaperSnapshotTool(client),
        ApplyShaperPresetTool(client),
        AuditShaperConfigTool(client),
        ExplainShaperConfigTool(client),
    ]
    shaper_tools: dict[str, Any] = {t.name: t for t in shaper_tool_instances}

    # One operation per class, but a smaller surface: most are exposed grouped by
    # resource with an `action`. See utils/tool_groups.
    exposed = build_groups({**tools, **shaper_tools})
    logger.info(
        "Exposing %d tools from %d operations",
        len(exposed),
        len(tools) + len(shaper_tools),
    )

    # Handle stdin/stdout communication
    async def process_messages() -> None:
        """Process incoming messages from the MCP client."""
        while True:
            try:
                # Read a line and handle EOF
                line = sys.stdin.readline()
                if not line:
                    break

                # Remove trailing newlines and skip empty lines
                line = line.strip()
                if not line:
                    continue

                # Log raw input for debugging
                logger.debug(f"Raw input line: {line!r}")

                # Parse the JSON message
                message = json.loads(line)
                msg_id = message.get("id")
                logger.debug(f"Parsed message: {message}")

                # Validate required fields
                if "jsonrpc" not in message or message["jsonrpc"] != "2.0":
                    err = error_response(
                        -32600, "Invalid Request: jsonrpc 2.0 required", msg_id
                    )
                    sys.stdout.write(json.dumps(err) + "\n")
                    sys.stdout.flush()
                    continue

                if "method" not in message:
                    err = error_response(
                        -32600, "Invalid Request: method required", msg_id
                    )
                    sys.stdout.write(json.dumps(err) + "\n")
                    sys.stdout.flush()
                    continue

                # Handle the message
                response = await handle_message(message, exposed)
                if response is not None:
                    sys.stdout.write(json.dumps(response) + "\n")
                    sys.stdout.flush()
                    logger.debug(f"Sent response: {response}")
                elif msg_id is not None:
                    err = error_response(
                        -32601,
                        f"Method '{message.get('method')}' not found",
                        msg_id,
                    )
                    sys.stdout.write(json.dumps(err) + "\n")
                    sys.stdout.flush()

            except json.JSONDecodeError:
                logger.exception("Invalid JSON")
                err = error_response(-32700, "Parse error")
                sys.stdout.write(json.dumps(err) + "\n")
                sys.stdout.flush()
            except Exception as e:
                logger.error(f"Error handling message: {e}", exc_info=True)
                err_msg = f"Internal error: {str(e)}"
                err = error_response(-32603, err_msg, msg_id)
                sys.stdout.write(json.dumps(err) + "\n")
                sys.stdout.flush()

    asyncio.run(process_messages())


if __name__ == "__main__":
    try:
        main()
    except Exception:
        logger.exception("Fatal error")
        sys.exit(1)
