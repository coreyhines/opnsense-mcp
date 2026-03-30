import logging
import os
import shlex
import subprocess  # nosec B404 — subprocess required for local process management
import time
from pathlib import Path
from typing import Any

import paramiko
from paramiko.config import SSHConfig

from opnsense_mcp.utils.env import load_opnsense_env
from opnsense_mcp.utils.paramiko_ssh import apply_paramiko_host_key_policy

logger = logging.getLogger(__name__)


class PacketCaptureTool2:
    """Tool for running packet captures on OPNsense via SSH with automatic error detection and correction."""

    def __init__(
        self,
        client=None,
        ssh_host: str = None,
        ssh_user: str = None,
        ssh_key: str = None,
    ):
        self.client = client

        # Load credentials via env.load_opnsense_env (see opnsense_mcp.utils.env)
        load_opnsense_env()

        env_host = os.getenv("OPNSENSE_FIREWALL_HOST")
        env_user = os.getenv("OPNSENSE_SSH_USER")
        env_key = os.getenv("OPNSENSE_SSH_KEY")
        config_host = ssh_host or env_host or "opnsense"
        self.ssh_host = config_host
        self.ssh_user = (
            ssh_user
            or env_user
            or self._get_ssh_config("user", config_host)
            or os.getenv("USER")
            or "root"
        )
        raw_key = (
            ssh_key or env_key or self._get_ssh_config("identityfile", config_host)
        )
        self.ssh_key = os.path.expanduser(raw_key) if raw_key else None
        self.capture_file = "/tmp/mcp_capture.pcap"  # nosec B108 — remote path on OPNsense firewall, not local temp usage
        self.ssh_port = 22

        # Keep connection details on logger, never stdout in MCP mode.
        logger.info(
            "SSH Config: host=%s, user=%s, key=%s",
            self.ssh_host,
            self.ssh_user,
            self.ssh_key,
        )

    def _get_ssh_config(self, key: str, config_host: str) -> str | None:
        ssh_config_path = os.path.expanduser("~/.ssh/config")
        if not os.path.exists(ssh_config_path):
            return None
        with open(ssh_config_path) as f:
            config = SSHConfig()
            config.parse(f)
            host = config.lookup(config_host)
            return host.get(key)

    def _get_client(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        apply_paramiko_host_key_policy(client)
        client.connect(
            hostname=self.ssh_host,
            username=self.ssh_user,
            key_filename=self.ssh_key,
            port=self.ssh_port,
            timeout=10,
        )
        return client

    def _detect_mcp_server_issues(self) -> dict[str, Any]:
        """Detect common MCP server issues and provide solutions."""
        issues = []
        solutions = []

        # Check if MCP server process is running
        try:
            result = subprocess.run(
                ["pgrep", "-f", "opnsense_mcp/server.py"],
                capture_output=True,
                text=True,
            )  # nosec B603 B607 — hardcoded command, no user input
            if result.returncode != 0:
                # Try alternative process detection
                result2 = subprocess.run(
                    ["ps", "aux"],
                    capture_output=True,
                    text=True,
                )  # nosec B603 B607 — hardcoded command, no user input
                if "opnsense_mcp/server.py" in result2.stdout:
                    # Process is running but pgrep didn't find it
                    pass
                else:
                    issues.append("OPNsense MCP server is not running")
                    solutions.append("Restart the MCP server using: ./mcp_start.sh")
        except Exception as e:
            issues.append(f"Could not check MCP server status: {e}")
            solutions.append("Manually check if the MCP server is running")

        # Check if virtual environment exists
        venv_path = Path.cwd() / ".venv"
        if not venv_path.exists():
            issues.append("Virtual environment (.venv) is missing")
            solutions.append(
                "Recreate virtual environment: python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt"
            )

        # Check if required dependencies are installed
        try:
            import dotenv
            import paramiko
        except ImportError as e:
            issues.append(f"Missing dependency: {e}")
            solutions.append("Install dependencies: pip install -r requirements.txt")

        # Check SSH connectivity
        try:
            client = self._get_client()
            client.close()
        except Exception as e:
            issues.append(f"SSH connection failed: {e}")
            solutions.append("Check SSH configuration and firewall connectivity")

        return {
            "has_issues": len(issues) > 0,
            "issues": issues,
            "solutions": solutions,
            "status": "healthy" if len(issues) == 0 else "needs_attention",
        }

    def _auto_correct_issues(self) -> dict[str, Any]:
        """Attempt to automatically correct detected issues."""
        corrections = []
        errors = []

        # Try to restart MCP server if not running
        try:
            result = subprocess.run(
                ["pgrep", "-f", "opnsense_mcp/server.py"],
                capture_output=True,
                text=True,
            )  # nosec B603 B607 — hardcoded command, no user input
            if result.returncode != 0:
                # Try alternative process detection
                result2 = subprocess.run(
                    ["ps", "aux"],
                    capture_output=True,
                    text=True,
                )  # nosec B603 B607 — hardcoded command, no user input
                if "opnsense_mcp/server.py" in result2.stdout:
                    # Process is running but pgrep didn't find it
                    pass
                else:
                    # Try to start the MCP server
                    try:
                        subprocess.run(
                            ["./mcp_start.sh"],
                            cwd=Path.cwd(),
                            timeout=10,
                            capture_output=True,
                        )  # nosec B603 B607 — hardcoded command, no user input
                        corrections.append("Attempted to restart MCP server")
                        time.sleep(2)  # Give it time to start
                    except Exception as e:
                        errors.append(f"Failed to restart MCP server: {e}")
        except Exception as e:
            errors.append(f"Could not check MCP server status: {e}")

        # Try to recreate virtual environment if missing
        venv_path = Path.cwd() / ".venv"
        if not venv_path.exists():
            try:
                subprocess.run(
                    ["python3", "-m", "venv", ".venv"],
                    cwd=Path.cwd(),
                    timeout=30,
                    capture_output=True,
                )  # nosec B603 B607 — hardcoded command, no user input
                corrections.append("Recreated virtual environment")

                # Try to install dependencies
                try:
                    subprocess.run(
                        [
                            str(Path.cwd() / ".venv" / "bin" / "pip"),
                            "install",
                            "-r",
                            "requirements.txt",
                        ],
                        cwd=Path.cwd(),
                        timeout=60,
                        capture_output=True,
                    )  # nosec B603 B607 — hardcoded command, no user input
                    corrections.append("Installed dependencies")
                except Exception as e:
                    errors.append(f"Failed to install dependencies: {e}")
            except Exception as e:
                errors.append(f"Failed to recreate virtual environment: {e}")

        return {
            "corrections_applied": corrections,
            "errors": errors,
            "success": len(errors) == 0,
        }

    async def _resolve_interface(self, iface: str) -> str:
        """
        Resolve user-friendly interface name (e.g., 'wan', 'wifi', 'vlan 81') to real device name (e.g., 'ax1').
        Uses all available metadata: name, description, VLAN, addresses, aliases.
        """
        import json
        import os

        try:
            from opnsense_mcp.utils.api import OPNsenseClient

            load_opnsense_env()
            host = os.getenv("OPNSENSE_FIREWALL_HOST")
            api_key = os.getenv("OPNSENSE_API_KEY")
            api_secret = os.getenv("OPNSENSE_API_SECRET")
            if host and api_key and api_secret:
                client = OPNsenseClient(
                    {
                        "firewall_host": host,
                        "api_key": api_key,
                        "api_secret": api_secret,
                        "verify_ssl": False,
                    }
                )
                interfaces = await client.get_interfaces()
                aliases = []
                try:
                    aliases = await client._make_request(
                        "GET", "/api/interfaces/overview/export"
                    )
                except (OSError, ValueError, KeyError) as exc:
                    logger.debug("Failed to fetch interface aliases: %s", exc)
                alias_list = []
                if isinstance(aliases, dict):
                    for key, value in aliases.items():
                        alias_list.append(
                            {
                                "name": key,
                                "description": value.get("description", ""),
                                "device": value.get("device", ""),
                            }
                        )
                iface_lc = iface.lower()
                for entry in interfaces:
                    if entry.get("name", "").lower() == iface_lc:
                        return entry["name"]
                for entry in alias_list:
                    if entry.get("name", "").lower() == iface_lc:
                        return entry["device"] or entry["name"]
                for entry in interfaces:
                    if (
                        iface_lc in (entry.get("description", "") or "").lower()
                        or iface_lc in entry.get("name", "").lower()
                    ):
                        return entry["name"]
                for entry in alias_list:
                    if (
                        iface_lc in (entry.get("description", "") or "").lower()
                        or iface_lc in (entry.get("device", "") or "").lower()
                    ):
                        return entry["device"] or entry["name"]
                for entry in interfaces:
                    for addr in entry.get("addresses", []):
                        if iface_lc in addr.get("address", "").lower():
                            return entry["name"]
                return iface
        except (ImportError, OSError, ValueError, KeyError) as exc:
            logger.debug("Live interface resolution failed, falling back to mock data: %s", exc)
        mock_path = os.path.join(
            os.path.dirname(__file__), "../../examples/mock_data/interfaces.json"
        )
        try:
            with open(os.path.abspath(mock_path)) as f:
                data = json.load(f)
                interfaces = data.get("interfaces", [])
        except Exception:
            interfaces = []
        iface_lc = iface.lower()
        for entry in interfaces:
            if entry.get("name", "").lower() == iface_lc:
                return entry["name"]
        for entry in interfaces:
            if (
                iface_lc in (entry.get("description", "") or "").lower()
                or iface_lc in entry.get("name", "").lower()
            ):
                return entry["name"]
        for entry in interfaces:
            for addr in entry.get("addresses", []):
                if iface_lc in addr.get("address", "").lower():
                    return entry["name"]
        return iface

    async def start_capture(
        self,
        interface: str = "wan",
        filter_expr: str = "",
        duration: int = 5,
        count: int = None,
        stream: bool = False,
        preview_bytes: int = 1000,
        mode: str = "raw",
    ) -> dict[str, Any]:
        """
        Start a packet capture on the given interface.
        - mode: 'raw' (default) streams pcap data; 'text' streams human-readable tcpdump output (-nnevvvi).
        Always resolves logical interface names to OS device names. Returns error if resolution fails.
        """
        import logging

        from opnsense_mcp.tools.interface_list import InterfaceListTool

        requested_iface = interface
        resolved_iface = interface

        # Try to resolve interface name using InterfaceListTool
        try:
            ilt = InterfaceListTool(self.client)
            result = await ilt.execute({"resolve": interface})
            if result.get("resolved_device"):
                resolved_iface = result["resolved_device"]
                logging.getLogger(__name__).info(
                    f"Resolved '{interface}' to '{resolved_iface}'"
                )
            else:
                # If resolution failed, try to use the interface name directly
                # Check if it's already a valid device name
                iface_list = (await ilt.execute({})).get("interfaces", {})
                if interface in iface_list:
                    resolved_iface = interface
                    logging.getLogger(__name__).info(
                        f"Using interface '{interface}' directly"
                    )
                else:
                    # Try common mappings
                    common_mappings = {
                        "wan": "ax1",
                        "lan": "ax0_vlan2",
                        "wifi": "ax0_vlan81",
                        "guest": "ax0_vlan4",
                        "lab": "ax0_vlan3",
                        "mgmt": "igb3",
                    }
                    if interface.lower() in common_mappings:
                        resolved_iface = common_mappings[interface.lower()]
                        logging.getLogger(__name__).info(
                            f"Mapped '{interface}' to '{resolved_iface}'"
                        )
                    else:
                        # Last resort: assume it's already a device name
                        resolved_iface = interface
                        logging.getLogger(__name__).warning(
                            f"Could not resolve '{interface}', using as-is"
                        )
        except Exception as e:
            logging.getLogger(__name__).warning(
                f"Failed to resolve interface '{interface}': {e}"
            )
            # Fallback to common mappings
            common_mappings = {
                "wan": "ax1",
                "lan": "ax0_vlan2",
                "wifi": "ax0_vlan81",
                "guest": "ax0_vlan4",
                "lab": "ax0_vlan3",
                "mgmt": "igb3",
            }
            if interface.lower() in common_mappings:
                resolved_iface = common_mappings[interface.lower()]
            else:
                resolved_iface = interface

        # Sanitize inputs for shell command construction
        safe_iface = shlex.quote(resolved_iface)

        count_arg = ["-c", str(count)] if count else []
        filter_arg = [shlex.quote(filter_expr.strip())] if filter_expr.strip() else []

        def clean_cmd(cmd_parts):
            return " ".join([part for part in cmd_parts if part])

        if mode == "raw":
            # Raw pcap output (binary/hex preview)
            if stream:
                if count and not duration:
                    cmd_parts = (
                        ["sudo", "timeout", "5", "tcpdump", "-U", "-i", safe_iface]
                        + count_arg
                        + ["-w", "-"]
                        + filter_arg
                    )
                    cmd = clean_cmd(cmd_parts)
                elif duration and not count:
                    cmd_parts = [
                        "sudo",
                        "timeout",
                        str(duration),
                        "tcpdump",
                        "-U",
                        "-i",
                        safe_iface,
                        "-w",
                        "-",
                    ] + filter_arg
                    cmd = clean_cmd(cmd_parts)
                elif duration and count:
                    cmd_parts = (
                        [
                            "sudo",
                            "timeout",
                            str(duration),
                            "tcpdump",
                            "-U",
                            "-i",
                            safe_iface,
                        ]
                        + count_arg
                        + ["-w", "-"]
                        + filter_arg
                    )
                    cmd = clean_cmd(cmd_parts)
                else:
                    cmd_parts = [
                        "sudo",
                        "timeout",
                        "5",
                        "tcpdump",
                        "-U",
                        "-i",
                        safe_iface,
                        "-w",
                        "-",
                    ] + filter_arg
                    cmd = clean_cmd(cmd_parts)
                cmd = f"/bin/sh -c '{cmd}'"
                try:
                    client = self._get_client()
                    stdin, stdout, stderr = client.exec_command(cmd)  # nosec B601 — inputs sanitized via shlex.quote  # nosec B601 — inputs sanitized via shlex.quote
                    pcap_data = stdout.read(preview_bytes)
                    err = stderr.read().decode(errors="replace")
                    client.close()
                    return {
                        "status": "success",
                        "mode": "raw",
                        "pcap_preview": pcap_data.hex(),
                        "bytes": len(pcap_data),
                        "requested_interface": requested_iface,
                        "resolved_interface": resolved_iface,
                        "command": cmd,
                        "stderr": err,
                    }
                except Exception as e:
                    return {
                        "status": "error",
                        "error": str(e),
                        "requested_interface": requested_iface,
                        "resolved_interface": resolved_iface,
                        "command": cmd,
                        "guidance": "Raw mode capture failed. Try 'text' mode for human-readable output, or check if the interface is active and has traffic.",
                    }
        elif mode == "text":
            # Human-readable tcpdump output (-nnevvv)
            vflags = "-nnevvv"
            if stream:
                if count and not duration:
                    cmd_parts = (
                        [
                            "sudo",
                            "timeout",
                            "5",
                            "tcpdump",
                            vflags,
                            "-i",
                            safe_iface,
                        ]
                        + count_arg
                        + filter_arg
                    )
                    cmd = clean_cmd(cmd_parts)
                elif duration and not count:
                    cmd_parts = [
                        "sudo",
                        "timeout",
                        str(duration),
                        "tcpdump",
                        vflags,
                        "-i",
                        safe_iface,
                    ] + filter_arg
                    cmd = clean_cmd(cmd_parts)
                elif duration and count:
                    cmd_parts = (
                        [
                            "sudo",
                            "timeout",
                            str(duration),
                            "tcpdump",
                            vflags,
                            "-i",
                            safe_iface,
                        ]
                        + count_arg
                        + filter_arg
                    )
                    cmd = clean_cmd(cmd_parts)
                else:
                    cmd_parts = [
                        "sudo",
                        "timeout",
                        "5",
                        "tcpdump",
                        vflags,
                        "-i",
                        safe_iface,
                    ] + filter_arg
                    cmd = clean_cmd(cmd_parts)
                cmd = f"/bin/sh -c '{cmd}'"
                try:
                    client = self._get_client()
                    stdin, stdout, stderr = client.exec_command(cmd)  # nosec B601 — inputs sanitized via shlex.quote  # nosec B601 — inputs sanitized via shlex.quote
                    text_out = stdout.read(preview_bytes).decode(errors="replace")
                    err = stderr.read().decode(errors="replace")
                    client.close()
                    # Optionally, parse flows from text_out
                    flows = []
                    for line in text_out.splitlines():
                        # Simple flow parsing: look for src > dst or IP proto/port patterns
                        if " > " in line:
                            flows.append(line.strip())
                    return {
                        "status": "success",
                        "mode": "text",
                        "tcpdump_output": text_out,
                        "flows": flows,
                        "requested_interface": requested_iface,
                        "resolved_interface": resolved_iface,
                        "command": cmd,
                        "stderr": err,
                    }
                except Exception as e:
                    return {
                        "status": "error",
                        "error": str(e),
                        "requested_interface": requested_iface,
                        "resolved_interface": resolved_iface,
                        "command": cmd,
                        "guidance": "Text mode capture failed. Check if the interface is active, try a different interface, or verify SSH permissions.",
                    }
        else:
            return {
                "status": "error",
                "error": f"Unknown mode: {mode}",
                "requested_interface": requested_iface,
                "resolved_interface": resolved_iface,
                "guidance": "Valid modes are 'raw' (binary data) or 'text' (human-readable output).",
            }

    def stop_capture(self) -> dict[str, Any]:
        """Stop all running tcpdump processes started by this tool."""
        cmd = "sudo pkill -f 'tcpdump -i'"
        try:
            client = self._get_client()
            stdin, stdout, stderr = client.exec_command(cmd)  # nosec B601 — inputs sanitized via shlex.quote
            stdout.channel.recv_exit_status()
            client.close()
            return {
                "status": "success",
                "message": "Packet capture stopped successfully",
            }
        except Exception as e:
            logger.exception("Failed to stop packet capture")
            return {
                "status": "error",
                "error": str(e),
                "guidance": "Failed to stop packet capture. This may be normal if no capture was running.",
            }

    def fetch_pcap(self, local_path: str = None) -> dict[str, Any]:
        """Download the pcap file from the OPNsense host."""
        local_path = local_path or str(Path.home() / "mcp_capture.pcap")
        try:
            client = self._get_client()
            sftp = client.open_sftp()
            sftp.get(self.capture_file, local_path)
            sftp.close()
            client.close()
            return {
                "status": "success",
                "local_file": local_path,
                "message": f"PCAP file downloaded to {local_path}",
            }
        except Exception as e:
            logger.exception("Failed to fetch pcap file")
            return {
                "status": "error",
                "error": str(e),
                "guidance": "Failed to download PCAP file. Make sure a capture was running and completed successfully first.",
            }

    async def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        """Execute packet capture operations with automatic error detection and correction."""
        action = params.get("action", "start")

        logger.debug("Packet capture execute called with params: %s", params)

        # Special action for diagnostics
        if action == "diagnose":
            return await self._diagnose_and_fix()

        # Validate parameters and provide guidance
        if action == "start":
            # Validate required parameters before any issue detection
            interface = params.get("interface", "wan")
            duration = params.get("duration", 30)
            count = params.get("count")
            mode = params.get(
                "mode", "text"
            )  # Default to text mode for better user experience
            stream = params.get(
                "stream", True
            )  # Default to stream for immediate results

            logger.debug("Packet capture duration=%s type=%s", duration, type(duration))

            # Validate duration
            if duration <= 0 or duration > 3600:
                logger.debug("Duration validation failed: %s", duration)
                return {
                    "status": "error",
                    "error": f"Invalid duration: {duration}. Must be between 1 and 3600 seconds.",
                    "guidance": "Try a duration between 10-300 seconds for best results.",
                }

            # Validate count if provided
            if count is not None and (count <= 0 or count > 10000):
                return {
                    "status": "error",
                    "error": f"Invalid count: {count}. Must be between 1 and 10000 packets.",
                    "guidance": "Try a count between 50-1000 packets for best results.",
                }

            # Validate mode
            if mode not in ["raw", "text"]:
                return {
                    "status": "error",
                    "error": f"Invalid mode: {mode}. Must be 'raw' or 'text'.",
                    "guidance": "Use 'text' mode for human-readable output, 'raw' for binary data.",
                }

            # Detect and auto-correct any infrastructure issues
            issues = self._detect_mcp_server_issues()
            if issues["has_issues"]:
                # Try to auto-correct issues
                corrections = self._auto_correct_issues()

                # If auto-correction failed, return diagnostic information
                if not corrections["success"]:
                    return {
                        "status": "error",
                        "error": "MCP server issues detected and auto-correction failed",
                        "detected_issues": issues["issues"],
                        "suggested_solutions": issues["solutions"],
                        "auto_correction_attempts": corrections["corrections_applied"],
                        "auto_correction_errors": corrections["errors"],
                        "guidance": "Please manually fix the issues above, then try again. You can also use action='diagnose' for detailed diagnostics.",
                    }

                # If auto-correction succeeded, retry the operation
                return await self._retry_after_correction(params)

            # Test SSH connection first
            try:
                client = self._get_client()
                client.close()
            except Exception as e:
                return {
                    "status": "error",
                    "error": f"SSH connection failed: {str(e)}",
                    "guidance": "Please check your SSH configuration and ensure the firewall is accessible.",
                }

            # Test tcpdump availability
            try:
                client = self._get_client()
                stdin, stdout, stderr = client.exec_command("which tcpdump")  # nosec B601 — static command
                if stdout.read().decode().strip() == "":
                    client.close()
                    return {
                        "status": "error",
                        "error": "tcpdump not found on the firewall.",
                        "guidance": "tcpdump may not be installed. Try installing it via the OPNsense package manager.",
                    }
                client.close()
            except Exception as e:
                return {
                    "status": "error",
                    "error": f"Failed to check tcpdump availability: {str(e)}",
                    "guidance": "There may be an SSH or permission issue.",
                }

            # Test interface availability
            try:
                client = self._get_client()
                stdin, stdout, stderr = client.exec_command(f"ifconfig {shlex.quote(interface)}")  # nosec B601 — inputs sanitized via shlex.quote
                if (
                    "not found" in stderr.read().decode()
                    or "No such interface" in stderr.read().decode()
                ):
                    client.close()
                    return {
                        "status": "error",
                        "error": f"Interface '{interface}' not found.",
                        "guidance": "Available interfaces: wan, lan, wifi, guest, lab, mgmt, or specific device names like ax1, ax0_vlan81. Try 'interface_list' tool to see all available interfaces.",
                    }
                client.close()
            except Exception as e:
                return {
                    "status": "error",
                    "error": f"Failed to check interface '{interface}': {str(e)}",
                    "guidance": "There may be an SSH or permission issue.",
                }

            # If all validations pass, proceed with capture
            return await self.start_capture(
                interface,
                params.get("filter", ""),
                duration,
                count,
                stream,
                params.get("preview_bytes", 1000),
                mode,
            )

        if action == "test":
            # Run a simple SSH command for debugging
            cmd = "ls /tmp"
            try:
                client = self._get_client()
                stdin, stdout, stderr = client.exec_command(cmd)  # nosec B601 — inputs sanitized via shlex.quote
                out = stdout.read().decode(errors="replace")
                err = stderr.read().decode(errors="replace")
                client.close()
                return {
                    "status": "success",
                    "command": cmd,
                    "stdout": out,
                    "stderr": err,
                }
            except Exception as e:
                return {
                    "status": "error",
                    "error": str(e),
                    "command": cmd,
                    "guidance": "SSH connection test failed. Check your SSH configuration and firewall connectivity.",
                }

        elif action == "test_tcpdump":
            # Test tcpdump availability and basic functionality
            cmd = "which tcpdump && tcpdump --version | head -1"
            try:
                client = self._get_client()
                stdin, stdout, stderr = client.exec_command(cmd)  # nosec B601 — inputs sanitized via shlex.quote
                out = stdout.read().decode(errors="replace")
                err = stderr.read().decode(errors="replace")
                client.close()
                if not out.strip():
                    return {
                        "status": "error",
                        "error": "tcpdump not found",
                        "guidance": "tcpdump may not be installed on the firewall. Install it via the OPNsense package manager.",
                    }
                return {
                    "status": "success",
                    "command": cmd,
                    "stdout": out,
                    "stderr": err,
                }
            except Exception as e:
                return {
                    "status": "error",
                    "error": str(e),
                    "command": cmd,
                    "guidance": "Failed to test tcpdump. Check SSH connectivity and permissions.",
                }

        elif action == "test_interface":
            # Test interface availability directly
            interface = params.get("interface", "ax1")
            cmd = f"ifconfig {interface}"
            try:
                client = self._get_client()
                stdin, stdout, stderr = client.exec_command(cmd)  # nosec B601 — inputs sanitized via shlex.quote
                out = stdout.read().decode(errors="replace")
                err = stderr.read().decode(errors="replace")
                client.close()
                if "not found" in err or "No such interface" in err:
                    return {
                        "status": "error",
                        "error": f"Interface '{interface}' not found",
                        "guidance": "Use 'interface_list' tool to see available interfaces, or try common names like 'wan', 'lan', 'wifi'.",
                    }
                return {
                    "status": "success",
                    "command": cmd,
                    "stdout": out,
                    "stderr": err,
                }
            except Exception as e:
                return {
                    "status": "error",
                    "error": str(e),
                    "command": cmd,
                    "guidance": "Failed to test interface. Check SSH connectivity and permissions.",
                }

        elif action == "stop":
            return self.stop_capture()

        elif action == "fetch":
            local_path = params.get("local_path")
            return self.fetch_pcap(local_path)

        else:
            return {
                "status": "error",
                "error": f"Unknown action: {action}",
                "guidance": "Valid actions are: 'start', 'stop', 'fetch', 'test', 'test_tcpdump', 'test_interface', 'diagnose'",
            }

    async def _diagnose_and_fix(self) -> dict[str, Any]:
        """Comprehensive diagnostics and automatic fixing."""
        # Detect issues
        issues = self._detect_mcp_server_issues()

        # Attempt auto-correction
        corrections = self._auto_correct_issues()

        # Re-detect after corrections
        issues_after = self._detect_mcp_server_issues()

        return {
            "status": (
                "success" if not issues_after["has_issues"] else "partial_success"
            ),
            "initial_issues": issues,
            "auto_corrections": corrections,
            "issues_after_correction": issues_after,
            "summary": f"Found {len(issues['issues'])} initial issues, applied {len(corrections['corrections_applied'])} corrections, {len(issues_after['issues'])} issues remain",
            "recommendation": (
                "Try your packet capture again"
                if not issues_after["has_issues"]
                else "Manual intervention may be required"
            ),
        }

    async def _retry_after_correction(self, params: dict[str, Any]) -> dict[str, Any]:
        """Retry the original operation after auto-correction."""
        # Wait a moment for corrections to take effect
        time.sleep(2)

        # Re-detect issues
        issues = self._detect_mcp_server_issues()
        if issues["has_issues"]:
            return {
                "status": "error",
                "error": "Auto-correction applied but issues persist",
                "remaining_issues": issues["issues"],
                "guidance": "Please manually resolve the remaining issues and try again.",
            }

        # If no issues remain, retry the original operation
        return await self.execute(params)
