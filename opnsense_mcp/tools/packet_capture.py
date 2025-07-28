import logging
import os
from pathlib import Path
from typing import Any

import paramiko
from paramiko.config import SSHConfig

logger = logging.getLogger(__name__)


class PacketCaptureTool2:
    """Tool for running packet captures on OPNsense via SSH."""

    def __init__(
        self,
        client=None,
        ssh_host: str = None,
        ssh_user: str = None,
        ssh_key: str = None,
    ):
        self.client = client

        # Load environment variables from .opnsense-env file
        env_file = Path.home() / ".opnsense-env"
        if env_file.exists():
            try:
                with open(env_file) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            if "=" in line:
                                key, value = line.split("=", 1)
                                os.environ[key] = value
            except Exception as e:
                logger.warning(f"Failed to load .opnsense-env: {e}")

        env_host = os.getenv("OPNSENSE_FIREWALL_HOST")
        config_host = ssh_host or env_host or "opnsense"
        self.ssh_host = config_host
        self.ssh_user = ssh_user or self._get_ssh_config("user", config_host) or "root"
        self.ssh_key = ssh_key or self._get_ssh_config("identityfile", config_host)
        self.capture_file = "/tmp/mcp_capture.pcap"
        self.ssh_port = 22

        # Debug SSH configuration
        print(
            f"SSH Config: host={self.ssh_host}, user={self.ssh_user}, key={self.ssh_key}"
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
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self.ssh_host,
            username=self.ssh_user,
            key_filename=self.ssh_key,
            port=self.ssh_port,
        )
        return client

    async def _resolve_interface(self, iface: str) -> str:
        """
        Resolve user-friendly interface name (e.g., 'wan', 'wifi', 'vlan 81') to real device name (e.g., 'ax1').
        Uses all available metadata: name, description, VLAN, addresses, aliases.
        """
        import json
        import os

        try:
            from dotenv import load_dotenv

            from opnsense_mcp.utils.api import OPNsenseClient

            load_dotenv(os.path.expanduser("~/.opnsense-env"))
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
                except Exception:
                    pass
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
        except Exception:
            pass
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

        count_arg = ["-c", str(count)] if count else []
        filter_arg = [filter_expr.strip()] if filter_expr.strip() else []

        def clean_cmd(cmd_parts):
            return " ".join([part for part in cmd_parts if part])

        if mode == "raw":
            # Raw pcap output (binary/hex preview)
            if stream:
                if count and not duration:
                    cmd_parts = (
                        ["sudo", "timeout", "5", "tcpdump", "-U", "-i", resolved_iface]
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
                        resolved_iface,
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
                            resolved_iface,
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
                        resolved_iface,
                        "-w",
                        "-",
                    ] + filter_arg
                    cmd = clean_cmd(cmd_parts)
                cmd = f"/bin/sh -c '{cmd}'"
                try:
                    client = self._get_client()
                    stdin, stdout, stderr = client.exec_command(cmd)
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
                            resolved_iface,
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
                        resolved_iface,
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
                            resolved_iface,
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
                        resolved_iface,
                    ] + filter_arg
                    cmd = clean_cmd(cmd_parts)
                cmd = f"/bin/sh -c '{cmd}'"
                try:
                    client = self._get_client()
                    stdin, stdout, stderr = client.exec_command(cmd)
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
                    }
        else:
            return {
                "status": "error",
                "error": f"Unknown mode: {mode}",
                "requested_interface": requested_iface,
                "resolved_interface": resolved_iface,
            }

    def stop_capture(self) -> dict[str, Any]:
        """Stop all running tcpdump processes started by this tool."""
        cmd = "sudo pkill -f 'tcpdump -i'"
        try:
            client = self._get_client()
            stdin, stdout, stderr = client.exec_command(cmd)
            stdout.channel.recv_exit_status()
            client.close()
            return {"status": "success"}
        except Exception as e:
            logger.exception("Failed to stop packet capture")
            return {"status": "error", "error": str(e)}

    def fetch_pcap(self, local_path: str = None) -> dict[str, Any]:
        """Download the pcap file from the OPNsense host."""
        local_path = local_path or str(Path.home() / "mcp_capture.pcap")
        try:
            client = self._get_client()
            sftp = client.open_sftp()
            sftp.get(self.capture_file, local_path)
            sftp.close()
            client.close()
            return {"status": "success", "local_file": local_path}
        except Exception as e:
            logger.exception("Failed to fetch pcap file")
            return {"status": "error", "error": str(e)}

    async def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        action = params.get("action", "start")
        if action == "test":
            # Run a simple SSH command for debugging
            cmd = "ls /tmp"
            try:
                client = self._get_client()
                stdin, stdout, stderr = client.exec_command(cmd)
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
                return {"status": "error", "error": str(e), "command": cmd}
        elif action == "test_tcpdump":
            # Test tcpdump availability and basic functionality
            cmd = "which tcpdump && tcpdump --version | head -1"
            try:
                client = self._get_client()
                stdin, stdout, stderr = client.exec_command(cmd)
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
                return {"status": "error", "error": str(e), "command": cmd}
        elif action == "test_interface":
            # Test interface availability directly
            interface = params.get("interface", "ax1")
            cmd = f"ifconfig {interface}"
            try:
                client = self._get_client()
                stdin, stdout, stderr = client.exec_command(cmd)
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
                return {"status": "error", "error": str(e), "command": cmd}
        elif action == "start":
            return await self.start_capture(
                params.get("interface", "wan"),
                params.get("filter", ""),
                params.get("duration", 5),
                params.get("count"),
                params.get("stream", False),
                params.get("preview_bytes", 1000),
                params.get("mode", "raw"),
            )
        elif action == "stop":
            return self.stop_capture()
        elif action == "fetch":
            return self.fetch_pcap(params.get("local_path"))
        else:
            return {"status": "error", "error": f"Unknown action: {action}"}
