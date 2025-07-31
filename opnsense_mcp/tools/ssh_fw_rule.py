"""SSH-based firewall rule management tool for OPNsense."""

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any

import paramiko
from paramiko.config import SSHConfig

logger = logging.getLogger(__name__)


class SSHFirewallRuleTool:
    """Tool for creating firewall rules on OPNsense via SSH."""

    name = "ssh_fw_rule"
    description = "Create firewall rules via SSH (bypasses API issues)"
    input_schema = {
        "type": "object",
        "properties": {
            "description": {"type": "string"},
            "interface": {"type": "string", "default": "lan"},
            "action": {"type": "string", "default": "block"},
            "protocol": {"type": "string", "default": "any"},
            "source_net": {"type": "string", "default": "any"},
            "source_port": {"type": "string", "default": "any"},
            "destination_net": {"type": "string", "default": "any"},
            "destination_port": {"type": "string", "default": "any"},
            "direction": {"type": "string", "default": "in"},
            "ipprotocol": {"type": "string", "default": "inet"},
            "enabled": {"type": "boolean", "default": True},
            "apply": {"type": "boolean", "default": True},
        },
        "required": ["description"],
    }

    def __init__(self, client: Any) -> None:
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

        # Get SSH configuration exactly like packet capture tool
        env_host = os.getenv("OPNSENSE_FIREWALL_HOST")
        config_host = env_host or "opnsense"
        self.ssh_host = config_host
        self.ssh_user = self._get_ssh_config("user", config_host) or "root"
        self.ssh_key = self._get_ssh_config("identityfile", config_host)
        self.ssh_port = 22

        logger.info(
            f"SSH Config: host={self.ssh_host}, user={self.ssh_user}, key={self.ssh_key}"
        )

    def _get_ssh_config(self, key: str, config_host: str) -> str | None:
        ssh_config_path = os.path.expanduser("~/.ssh/config")
        if not os.path.exists(ssh_config_path):
            return None
        try:
            with open(ssh_config_path) as f:
                config = SSHConfig()
                config.parse(f)
                host = config.lookup(config_host)
                return host.get(key)
        except Exception as e:
            logger.warning(f"Failed to read SSH config: {e}")
            return None

    def _get_ssh_client(self) -> paramiko.SSHClient:
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

    def _execute_ssh_command(self, command: str) -> dict[str, Any]:
        ssh = None
        try:
            ssh = self._get_ssh_client()
            stdin, stdout, stderr = ssh.exec_command(command)
            exit_code = stdout.channel.recv_exit_status()
            stdout_output = stdout.read().decode().strip()
            stderr_output = stderr.read().decode().strip()
            return {
                "exit_code": exit_code,
                "stdout": stdout_output,
                "stderr": stderr_output,
                "success": exit_code == 0,
            }
        except Exception as e:
            logger.error(f"SSH command execution failed: {e}")
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e),
                "success": False,
            }
        finally:
            if ssh:
                ssh.close()

    async def execute(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Create a new firewall rule via SSH and optionally apply changes.

        Args:
            params: Rule creation parameters including description, interface, etc.

        Returns:
            Dictionary containing rule creation results.

        """
        if params is None:
            params = {}

        try:
            # Extract rule parameters
            description = params.get("description", "SSH Created Rule")
            interface = params.get("interface", "lan")
            action = params.get("action", "block")
            protocol = params.get("protocol", "any")
            source_net = params.get("source_net", "any")
            source_port = params.get("source_port", "any")
            destination_net = params.get("destination_net", "any")
            destination_port = params.get("destination_port", "any")
            direction = params.get("direction", "in")
            ipprotocol = params.get("ipprotocol", "inet")
            enabled = params.get("enabled", True)
            apply_changes = params.get("apply", True)

            # Create the firewall rule using SSH
            result = await self._create_rule_via_ssh(
                description=description,
                interface=interface,
                action=action,
                protocol=protocol,
                source_net=source_net,
                source_port=source_port,
                destination_net=destination_net,
                destination_port=destination_port,
                direction=direction,
                ipprotocol=ipprotocol,
                enabled=enabled,
                apply_changes=apply_changes,
            )

        except Exception as e:
            logger.exception("Failed to create firewall rule via SSH")
            return {"status": "error", "error": str(e)}

    def _build_pf_rule_command(self, **rule_params: Any) -> str:
        """
        Build an OPNsense firewall rule command using the OPNsense CLI.

        Args:
            **rule_params: Rule parameters.

        Returns:
            OPNsense firewall rule command string.

        """
        # Extract parameters
        description = rule_params.get("description", "SSH Rule")
        interface = rule_params.get("interface", "lan")
        action = rule_params.get("action", "block")
        protocol = rule_params.get("protocol", "any")
        source_net = rule_params.get("source_net", "any")
        destination_net = rule_params.get("destination_net", "any")
        direction = rule_params.get("direction", "in")

        # Use OPNsense's firewall rule management
        # First, let's try using the OPNsense firewall rule CLI
        cmd = "opnsense-shell firewall rule add"
        cmd += f" --interface {interface}"
        cmd += f" --action {action}"
        cmd += f" --direction {direction}"

        if protocol != "any":
            cmd += f" --protocol {protocol}"

        if source_net != "any":
            cmd += f" --source {source_net}"

        if destination_net != "any":
            cmd += f" --destination {destination_net}"

        cmd += f" --description '{description}'"

        return cmd

    async def _create_rule_via_ssh(self, **rule_params: Any) -> dict[str, Any]:
        """
        Create a firewall rule via SSH.

        Args:
            **rule_params: Rule parameters.

        Returns:
            Result dictionary.

        """
        try:
            rule_cmd = self._build_pf_rule_command(**rule_params)
            logger.info(f"Creating firewall rule via SSH: {rule_cmd}")

            result = self._execute_ssh_command(rule_cmd)
            if not result["success"]:
                return {
                    "status": "error",
                    "error": f"SSH command failed (exit code {result['exit_code']}): {result['stderr']}",
                }

            if rule_params.get("apply", True):
                reload_cmd = "opnsense-shell firewall reload"
                reload_result = self._execute_ssh_command(reload_cmd)
                if not reload_result["success"]:
                    return {
                        "status": "warning",
                        "message": f"Rule created but firewall reload failed: {reload_result['stderr']}",
                        "rule_params": rule_params,
                    }

            return {
                "status": "success",
                "message": "Firewall rule created successfully via SSH",
                "rule_params": rule_params,
                "applied": rule_params.get("apply", True),
            }
        except Exception as e:
            logger.exception("SSH firewall rule creation failed")
            return {"status": "error", "error": f"SSH error: {str(e)}"}
