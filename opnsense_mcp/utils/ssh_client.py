"""Common SSH client utility for OPNsense tools."""

import logging
import os
from pathlib import Path
from typing import Any

import paramiko
from paramiko.config import SSHConfig

logger = logging.getLogger(__name__)


class OPNsenseSSHClient:
    """Common SSH client for OPNsense tools."""

    def __init__(self, client=None):
        """
        Initialize SSH client with configuration from environment and SSH config.

        Args:
            client: OPNsense client instance (optional, for compatibility)
        """
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

        # Debug SSH configuration
        logger.info(
            f"SSH Config: host={self.ssh_host}, user={self.ssh_user}, key={self.ssh_key}"
        )

    def _get_ssh_config(self, key: str, config_host: str) -> str | None:
        """Get SSH configuration from ~/.ssh/config file."""
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

    def get_ssh_client(self) -> paramiko.SSHClient:
        """
        Get a configured SSH client exactly like packet capture tool.

        Returns:
            Configured paramiko SSH client.

        Raises:
            Exception: If SSH connection fails.
        """
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

    def execute_command(self, command: str) -> dict[str, Any]:
        """
        Execute a command via SSH.

        Args:
            command: Command to execute.

        Returns:
            Dictionary with command results.
        """
        ssh = None
        try:
            ssh = self.get_ssh_client()
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

    def get_config(self) -> dict[str, Any]:
        """Get SSH configuration for debugging."""
        return {
            "host": self.ssh_host,
            "user": self.ssh_user,
            "key": self.ssh_key,
            "port": self.ssh_port,
        }
