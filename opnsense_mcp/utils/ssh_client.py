"""Common SSH client utility for OPNsense tools."""

import logging
import os
import socket
from pathlib import Path
from typing import Any

import paramiko
from paramiko.config import SSHConfig

from opnsense_mcp.utils.env import load_opnsense_env
from opnsense_mcp.utils.paramiko_ssh import apply_paramiko_host_key_policy

logger = logging.getLogger(__name__)

_VALID_ADDRESS_FAMILIES = {"inet", "inet6", "any"}


def _parse_positive_int(name: str, default: int) -> int:
    """Parse a positive integer from an environment variable."""
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        v = int(raw)
        return v if v > 0 else default
    except ValueError:
        return default


def _fix_public_key_path(key_path: str) -> str:
    """If the user accidentally points at a .pub file, use the private key instead."""
    if not key_path.endswith(".pub"):
        return key_path
    private_path = key_path[:-4]
    if Path(private_path).is_file():
        logger.warning(
            "OPNSENSE_SSH_KEY points to public key %s; using private key %s instead",
            key_path,
            private_path,
        )
        return private_path
    return key_path


def _resolve_host_ip(hostname: str, port: int, address_family: str) -> str:
    """Resolve hostname to a routable IP, respecting address-family preference.

    Paramiko's ``SSHClient.connect`` passes the hostname straight to
    ``socket.create_connection`` which calls ``getaddrinfo`` and tries
    addresses in order.  When the hostname resolves to many IPv6 addresses
    (most unreachable) before a reachable IPv4 address, the connection
    attempt burns the entire timeout on the first unreachable IPv6 address.

    This helper resolves the hostname ourselves and returns a single IP so
    paramiko connects immediately to a reachable address.
    """
    if address_family == "inet":
        af = socket.AF_INET
    elif address_family == "inet6":
        af = socket.AF_INET6
    else:
        af = socket.AF_UNSPEC

    try:
        results = socket.getaddrinfo(hostname, port, af, socket.SOCK_STREAM)
    except socket.gaierror:
        return hostname

    if not results:
        return hostname

    if af != socket.AF_UNSPEC:
        return results[0][4][0]

    # "any" — prefer IPv4 to avoid unreachable-IPv6-first problem
    ipv4 = [r for r in results if r[0] == socket.AF_INET]
    if ipv4:
        return ipv4[0][4][0]
    return results[0][4][0]


class OPNsenseSSHClient:
    """Common SSH client for OPNsense tools."""

    def __init__(
        self,
        client: Any = None,
        *,
        ssh_host: str | None = None,
        ssh_user: str | None = None,
        ssh_key: str | None = None,
    ) -> None:
        """
        Initialize SSH client with configuration from environment and SSH config.

        Args:
            client: OPNsense client instance (optional, for compatibility)
            ssh_host: Override hostname (else OPNSENSE_SSH_HOST / OPNSENSE_FIREWALL_HOST)
            ssh_user: Override username (else OPNSENSE_SSH_USER / ~/.ssh/config / $USER)
            ssh_key: Override path to private key (else OPNSENSE_SSH_KEY / IdentityFile)
        """
        self.client = client

        load_opnsense_env()

        env_ssh_host = os.getenv("OPNSENSE_SSH_HOST")
        env_host = os.getenv("OPNSENSE_FIREWALL_HOST")
        config_host = ssh_host or env_ssh_host or env_host or "opnsense"
        self.ssh_host = config_host
        self.ssh_user = (
            ssh_user
            or os.getenv("OPNSENSE_SSH_USER")
            or self._get_ssh_config("user", config_host)
            or os.getenv("USER")
            or "root"
        )
        raw_key = (
            ssh_key
            or os.getenv("OPNSENSE_SSH_KEY")
            or self._get_ssh_config("identityfile", config_host)
        )
        expanded = os.path.expanduser(raw_key) if raw_key else None
        self.ssh_key = _fix_public_key_path(expanded) if expanded else None
        self.ssh_port = _parse_positive_int("OPNSENSE_SSH_PORT", 22)
        self.connect_timeout = _parse_positive_int("OPNSENSE_SSH_TIMEOUT", 15)

        af_raw = os.getenv("OPNSENSE_SSH_ADDRESS_FAMILY", "inet").strip().lower()
        self.address_family = af_raw if af_raw in _VALID_ADDRESS_FAMILIES else "inet"

        logger.info(
            "SSH Config: host=%s, user=%s, key=%s, port=%s, timeout=%ss, af=%s",
            self.ssh_host,
            self.ssh_user,
            self.ssh_key,
            self.ssh_port,
            self.connect_timeout,
            self.address_family,
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
        except OSError as e:
            logger.warning("Failed to read SSH config: %s", e)
            return None

    def get_ssh_client(self) -> paramiko.SSHClient:
        """
        Get a configured Paramiko SSH client.

        Returns:
            Configured paramiko SSH client.

        Raises:
            Exception: If SSH connection fails.
        """
        resolved_ip = _resolve_host_ip(
            self.ssh_host, self.ssh_port, self.address_family
        )
        if resolved_ip != self.ssh_host:
            logger.info(
                "Resolved %s -> %s (address_family=%s)",
                self.ssh_host,
                resolved_ip,
                self.address_family,
            )

        client = paramiko.SSHClient()
        apply_paramiko_host_key_policy(client)
        client.connect(
            hostname=resolved_ip,
            username=self.ssh_user,
            key_filename=self.ssh_key,
            port=self.ssh_port,
            timeout=self.connect_timeout,
            banner_timeout=self.connect_timeout,
            auth_timeout=self.connect_timeout,
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
            stdin, stdout, stderr = ssh.exec_command(
                command
            )  # nosec B601 — general-purpose SSH executor, callers responsible for sanitization
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
            logger.error("SSH command execution failed: %s", e)
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
            "timeout": self.connect_timeout,
            "address_family": self.address_family,
        }
