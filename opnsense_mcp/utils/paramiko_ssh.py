"""Shared Paramiko SSH host-key handling for OPNsense tools."""

from __future__ import annotations

import logging
import os

import paramiko

logger = logging.getLogger(__name__)

_TRUST_UNKNOWN_ENV = "OPNSENSE_SSH_TRUST_UNKNOWN_HOST_KEYS"


def apply_paramiko_host_key_policy(ssh_client: paramiko.SSHClient) -> None:
    """Load known host keys and set policy for unknown hosts.

    By default uses :class:`paramiko.RejectPolicy` after
    :meth:`paramiko.SSHClient.load_system_host_keys` — the firewall host must
    already appear in the user's ``~/.ssh/known_hosts`` (e.g. after one normal
    ``ssh user@firewall``). This matches standard OpenSSH ``StrictHostKeyChecking``.

    Set ``OPNSENSE_SSH_TRUST_UNKNOWN_HOST_KEYS=1`` to restore the previous
    behavior (auto-accept any host key). Use only when you understand the MITM
    risk (e.g. isolated lab).
    """
    ssh_client.load_system_host_keys()
    if os.getenv(_TRUST_UNKNOWN_ENV, "").strip().lower() in ("1", "true", "yes"):
        logger.warning(
            "%s is enabled: unknown SSH host keys will be accepted (MITM risk)",
            _TRUST_UNKNOWN_ENV,
        )
        # Opt-in legacy behavior only; see module docstring.
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # nosec B507
    else:
        ssh_client.set_missing_host_key_policy(paramiko.RejectPolicy())
