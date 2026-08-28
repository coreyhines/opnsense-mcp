"""Shared Paramiko SSH host-key handling for OPNsense tools."""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

import paramiko

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = logging.getLogger(__name__)

_TRUST_UNKNOWN_ENV = "OPNSENSE_SSH_TRUST_UNKNOWN_HOST_KEYS"


class HostnameOrAddressPolicy(paramiko.MissingHostKeyPolicy):
    """Reject unknown hosts, but look the key up under alternate names first.

    `ssh_client.py` resolves the firewall hostname itself and connects to the
    resolved IP, because a hostname whose IPv6 addresses are unreachable
    otherwise burns the whole connect timeout. Paramiko keys its known_hosts
    lookup on whatever string it was given, so that made the check ask about
    the IP and never about the hostname.

    OpenSSH's `CheckHostIP` defaults to no, so a normal `ssh user@firewall`
    records only the hostname. The documented remedy therefore did not work:
    doing exactly what it said still left `RejectPolicy` refusing the
    connection. It appeared to work only on machines whose known_hosts held
    the IP from historical connections.

    This checks the alternate names before refusing, so an entry written by
    either convention is accepted. The key itself must still match; a listed
    name presenting an unknown key is refused as before.
    """

    def __init__(self, alternates: Iterable[str]) -> None:
        """Store the alternate names to try, e.g. the pre-resolution hostname."""
        self.alternates = [name for name in alternates if name]

    def missing_host_key(
        self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey
    ) -> None:
        """Accept only when an alternate name holds this exact key."""
        host_keys = client.get_host_keys()
        for name in self.alternates:
            if name == hostname:
                continue
            entry = host_keys.lookup(name)
            if entry is None:
                continue
            known = entry.get(key.get_name())
            if known is not None and known == key:
                logger.debug(
                    "Host key for %s matched the known_hosts entry for %s",
                    hostname,
                    name,
                )
                return

        msg = (
            f"Server {hostname!r} not found in known_hosts "
            f"(also tried {', '.join(self.alternates) or 'no alternates'}). "
            f"Add the host with `ssh-keyscan` or connect once with `ssh`."
        )
        raise paramiko.SSHException(msg)


def apply_paramiko_host_key_policy(
    ssh_client: paramiko.SSHClient,
    alternates: Iterable[str] = (),
) -> None:
    """Load known host keys and set policy for unknown hosts.

    By default uses :class:`HostnameOrAddressPolicy` after
    :meth:`paramiko.SSHClient.load_system_host_keys`, which refuses a host
    absent from the user's ``~/.ssh/known_hosts`` exactly as OpenSSH's
    ``StrictHostKeyChecking`` does, but accepts an entry recorded under any of
    ``alternates`` -- the hostname, when the connection is made to an address
    resolved from it.

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
        ssh_client.set_missing_host_key_policy(HostnameOrAddressPolicy(alternates))
