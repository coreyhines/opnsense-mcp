"""Host-key checking must accept the entry a normal `ssh` actually writes.

Issue #20. `ssh_client.py` resolves the firewall hostname and hands paramiko
the resolved IP, and paramiko keys its known_hosts lookup on exactly that
string, so it checked `192.0.2.1` and never `fw.example`.

`paramiko_ssh.py` documented the remedy as "the firewall host must already
appear in the user's ~/.ssh/known_hosts (e.g. after one normal `ssh
user@firewall`)". But OpenSSH's `CheckHostIP` defaults to no, so a normal
`ssh user@fw.example` records only the hostname. Following the documented
remedy still left RejectPolicy refusing the connection. It happened to work
on a machine whose known_hosts held the IP from historical connections.

Resolving to an IP is deliberate -- it stops an unreachable-IPv6-first
hostname burning the whole timeout -- so the fix keeps that and widens the
host-key lookup instead.
"""

from __future__ import annotations

import paramiko
import pytest

HOSTNAME = "fw.example"
RESOLVED_IP = "192.0.2.1"


@pytest.fixture
def host_key() -> paramiko.PKey:
    """A stable key standing in for the firewall's host key."""
    return paramiko.RSAKey.generate(2048)


def _client_with_known_hosts(entries: dict[str, paramiko.PKey]) -> paramiko.SSHClient:
    """An SSHClient whose loaded host keys are exactly `entries`."""
    client = paramiko.SSHClient()
    for name, key in entries.items():
        client.get_host_keys().add(name, key.get_name(), key)
    return client


def test_a_hostname_only_known_hosts_entry_is_accepted(host_key: paramiko.PKey) -> None:
    """What `ssh user@fw.example` actually writes must be enough."""
    from opnsense_mcp.utils.paramiko_ssh import HostnameOrAddressPolicy

    client = _client_with_known_hosts({HOSTNAME: host_key})
    policy = HostnameOrAddressPolicy([HOSTNAME])

    # Connecting to the resolved IP: paramiko finds no entry for it and asks
    # the policy, which checks the hostname the IP was resolved from.
    policy.missing_host_key(client, RESOLVED_IP, host_key)


def test_an_unknown_host_is_still_rejected(host_key: paramiko.PKey) -> None:
    """Widening the lookup must not turn RejectPolicy into AutoAdd."""
    from opnsense_mcp.utils.paramiko_ssh import HostnameOrAddressPolicy

    client = _client_with_known_hosts({})
    policy = HostnameOrAddressPolicy([HOSTNAME])

    with pytest.raises(paramiko.SSHException):
        policy.missing_host_key(client, RESOLVED_IP, host_key)


def test_a_known_hostname_presenting_a_different_key_is_rejected(
    host_key: paramiko.PKey,
) -> None:
    """The falsification: being listed is not enough, the key must match.

    A policy that accepted any key for a listed hostname would be an
    AutoAddPolicy wearing a checked name, and would pass every other test here.
    """
    from opnsense_mcp.utils.paramiko_ssh import HostnameOrAddressPolicy

    impostor = paramiko.RSAKey.generate(2048)
    client = _client_with_known_hosts({HOSTNAME: host_key})
    policy = HostnameOrAddressPolicy([HOSTNAME])

    with pytest.raises(paramiko.SSHException):
        policy.missing_host_key(client, RESOLVED_IP, impostor)


def test_a_different_key_type_for_a_known_host_is_rejected(
    host_key: paramiko.PKey,
) -> None:
    """A matching name and a key of another type is not a match."""
    from opnsense_mcp.utils.paramiko_ssh import HostnameOrAddressPolicy

    other_type = paramiko.ECDSAKey.generate()
    client = _client_with_known_hosts({HOSTNAME: host_key})
    policy = HostnameOrAddressPolicy([HOSTNAME])

    with pytest.raises(paramiko.SSHException):
        policy.missing_host_key(client, RESOLVED_IP, other_type)


def test_an_ip_only_known_hosts_entry_still_works(host_key: paramiko.PKey) -> None:
    """No regression for a machine whose known_hosts holds the IP.

    Paramiko resolves this before the policy is consulted, so this asserts the
    entry is found by the normal lookup rather than by the widened one.
    """
    client = _client_with_known_hosts({RESOLVED_IP: host_key})

    entry = client.get_host_keys().lookup(RESOLVED_IP)

    assert entry is not None
    assert entry[host_key.get_name()] == host_key


def test_the_connect_path_passes_the_hostname_as_an_alternate() -> None:
    """The policy is only useful if get_ssh_client actually wires it up."""
    from unittest.mock import MagicMock, patch

    from opnsense_mcp.utils.paramiko_ssh import HostnameOrAddressPolicy
    from opnsense_mcp.utils.ssh_client import OPNsenseSSHClient

    ssh = OPNsenseSSHClient.__new__(OPNsenseSSHClient)
    ssh.ssh_host = HOSTNAME
    ssh.ssh_user = "corey"
    ssh.ssh_key = "/dev/null"
    ssh.ssh_port = 22
    ssh.address_family = "any"
    ssh.connect_timeout = 5

    fake_client = MagicMock()
    with (
        patch(
            "opnsense_mcp.utils.ssh_client._resolve_host_ip", return_value=RESOLVED_IP
        ),
        patch("paramiko.SSHClient", return_value=fake_client),
    ):
        ssh.get_ssh_client()

    policy = fake_client.set_missing_host_key_policy.call_args[0][0]
    assert isinstance(policy, HostnameOrAddressPolicy)
    assert HOSTNAME in policy.alternates
    # Still connects to the resolved IP, so the IPv6 timeout fix survives.
    assert fake_client.connect.call_args.kwargs["hostname"] == RESOLVED_IP


PORT = 2222


def test_a_non_default_port_entry_is_accepted(host_key: paramiko.PKey) -> None:
    """`ssh -p 2222 fw.example` records `[fw.example]:2222`; paramiko asks for
    `[192.0.2.1]:2222`. The bare-hostname alternate never matched that."""
    from opnsense_mcp.utils.paramiko_ssh import HostnameOrAddressPolicy
    from opnsense_mcp.utils.ssh_client import known_hosts_names

    client = _client_with_known_hosts({f"[{HOSTNAME}]:{PORT}": host_key})
    policy = HostnameOrAddressPolicy(known_hosts_names(HOSTNAME, PORT))

    policy.missing_host_key(client, f"[{RESOLVED_IP}]:{PORT}", host_key)


def test_a_non_default_port_entry_with_the_wrong_key_is_rejected(
    host_key: paramiko.PKey,
) -> None:
    """The port-qualified alternate must still compare the key."""
    from opnsense_mcp.utils.paramiko_ssh import HostnameOrAddressPolicy
    from opnsense_mcp.utils.ssh_client import known_hosts_names

    other = paramiko.RSAKey.generate(2048)
    client = _client_with_known_hosts({f"[{HOSTNAME}]:{PORT}": other})
    policy = HostnameOrAddressPolicy(known_hosts_names(HOSTNAME, PORT))

    with pytest.raises(paramiko.SSHException):
        policy.missing_host_key(client, f"[{RESOLVED_IP}]:{PORT}", host_key)


def test_port_22_adds_no_bracketed_name() -> None:
    """OpenSSH files port-22 hosts under the bare name only."""
    from opnsense_mcp.utils.ssh_client import known_hosts_names

    assert known_hosts_names(HOSTNAME, 22) == [HOSTNAME]


def test_the_client_passes_the_port_qualified_name() -> None:
    """Pin the call site: the helper is useless if connect() ignores it."""
    from unittest.mock import MagicMock, patch

    from opnsense_mcp.utils.ssh_client import OPNsenseSSHClient

    ssh = OPNsenseSSHClient.__new__(OPNsenseSSHClient)
    ssh.ssh_host, ssh.ssh_port, ssh.address_family = HOSTNAME, PORT, "any"
    ssh.ssh_user, ssh.ssh_key, ssh.connect_timeout = "root", None, 1
    with (
        patch(
            "opnsense_mcp.utils.ssh_client._resolve_host_ip", return_value=RESOLVED_IP
        ),
        patch("opnsense_mcp.utils.ssh_client.paramiko.SSHClient", MagicMock()),
        patch(
            "opnsense_mcp.utils.ssh_client.apply_paramiko_host_key_policy"
        ) as apply_policy,
    ):
        ssh.get_ssh_client()

    assert f"[{HOSTNAME}]:{PORT}" in apply_policy.call_args.kwargs["alternates"]
