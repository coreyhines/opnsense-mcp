"""Probe the runtime paths a deployed server actually has.

The repo's example quadlet has set ``OPNSENSE_BACKUP_DIR`` for some time.
The unit installed on the container host had not, so ``config_backup
action=download`` failed there with "OPNSENSE_BACKUP_DIR is not set" while
every repo test stayed green: ``tests/test_deploy_runtime_paths.py`` read the
example file, and a check that inspects the intended config instead of the
running system is not a check (defect D2a, issue #21). The SSH key directory
is the same shape — an uncreated bind source mounts empty and does not fail
(issue #20).

No repo test can see a deployment. A running server can see itself. This
module is what lets the ``system`` tool answer "do my paths work?" without
attempting a download and reading the error.

Layout, deliberately split so the decision is testable without a filesystem:

* :func:`judge_runtime_paths` — the decision function. Pure: it judges a
  mapping of role -> configured path plus the facts the caller passes in
  (exists / is a directory / is writable). No environment access, no
  filesystem access.
* :func:`collect_observations` — the thin I/O helper. Reads the environment,
  stats each configured path, and produces exactly those facts.
* :func:`runtime_paths_report` — composes the two, for the ``system`` tool.

Verdicts carry a machine-readable reason code, not prose to assert on. "Not
configured" and "configured but broken" are different codes because they
have different fixes; collapsing them is how D2a stayed invisible.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping


class Reason(StrEnum):
    """Machine-readable verdict codes. The contract callers assert on."""

    OK = "ok"
    NOT_CONFIGURED = "not_configured"
    MISSING = "missing"
    NOT_A_DIRECTORY = "not_a_directory"
    NOT_WRITABLE = "not_writable"
    KEY_MISSING = "key_missing"
    KNOWN_HOSTS_MISSING = "known_hosts_missing"
    HOST_NOT_KNOWN = "host_not_known"


BACKUP_DIR = "backup_dir"
SSH_KEY_DIR = "ssh_key_dir"


@dataclass(frozen=True)
class RoleSpec:
    """What one runtime path role needs, and where its path is configured."""

    env_var: str
    description: str
    # A backup directory is written to; a key directory is only read (the
    # quadlet mounts /root/.ssh read-only on purpose), so demanding
    # writability there would report a defect on every healthy deploy.
    requires_writable: bool
    # The env var names a file and the role is the directory holding it.
    directory_of_value: bool


ROLES: dict[str, RoleSpec] = {
    BACKUP_DIR: RoleSpec(
        env_var="OPNSENSE_BACKUP_DIR",
        description="where config_backup action=download writes",
        requires_writable=True,
        directory_of_value=False,
    ),
    SSH_KEY_DIR: RoleSpec(
        env_var="OPNSENSE_SSH_KEY",
        description="directory holding the private key the SSH-backed tools read",
        requires_writable=False,
        directory_of_value=True,
    ),
}


@dataclass(frozen=True)
class PathObservation:
    """One role's configured path plus the filesystem facts about it.

    ``configured_path`` is the path the role acts on, already resolved: for
    the ssh key directory it is the directory holding the key, not the key.
    Facts only — judging is :func:`judge_runtime_paths`'s job, so a caller can
    construct these by hand and test the decision without a filesystem.
    """

    configured_path: str | None
    exists: bool = False
    is_dir: bool = False
    writable: bool = False
    # SSH role only; None means "not checked". The directory existing says
    # nothing about its contents: an empty bind mount is a directory.
    key_readable: bool | None = None
    known_hosts_present: bool | None = None
    host_known: bool | None = None


@dataclass(frozen=True)
class PathVerdict:
    """One role's verdict. ``reason`` is the machine-readable code."""

    role: str
    env_var: str
    configured_path: str | None
    reason: Reason

    @property
    def ok(self) -> bool:
        """True only for a fully working path."""
        return self.reason is Reason.OK

    def as_dict(self) -> dict[str, str | bool | None]:
        """JSON-ready form, as the ``system`` tool reports it.

        ``reason`` and ``ok`` are what callers assert on. ``remedy`` is
        operator prose keyed off the code — never a contract.
        """
        return {
            "role": self.role,
            "description": ROLES[self.role].description,
            "env_var": self.env_var,
            "configured_path": self.configured_path,
            "reason": self.reason.value,
            "ok": self.ok,
            "remedy": _REMEDIES[self.reason],
        }


_REMEDIES: dict[Reason, str] = {
    Reason.OK: "",
    Reason.NOT_CONFIGURED: (
        "set the variable in the container unit; "
        "deploy/opnsense-mcp-app.container.example shows the shape"
    ),
    Reason.MISSING: (
        "create the directory on the host and mount it: a missing bind "
        "source mounts empty instead of failing the deploy"
    ),
    Reason.NOT_A_DIRECTORY: (
        "the configured path is not a directory; repoint the variable"
    ),
    Reason.NOT_WRITABLE: (
        "give this directory a rw mount; the install root is mounted ro"
    ),
    Reason.KEY_MISSING: (
        "the directory exists but holds no readable private key; an empty "
        "bind mount looks exactly like this. Copy the key in"
    ),
    Reason.KNOWN_HOSTS_MISSING: (
        "no ~/.ssh/known_hosts, so every host key is refused; record the "
        "firewall's key with one ssh to it"
    ),
    Reason.HOST_NOT_KNOWN: (
        "known_hosts has no entry for the configured SSH host (as host, or "
        "[host]:port off port 22); record it with one ssh to it"
    ),
}


def judge_runtime_paths(
    observations: Mapping[str, PathObservation],
) -> dict[str, PathVerdict]:
    """Judge every role's path purely from the facts passed in.

    No I/O: the caller supplies the configured path and whether it exists /
    is a directory / is writable, so this is testable without any of those
    existing. Unknown roles raise ``KeyError`` — a typo in a role name is a
    programming error, not a deployment finding.

    Args:
        observations: role name -> the path configured for it and the facts
            about it. Roles come from :data:`ROLES`.

    Returns:
        One verdict per role given, keyed by role name.

    """
    return {role: _judge_one(role, obs) for role, obs in observations.items()}


def _judge_one(role: str, observation: PathObservation) -> PathVerdict:
    """One role through the verdict ladder, most specific failure first.

    The order is the contract: an unset variable is never reported as a
    broken path, and a missing path is never reported as a permission
    problem — those have different fixes.
    """
    spec = ROLES[role]
    path = observation.configured_path
    if path is None or not path.strip():
        return PathVerdict(role, spec.env_var, None, Reason.NOT_CONFIGURED)
    if not observation.exists:
        return PathVerdict(role, spec.env_var, path, Reason.MISSING)
    if not observation.is_dir:
        return PathVerdict(role, spec.env_var, path, Reason.NOT_A_DIRECTORY)
    if spec.requires_writable and not observation.writable:
        return PathVerdict(role, spec.env_var, path, Reason.NOT_WRITABLE)
    if observation.key_readable is False:
        return PathVerdict(role, spec.env_var, path, Reason.KEY_MISSING)
    if observation.known_hosts_present is False:
        return PathVerdict(role, spec.env_var, path, Reason.KNOWN_HOSTS_MISSING)
    if observation.host_known is False:
        return PathVerdict(role, spec.env_var, path, Reason.HOST_NOT_KNOWN)
    return PathVerdict(role, spec.env_var, path, Reason.OK)


def collect_observations(
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> dict[str, PathObservation]:
    """Read the environment and stat every configured path.

    The only I/O in this module, kept separate from the decision function so
    that the decision is testable without a filesystem.

    Args:
        environ: where to read the role variables from. Defaults to
            ``os.environ``; tests pass a plain mapping instead of patching
            the world.
        home: the home directory paramiko reads ``~/.ssh`` from. Defaults to
            ``Path.home()``.

    Returns:
        One :class:`PathObservation` per role in :data:`ROLES`.

    """
    env = os.environ if environ is None else environ
    home = Path.home() if home is None else home
    observations: dict[str, PathObservation] = {}
    for role, spec in ROLES.items():
        raw = (env.get(spec.env_var) or "").strip()
        if role == SSH_KEY_DIR:
            observations[role] = _observe_ssh(env, raw, home)
            continue
        path = _resolve_role_path(spec, raw)
        if path is None:
            observations[role] = PathObservation(configured_path=None)
        else:
            observations[role] = _observe_path(path)
    return observations


# What paramiko tries when no key_filename is given.
DEFAULT_KEY_NAMES = ("id_rsa", "id_ecdsa", "id_ed25519", "id_dsa")


def _observe_ssh(env: Mapping[str, str], raw: str, home: Path) -> PathObservation:
    """Facts about the SSH role: the key file itself, not only its directory.

    Judging the directory alone reported an empty bind mount as healthy.
    With ``OPNSENSE_SSH_KEY`` unset, paramiko falls back to the default key
    names in ``~/.ssh``, so that is what is checked rather than reporting
    not-configured for a setup that works.
    """
    if raw:
        try:
            key = Path(raw).expanduser()
        except RuntimeError:
            key = Path(raw)
        keys = [key]
        directory = key.parent
    else:
        directory = home / ".ssh"
        keys = [directory / name for name in DEFAULT_KEY_NAMES]
        if not any(k.exists() for k in keys):
            return PathObservation(configured_path=None)

    base = _observe_path(str(directory))
    if not base.is_dir:
        return base
    known_hosts = home / ".ssh" / "known_hosts"
    present = known_hosts.is_file() and os.access(known_hosts, os.R_OK)
    host = (
        env.get("OPNSENSE_SSH_HOST") or env.get("OPNSENSE_FIREWALL_HOST") or ""
    ).strip()
    return PathObservation(
        configured_path=base.configured_path,
        exists=base.exists,
        is_dir=base.is_dir,
        writable=base.writable,
        key_readable=any(k.is_file() and os.access(k, os.R_OK) for k in keys),
        known_hosts_present=present,
        host_known=(
            _known_hosts_names(known_hosts, host, env.get("OPNSENSE_SSH_PORT"))
            if present and host
            else None
        ),
    )


def _known_hosts_names(known_hosts: Path, host: str, port: str | None) -> bool:
    """Whether known_hosts has an entry for the host, port-qualified off 22."""
    import paramiko

    try:
        keys = paramiko.HostKeys(str(known_hosts))
    except (OSError, paramiko.SSHException):
        return False
    try:
        port_n = int(port) if port and port.strip() else 22
    except ValueError:
        port_n = 22
    names = [host] if port_n == 22 else [f"[{host}]:{port_n}", host]
    return any(keys.lookup(name) is not None for name in names)


def _resolve_role_path(spec: RoleSpec, raw: str) -> str | None:
    """The path this role acts on, or None when nothing configured it.

    ``~`` forms are expanded the way the consumers expand them
    (``config_backup`` and ``ssh_client`` both do). The ssh key role checks
    the directory the key lives in, because that directory is what the
    quadlet mounts and what an empty bind source leaves broken.
    """
    if not raw:
        return None
    try:
        expanded = Path(raw).expanduser()
    except RuntimeError:
        # ``~user`` for a user the host does not know. A malformed value
        # must never crash the probe; the unresolved path will not exist,
        # which is its own verdict.
        expanded = Path(raw)
    if spec.directory_of_value:
        expanded = expanded.parent
    return str(expanded)


def _observe_path(path: str) -> PathObservation:
    """Gather plain facts about one path. ``os.access`` because pathlib has
    no writability check, and a probe file would be a side effect."""
    p = Path(path)
    exists = p.exists()
    is_dir = exists and p.is_dir()
    writable = is_dir and os.access(p, os.W_OK)
    return PathObservation(
        configured_path=path, exists=exists, is_dir=is_dir, writable=writable
    )


def runtime_paths_report(
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> dict[str, dict[str, str | bool | None]]:
    """Each role's configured path and verdict, as the ``system`` tool reports.

    A broken path is a finding to report, never an exception to raise: the
    caller reads ``reason`` and decides. Assert on the codes and on ``ok``,
    never on the wording of ``remedy``.

    Args:
        environ: passed straight through to :func:`collect_observations`.
        home: likewise.

    Returns:
        role name -> the JSON-ready verdict from :meth:`PathVerdict.as_dict`.

    """
    return {
        role: verdict.as_dict()
        for role, verdict in judge_runtime_paths(
            collect_observations(environ, home)
        ).items()
    }
