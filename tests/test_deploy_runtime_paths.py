"""The quadlet must provide the directories the tools need at runtime.

Two tools were non-functional as deployed, both because a path the code
expects had nothing behind it (issues #20 and #21):

- Every SSH-backed tool failed. The quadlet mounts a host `ssh` directory at
  /root/.ssh, but nothing created it, so the container got an empty mount:
  no key, no known_hosts.
- `config_backup action=download` failed on an unset OPNSENSE_BACKUP_DIR, and
  the only writable path was not writable: the install root is mounted `ro`.

Both failed closed with a clear message, which is why they were low severity
and also why they went unnoticed for so long. These tests fail in the repo
rather than on the next deploy.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEPLOY = REPO_ROOT / "deploy"
INSTALL_SH = DEPLOY / "install.sh"
APP_QUADLET = DEPLOY / "opnsense-mcp-app.container.example"
ENVIRONMENT_EXAMPLE = DEPLOY / "environment.example"

INSTALL_ROOT = "/opt/containerdata/opnsense-mcp"


def _volumes() -> list[str]:
    """The Volume= lines of the app quadlet."""
    return [
        line.split("=", 1)[1].strip()
        for line in APP_QUADLET.read_text().splitlines()
        if line.strip().startswith("Volume=")
    ]


def _volume_for(container_path: str) -> str:
    """The single Volume= line mounting `container_path`, or fail."""
    matches = [v for v in _volumes() if v.split(":")[1] == container_path]
    assert len(matches) == 1, (
        f"expected exactly one mount at {container_path}, got {matches}"
    )
    return matches[0]


# --- #20: SSH material ------------------------------------------------------


def test_the_install_creates_the_ssh_directory_it_mounts() -> None:
    """Podman creates a missing bind source as an empty directory.

    So a quadlet that mounts a path nothing created does not fail; it
    silently hands the container an empty /root/.ssh, and every SSH tool
    reports a missing key or an unknown host instead.
    """
    mount = _volume_for("/root/.ssh")
    host_path = mount.split(":")[0]

    assert host_path.endswith("/ssh")
    assert re.search(
        rf"mkdir -p .*{re.escape('${INSTALL_ROOT}')}/ssh|mkdir -p .*{re.escape(host_path)}",
        INSTALL_SH.read_text(),
    ), "install.sh does not create the directory the quadlet mounts at /root/.ssh"


def test_the_ssh_mount_stays_read_only() -> None:
    """Private key material has no reason to be writable by the container."""
    assert "ro" in _volume_for("/root/.ssh").split(":")[2].split(",")


# --- #21: backup directory --------------------------------------------------


def test_the_backup_directory_is_configured() -> None:
    """`config_backup action=download` errors out when this is unset."""
    text = APP_QUADLET.read_text() + ENVIRONMENT_EXAMPLE.read_text()

    assert "OPNSENSE_BACKUP_DIR" in text, (
        "nothing sets OPNSENSE_BACKUP_DIR, so download can never succeed"
    )


def test_the_backup_directory_is_writable() -> None:
    """The install root is mounted ro, so backups need their own rw mount.

    Pointing OPNSENSE_BACKUP_DIR inside the read-only mount would swap one
    failure for a less obvious one.
    """
    backup_mount = _volume_for(f"{INSTALL_ROOT}/backups")
    options = backup_mount.split(":")[2].split(",")

    assert "ro" not in options, f"backup volume is read-only: {backup_mount}"


def test_the_backup_directory_is_outside_the_git_checkout() -> None:
    """The tool's own error says to keep backups out of the repository."""
    mount = _volume_for(f"{INSTALL_ROOT}/backups")

    assert mount.split(":")[0].startswith(INSTALL_ROOT)


def test_the_install_creates_the_backup_directory() -> None:
    """Same trap as the ssh mount: an uncreated bind source mounts empty."""
    assert re.search(
        r"mkdir -p .*\$\{INSTALL_ROOT\}/backups", INSTALL_SH.read_text()
    ), "install.sh does not create the backups directory"
