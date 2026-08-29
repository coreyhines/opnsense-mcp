"""The quadlet must provide the directories the tools need at runtime.

Two tools were non-functional as deployed, both because a path the code
expects had nothing behind it (issues #20 and #21):

- Every SSH-backed tool failed. The quadlet mounts a host `ssh` directory at
  /root/.ssh, but nothing created it, so the container got an empty mount:
  no key, no known_hosts.
- `config_backup action=download` failed on an unset OPNSENSE_BACKUP_DIR, and
  the only writable path was not writable: the install root is mounted `ro`.

Every check in this file reads files in this repository — the example
quadlet, the environment example, the install script. None of them can see a
deployment, and that is not a technicality: the example below was correct the
whole time while the unit installed on the container host was stale and left
OPNSENSE_BACKUP_DIR unset, so `download` failed there with
"OPNSENSE_BACKUP_DIR is not set" while every assertion in this file stayed
green (defect D2a, issue #21). These tests keep the *intended* configuration
from regressing; a green run here says nothing about any deployed host. The
deployment-side answer comes from the running server itself:
``opnsense_mcp/utils/deploy_probe.py``, surfaced by the `system` tool's
``mcp_server.runtime_paths`` section, falsified in
tests/test_deploy_probe.py.
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


def _generated_unit() -> str:
    """The app unit as `install.sh` actually writes it.

    The example file is documentation. `verify_deploy_tree` checks it exists
    and nothing ever reads it: `write_opnsense_mcp_quadlet` emits the unit from
    its own printf lines. So every assertion against the example was checking a
    file the installer ignores, which is why the example carried
    OPNSENSE_BACKUP_DIR for months while installed units did not.

    Extracted from the shell rather than executed: running install.sh needs
    root, podman and a network.
    """
    body = INSTALL_SH.read_text()
    start = body.index("write_opnsense_mcp_quadlet() {")
    end = body.index("write_caddy_quadlet() {", start)
    lines = []
    for raw in body[start:end].splitlines():
        stripped = raw.strip()
        if not stripped.startswith("printf '%s\\n'"):
            continue
        value = stripped.split("printf '%s\\n'", 1)[1].strip()
        if value.startswith(("'", '"')):
            value = value[1:-1]
        lines.append(value.replace("${INSTALL_ROOT}", INSTALL_ROOT))
    return "\n".join(lines)


def _generated_volumes() -> list[str]:
    """The Volume= lines install.sh writes into the unit."""
    return [
        line.split("=", 1)[1].strip()
        for line in _generated_unit().splitlines()
        if line.startswith("Volume=")
    ]


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


def _backup_dir_from_example() -> str:
    """The OPNSENSE_BACKUP_DIR value the example quadlet sets, or fail."""
    for line in APP_QUADLET.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("Environment=OPNSENSE_BACKUP_DIR="):
            return stripped.split("=", 2)[2].strip()
    raise AssertionError("the example quadlet sets no OPNSENSE_BACKUP_DIR")


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
#
# These assertions check the repo's EXAMPLE, not the deployment — that is
# the whole reason this section needed new names. The example set
# OPNSENSE_BACKUP_DIR correctly the entire time while the unit installed on
# the container host left it unset, so `config_backup action=download` failed
# on the deployed server with "OPNSENSE_BACKUP_DIR is not set" and every test
# in this section stayed green. This file cannot see the deployment, and no
# repo test can; the names now say "_in_the_example" so a reader cannot
# mistake a green run here for a deployment verdict — that mistake is exactly
# how the defect survived. The deployed host's verdict is the running
# server's own report (opnsense_mcp/utils/deploy_probe.py, in the `system`
# tool's mcp_server.runtime_paths).


def test_the_backup_directory_is_configured_in_the_example() -> None:
    """The EXAMPLE sets OPNSENSE_BACKUP_DIR; the deployment may not have.

    `config_backup action=download` errors out when this is unset — which is
    what the deployed unit did while this assertion, reading only the repo's
    example quadlet and environment example, stayed green.
    """
    text = APP_QUADLET.read_text() + ENVIRONMENT_EXAMPLE.read_text()

    assert "OPNSENSE_BACKUP_DIR" in text, (
        "nothing in the repo example sets OPNSENSE_BACKUP_DIR, "
        "so download can never succeed"
    )


def test_the_backup_dir_value_in_the_example_is_the_path_mounted_rw() -> None:
    """The example's value must be the directory the example mounts rw.

    The install root is mounted ro, so a value pointing anywhere else would
    swap "not set" for the quieter "cannot write" on the deployed box. Still
    only an internal-consistency check of the repo example, not a deployment
    one.
    """
    configured = _backup_dir_from_example()
    backup_mount = _volume_for(f"{INSTALL_ROOT}/backups")
    container_side = backup_mount.split(":")[1]
    options = backup_mount.split(":")[2].split(",")

    assert configured == container_side, (
        f"the example sets OPNSENSE_BACKUP_DIR={configured} but mounts "
        f"{container_side} for backups"
    )
    assert "ro" not in options, f"backup volume is read-only: {backup_mount}"


def test_the_backup_mount_is_writable_in_the_example() -> None:
    """The EXAMPLE's backup mount must not be read-only.

    The install root is mounted ro, so backups need their own rw mount.
    Pointing OPNSENSE_BACKUP_DIR inside the read-only mount would swap one
    failure for a less obvious one. This reads the example quadlet in this
    repo; it cannot see the deployment.
    """
    backup_mount = _volume_for(f"{INSTALL_ROOT}/backups")
    options = backup_mount.split(":")[2].split(",")

    assert "ro" not in options, f"backup volume is read-only: {backup_mount}"


def test_the_backup_directory_is_outside_the_git_checkout_in_the_example() -> None:
    """The EXAMPLE keeps backups out of the repository.

    The tool's own error says to keep backups out of the git checkout; this
    checks the example's host path only, not the deployment.
    """
    mount = _volume_for(f"{INSTALL_ROOT}/backups")

    assert mount.split(":")[0].startswith(INSTALL_ROOT)


def test_the_install_script_in_this_repo_creates_the_backup_directory() -> None:
    """install.sh IN THIS REPO creates the backups directory it mounts.

    Same trap as the ssh mount: an uncreated bind source mounts empty. This
    reads deploy/install.sh from the repository; whether the script ever ran
    on the container host is not something this file can see.
    """
    assert re.search(
        r"mkdir -p .*\$\{INSTALL_ROOT\}/backups", INSTALL_SH.read_text()
    ), "install.sh does not create the backups directory"


# --- the installer, not the example ----------------------------------------
#
# These are the assertions that would have caught D2a. Each one has a
# counterpart above that reads the example and passed throughout.


def test_the_installer_sets_the_backup_directory() -> None:
    """The example carried this for months while installed units did not."""
    assert f"Environment=OPNSENSE_BACKUP_DIR={INSTALL_ROOT}/backups" in (
        _generated_unit()
    ), "install.sh writes a unit with no OPNSENSE_BACKUP_DIR; download cannot work"


def test_the_installer_mounts_the_backup_directory_writable() -> None:
    """The install root is mounted ro, so backups need their own rw mount."""
    mounts = [v for v in _generated_volumes() if v.split(":")[1].endswith("/backups")]
    assert len(mounts) == 1, f"expected one backups mount, got {mounts}"
    assert "ro" not in mounts[0].split(":")[2].split(","), (
        f"backup volume is read-only: {mounts[0]}"
    )


def test_the_installer_mounts_the_ssh_directory() -> None:
    """An unmounted key directory fails one SSH-backed tool call at a time."""
    mounts = [v for v in _generated_volumes() if v.split(":")[1] == "/root/.ssh"]
    assert len(mounts) == 1, f"expected one /root/.ssh mount, got {mounts}"
    assert "ro" in mounts[0].split(":")[2].split(","), (
        f"private key material should not be writable: {mounts[0]}"
    )


def test_the_installer_and_the_example_do_not_disagree() -> None:
    """Two descriptions of one unit that drift are worse than one.

    The example is what a reader consults; the installer is what runs. They
    disagreed on three lines, and only the reader-facing one was tested.
    """
    generated = set(_generated_volumes())
    documented = set(_volumes())
    missing = {v.split(":")[1] for v in documented} - {
        v.split(":")[1] for v in generated
    }
    assert not missing, (
        f"the example documents mounts install.sh does not create: {sorted(missing)}"
    )


def test_the_installer_restarts_a_running_unit() -> None:
    """A re-run that rewrites the quadlet must reload the running container.

    `systemctl start` on an active unit is a no-op and `daemon-reload` does not
    restart services, so the script rewrote the unit with the new mounts,
    printed "Install finished", and left the container running the old image
    with the old mount set. Verified by hand on the deployment: after a
    successful re-run, `podman ps` still showed the previous image tag.

    The mounts this file asserts are therefore only true of the next cold
    start unless the installer restarts what is already up.
    """
    body = INSTALL_SH.read_text()
    start = body.index("enable_or_start_quadlet() {")
    # The function's own closing brace, at its indent. Searching for a bare
    # "}" stops inside "${sname}".
    end = body.index("\n  }", start)
    helper = body[start:end]

    assert "is-active" in helper, (
        "the installer does not check whether the unit is already running, so "
        "a re-run cannot restart it"
    )
    assert "restart" in helper, (
        "the installer never restarts; a rewritten quadlet stays unapplied "
        "until something else stops the unit"
    )
