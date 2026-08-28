"""Tests that the deploy scripts agree on where quadlets live.

Three scripts encode the quadlet path independently: install.sh writes the
files, deploy-host.sh patches the image tag in one of them, and uninstall.sh
removes them. They drifted once already, which left the service running from
flat files in the shared parent while a stale subdirectory sat beside them.
These tests fail on that drift rather than waiting for a deploy to reveal it.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = REPO_ROOT / "deploy" / "install.sh"
UNINSTALL_SH = REPO_ROOT / "deploy" / "uninstall.sh"
DEPLOY_HOST_SH = REPO_ROOT / "deploy" / "ci" / "deploy-host.sh"

SHARED_PARENT = "/etc/containers/systemd"
SERVICE_DIR = f"{SHARED_PARENT}/opnsense-mcp"


def assign(script: Path, name: str) -> str:
    """Return the value assigned to `name` in a shell script, quotes stripped."""
    pattern = re.compile(rf"^\s*(?:readonly\s+)?{re.escape(name)}=(\S+)", re.MULTILINE)
    match = pattern.search(script.read_text())
    assert match is not None, f"{script.name} does not assign {name}"
    return match.group(1).strip("\"'")


def test_install_writes_quadlets_to_the_service_directory() -> None:
    """Quadlets belong in a per-service directory, as every other service uses."""
    assert assign(INSTALL_SH, "QUADLET_DIR") == SERVICE_DIR


def test_uninstall_targets_the_same_directory_install_writes() -> None:
    """An uninstall that looks elsewhere leaves units behind."""
    assert assign(UNINSTALL_SH, "QUADLET_DIR") == assign(INSTALL_SH, "QUADLET_DIR")


def test_deploy_host_patches_the_same_directory_install_writes() -> None:
    """The image-tag rollout must edit the file systemd is actually reading."""
    assert assign(DEPLOY_HOST_SH, "QUADLET_DIR") == assign(INSTALL_SH, "QUADLET_DIR")


def test_scripts_treat_the_parent_as_the_legacy_location() -> None:
    """The flat parent is where the previous layout put files, not the target."""
    for script in (INSTALL_SH, UNINSTALL_SH):
        assert assign(script, "LEGACY_QUADLET_FLAT_DIR") == SHARED_PARENT


def test_uninstall_never_removes_the_shared_parent_directory() -> None:
    """`/etc/containers/systemd` holds every other service on the host.

    Removing it would take the whole fleet down. Only the per-service directory
    may be removed, and only by name.
    """
    rmdir_targets = re.findall(
        r"^\s*rmdir\s+(\S+)", UNINSTALL_SH.read_text(), re.MULTILINE
    )
    assert rmdir_targets, "uninstall.sh no longer removes the service directory"
    for target in rmdir_targets:
        stripped = target.strip("\"'")
        assert stripped != SHARED_PARENT
        assert "LEGACY_QUADLET_FLAT_DIR" not in stripped
        assert "QUADLET_DIR" in stripped


def test_no_script_writes_a_quadlet_into_the_shared_parent() -> None:
    """The parent may only be read from or cleaned, never written to."""
    for script in (INSTALL_SH, UNINSTALL_SH, DEPLOY_HOST_SH):
        for line in script.read_text().splitlines():
            if "LEGACY_QUADLET_FLAT_DIR" not in line:
                continue
            stripped = line.strip()
            assert stripped.startswith(("#", "rm ", "rm -f", "readonly", "for ")) or (
                stripped.startswith('"') and "rm" not in stripped
            ), f"{script.name}: parent path used outside cleanup: {stripped}"
