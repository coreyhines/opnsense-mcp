"""CI deploy jobs pin the deploy host's key instead of trusting any answer.

`ssh-setup.sh` appended `ssh-keyscan` output with failures hidden, and every
ssh/scp then ran with `StrictHostKeyChecking=no`, so the scan was not even
consulted. A job that authenticates as root and runs a pushed script would
talk to whatever answered.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SSH_SETUP = REPO_ROOT / "deploy" / "ci" / "ssh-setup.sh"
CI_FILES = [
    *sorted((REPO_ROOT / ".forgejo" / "workflows").glob("*.yml")),
    *sorted((REPO_ROOT / "deploy" / "ci").glob("*.sh")),
]
HOST = "deploy.example"


def _code_lines(path: Path) -> list[str]:
    return [
        line
        for line in path.read_text().splitlines()
        if not line.lstrip().startswith("#")
    ]


@pytest.mark.parametrize("path", CI_FILES, ids=lambda p: p.name)
def test_no_ci_file_disables_host_key_checking(path: Path) -> None:
    for line in _code_lines(path):
        assert "StrictHostKeyChecking=no" not in line, line
        assert "ssh-keyscan" not in line, line


def _keypair(tmp_path: Path, name: str) -> tuple[Path, str]:
    key = tmp_path / name
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
    )
    return key, (tmp_path / f"{name}.pub").read_text().split()[1]


def _setup(tmp_path: Path, host_key: str | None) -> subprocess.CompletedProcess[str]:
    home = tmp_path / "home"
    home.mkdir()
    deploy_key, _ = _keypair(tmp_path, "deploy")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    # Fails the test if anything still scans: the key must come from config.
    scan = bin_dir / "ssh-keyscan"
    scan.write_text(f'#!/usr/bin/env bash\ntouch "{tmp_path}/scanned"\n')
    scan.chmod(0o755)
    env = {
        "HOME": str(home),
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "OPNSENSE_MCP_DEPLOY_HOST": HOST,
        "OPNSENSE_MCP_DEPLOY_SSH_KEY": str(deploy_key),
    }
    if host_key is not None:
        env["OPNSENSE_MCP_DEPLOY_HOST_KEY"] = host_key
    return subprocess.run(
        ["bash", str(SSH_SETUP)], env=env, capture_output=True, text=True, check=False
    )


def test_setup_refuses_without_a_pinned_host_key(tmp_path: Path) -> None:
    result = _setup(tmp_path, None)
    assert result.returncode != 0
    assert not (tmp_path / "home" / ".ssh" / "known_hosts").exists()
    assert not (tmp_path / "scanned").exists()


def test_setup_refuses_a_pinned_key_for_another_host(tmp_path: Path) -> None:
    _, pub = _keypair(tmp_path, "hostkey")
    result = _setup(tmp_path, f"other.example ssh-ed25519 {pub}")
    assert result.returncode != 0


def test_setup_pins_the_key_and_enforces_it(tmp_path: Path) -> None:
    _, pub = _keypair(tmp_path, "hostkey")
    line = f"{HOST} ssh-ed25519 {pub}"

    result = _setup(tmp_path, line)

    assert result.returncode == 0, result.stderr
    ssh_dir = tmp_path / "home" / ".ssh"
    assert (ssh_dir / "known_hosts").read_text().splitlines() == [line]
    config = (ssh_dir / "config").read_text().split()
    assert config[config.index("StrictHostKeyChecking") + 1] == "yes"
    assert not (tmp_path / "scanned").exists()
