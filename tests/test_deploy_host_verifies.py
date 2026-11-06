"""deploy-host.sh fails a rollout it cannot confirm.

It restarted with `app caddy || app`, which hid a failed Caddy restart, then
ran `podman ps` and exited 0 whether that printed the new tag, the old tag or
nothing, so CI went green on a stale or failed rollout. These run the real
script with `podman` and `systemctl` stubbed on PATH.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "deploy" / "ci" / "deploy-host.sh"
WANT = "registry.example/opnsense-mcp:1.3.1"


def _stub(bin_dir: Path, name: str, body: str) -> None:
    path = bin_dir / name
    path.write_text("#!/usr/bin/env bash\n" + body)
    path.chmod(0o755)


def _run(
    tmp_path: Path,
    *,
    running_image: str = WANT,
    inactive: str = "",
    restart_fails: bool = False,
    caddy: bool = True,
    app_name: str = "opnsense-mcp-app",
) -> tuple[subprocess.CompletedProcess[str], str]:
    quadlets = tmp_path / "quadlets"
    quadlets.mkdir()
    (quadlets / "opnsense-mcp-app.container").write_text(
        f"[Container]\nContainerName={app_name}\nImage=localhost/opnsense-mcp:1.0.0\n"
    )
    if caddy:
        (quadlets / "opnsense-mcp-caddy.container").write_text(
            "[Container]\nContainerName=edge-caddy\n"
        )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "calls.log"
    _stub(
        bin_dir,
        "podman",
        f'echo "podman $*" >> "{log}"\n'
        'if [[ "$1" == inspect ]]; then\n'
        f'  [[ "${{@: -1}}" == "{app_name}" ]] && printf "%s" "{running_image}"\n'
        "fi\n",
    )
    _stub(
        bin_dir,
        "systemctl",
        f'echo "systemctl $*" >> "{log}"\n'
        + ('[[ "$1" == restart ]] && exit 1\n' if restart_fails else "")
        + (
            f'[[ "$1" == is-active && "${{@: -1}}" == "{inactive}" ]] && exit 3\n'
            if inactive
            else ""
        )
        + "exit 0\n",
    )
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "OPNSENSE_MCP_IMAGE_REPO": "registry.example/opnsense-mcp",
        "OPNSENSE_MCP_IMAGE_TAG": "1.3.1",
        "OPNSENSE_MCP_QUADLET_DIR": str(quadlets),
        "OPNSENSE_MCP_INSTALL_ROOT": str(tmp_path / "root"),
    }
    result = subprocess.run(
        ["bash", str(SCRIPT)], env=env, capture_output=True, text=True, check=False
    )
    return result, log.read_text() if log.exists() else ""


def test_a_matching_rollout_succeeds(tmp_path: Path) -> None:
    result, _ = _run(tmp_path)
    assert result.returncode == 0, result.stderr


def test_a_stale_image_fails_the_deploy(tmp_path: Path) -> None:
    """The old tail exited 0 while the old image kept running."""
    result, _ = _run(tmp_path, running_image="registry.example/opnsense-mcp:1.3.0")
    assert result.returncode != 0


def test_no_running_container_fails_the_deploy(tmp_path: Path) -> None:
    result, _ = _run(tmp_path, running_image="")
    assert result.returncode != 0


def test_an_inactive_caddy_fails_the_deploy(tmp_path: Path) -> None:
    result, _ = _run(tmp_path, inactive="opnsense-mcp-caddy.service")
    assert result.returncode != 0


def test_a_failed_restart_is_not_retried_as_app_only(tmp_path: Path) -> None:
    """`restart app caddy || restart app` turned a Caddy failure into exit 0."""
    result, calls = _run(tmp_path, restart_fails=True)
    assert result.returncode != 0
    restarts = [c for c in calls.splitlines() if c.startswith("systemctl restart")]
    assert len(restarts) == 1


@pytest.mark.parametrize("caddy", [True, False])
def test_container_names_come_from_the_quadlets(tmp_path: Path, caddy: bool) -> None:
    result, calls = _run(tmp_path, app_name="omcp", caddy=caddy)
    assert result.returncode == 0, result.stderr
    rm = next(c for c in calls.splitlines() if c.startswith("podman rm"))
    assert rm.split()[3:] == (["omcp", "edge-caddy"] if caddy else ["omcp"])
