"""The Docker runtime path gets what the podman quadlet already has (#108).

`install.sh --runtime docker` ran `compose up --build-arg`, which Compose does
not accept, so it errored. Its compose file set `build.context: .`, which
resolves relative to the compose file, so the Dockerfile path doubled to
`deploy/deploy/Containerfile`. It also had none of the fixes for issues #20
and #21: no /root/.ssh mount, no OPNSENSE_BACKUP_DIR, a read-only install
root, and a hard-coded install root.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
COMPOSE = REPO / "deploy" / "docker-compose.yml"
INSTALL_SH = REPO / "deploy" / "install.sh"
_VAR = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]*))?\}")


def _resolved(env: dict[str, str]) -> dict:
    """The compose file with ${VAR:-default} resolved, as Compose does."""
    text = _VAR.sub(
        lambda m: env.get(m.group(1)) or (m.group(2) or ""), COMPOSE.read_text()
    )
    return yaml.safe_load(text)


def _app(env: dict[str, str]) -> dict:
    return _resolved(env)["services"]["opnsense-mcp"]


def _mounts(service: dict) -> dict[str, tuple[str, str]]:
    """target -> (source, mode)."""
    out = {}
    for spec in service["volumes"]:
        source, target, *mode = spec.split(":")
        out[target] = (source, mode[0] if mode else "rw")
    return out


def test_the_build_context_is_the_repo_root() -> None:
    build = _app({})["build"]
    context = (COMPOSE.parent / build["context"]).resolve()
    assert context == REPO
    assert (context / build["dockerfile"]).is_file()


@pytest.mark.parametrize("root", ["/opt/containerdata/opnsense-mcp", "/srv/omcp"])
def test_ssh_and_backups_get_their_own_mounts(root: str) -> None:
    env = (
        {}
        if root == "/opt/containerdata/opnsense-mcp"
        else {"OPNSENSE_MCP_INSTALL_ROOT": root}
    )
    app = _app(env)
    mounts = _mounts(app)

    assert mounts["/root/.ssh"] == (f"{root}/ssh", "ro")
    backup_dir = app["environment"]["OPNSENSE_BACKUP_DIR"]
    assert backup_dir == f"{root}/backups"
    assert mounts[backup_dir] == (f"{root}/backups", "rw")
    assert mounts[root] == (root, "ro")
    assert app["env_file"] == [f"{root}/environment"]


def test_install_creates_every_bind_source_the_compose_file_mounts() -> None:
    """A missing bind source mounts empty instead of failing the deploy."""
    body = INSTALL_SH.read_text()
    assert 'mkdir -p "${INSTALL_ROOT}/ssh" "${INSTALL_ROOT}/backups"' in body


def test_install_builds_then_starts_without_up_build_arg() -> None:
    body = INSTALL_SH.read_text()
    branch = body[body.index('echo "docker not found in PATH"') :]
    branch = branch.split("Install finished")[0]
    code = [
        line.strip() for line in branch.splitlines() if not line.strip().startswith("#")
    ]
    assert not any("--build-arg" in line for line in code)
    assert '"${compose[@]}" build' in code
    assert '"${compose[@]}" up -d' in code


def test_the_caddy_image_is_pinned() -> None:
    image = _resolved({})["services"]["caddy"]["image"]
    assert re.search(r":\d+\.\d+\.\d+", image), image
