"""Tests for deploy/lib.sh and deploy/ci/compute-image-tag.sh."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
LIB_SH = REPO_ROOT / "deploy" / "lib.sh"
COMPUTE_TAG = REPO_ROOT / "deploy" / "ci" / "compute-image-tag.sh"


def _run_lib_snippet(snippet: str) -> subprocess.CompletedProcess[str]:
    script = f'source "{LIB_SH}"\n{snippet}'
    return subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        check=False,
    )


def test_validate_pinned_image_tag_rejects_latest() -> None:
    result = _run_lib_snippet('validate_pinned_image_tag "latest"')
    assert result.returncode != 0
    assert "latest" in result.stderr


def test_validate_pinned_image_tag_rejects_empty() -> None:
    result = _run_lib_snippet('validate_pinned_image_tag ""')
    assert result.returncode != 0
    assert "OPNSENSE_MCP_IMAGE_TAG" in result.stderr


def test_validate_pinned_image_tag_rejects_raw_sha() -> None:
    result = _run_lib_snippet('validate_pinned_image_tag "6845616"')
    assert result.returncode != 0


def test_validate_pinned_image_tag_accepts_release() -> None:
    result = _run_lib_snippet('validate_pinned_image_tag "1.0.0"')
    assert result.returncode == 0


def test_validate_pinned_image_tag_accepts_dev_build() -> None:
    result = _run_lib_snippet('validate_pinned_image_tag "1.0.0-dev.6845616"')
    assert result.returncode == 0


def test_normalize_image_repo_keeps_a_local_image_local() -> None:
    """A local image is what --build-local produces, so it must survive.

    This used to be rewritten to a private registry, which meant the local
    build path quietly pointed at a host the user has no account on.
    """
    result = _run_lib_snippet(
        'IMAGE_REPO="localhost/opnsense-mcp"\n'
        "normalize_image_repo\n"
        'printf "%s" "${IMAGE_REPO}"'
    )
    assert result.returncode == 0
    assert result.stdout == "localhost/opnsense-mcp"


def test_normalize_image_repo_defaults_to_a_local_image() -> None:
    """No registry configured means no registry, not somebody else's."""
    result = _run_lib_snippet(
        'IMAGE_REPO=""\nnormalize_image_repo\nprintf "%s" "${IMAGE_REPO}"'
    )
    assert result.returncode == 0
    assert result.stdout == "localhost/opnsense-mcp"


def test_normalize_image_repo_qualifies_a_bare_name() -> None:
    """A bare name is ambiguous to podman; qualify it as local."""
    result = _run_lib_snippet(
        'IMAGE_REPO="opnsense-mcp"\nnormalize_image_repo\nprintf "%s" "${IMAGE_REPO}"'
    )
    assert result.returncode == 0
    assert result.stdout == "localhost/opnsense-mcp"


def test_normalize_image_repo_keeps_an_explicit_registry() -> None:
    """Someone who names a registry gets that registry, untouched."""
    result = _run_lib_snippet(
        'IMAGE_REPO="registry.example/opnsense-mcp"\n'
        "normalize_image_repo\n"
        'printf "%s" "${IMAGE_REPO}"'
    )
    assert result.returncode == 0
    assert result.stdout == "registry.example/opnsense-mcp"


def test_pull_refuses_a_local_only_image_with_advice() -> None:
    """Pulling localhost/... fails deep in podman with an opaque registry error.

    Anyone deploying this in their own environment has no registry by default,
    so the failure has to name the two things that actually work.
    """
    result = _run_lib_snippet(
        'IMAGE_REPO="localhost/opnsense-mcp"\nrequire_pullable_image_repo'
    )
    assert result.returncode != 0
    assert "--build-local" in result.stderr
    assert "OPNSENSE_MCP_IMAGE_REPO" in result.stderr


def test_pull_accepts_any_real_registry() -> None:
    """No opinion about which registry, only that there is one."""
    result = _run_lib_snippet(
        'IMAGE_REPO="registry.example/opnsense-mcp"\nrequire_pullable_image_repo'
    )
    assert result.returncode == 0


def _compute_tag(
    tmp_path: Path, version: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Run a copy of compute-image-tag.sh against a pyproject at `version`."""
    script = tmp_path / "deploy" / "ci" / "compute-image-tag.sh"
    script.parent.mkdir(parents=True)
    script.write_text(COMPUTE_TAG.read_text())
    (tmp_path / "pyproject.toml").write_text(f'[project]\nversion = "{version}"\n')
    return subprocess.run(
        ["bash", str(script)],
        capture_output=True,
        text=True,
        check=False,
        env={
            "PATH": os.environ["PATH"],
            "CI_COMMIT_SHORT_SHA": "44c13f6",
            **(env or {}),
        },
    )


def _core(tag: str) -> tuple[int, ...]:
    return tuple(int(n) for n in tag.split("-", 1)[0].split("."))


def test_dev_tag_sorts_after_the_release_it_follows(tmp_path: Path) -> None:
    """A build after v1.1.0 was tagged 1.1.0-dev, which semver ranks below 1.1.0.

    A deployer then treated 1.1.0 as an upgrade and dropped 32 commits of
    fixes. The dev tag must be a prerelease of a later core version.
    """
    result = _compute_tag(tmp_path, "1.1.0")
    assert result.returncode == 0, result.stderr
    tag = result.stdout.strip()
    assert tag == "1.1.1-dev.44c13f6"
    assert _core(tag) > _core("1.1.0")


def test_release_tag_must_match_pyproject(tmp_path: Path) -> None:
    """Dev tags assume pyproject holds the last release, so a tag cannot drift."""
    result = _compute_tag(tmp_path, "1.1.0", {"CI_COMMIT_TAG": "v1.1.1"})
    assert result.returncode != 0
    assert result.stdout == ""


def test_release_tag_strips_the_v(tmp_path: Path) -> None:
    result = _compute_tag(tmp_path, "1.1.1", {"CI_COMMIT_TAG": "v1.1.1"})
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "1.1.1"


def test_dev_tag_refuses_a_non_semver_pyproject(tmp_path: Path) -> None:
    result = _compute_tag(tmp_path, "1.2.0rc1")
    assert result.returncode != 0
    assert result.stdout == ""


def test_is_interactive_shell_says_no_without_a_controlling_terminal() -> None:
    """The case a non-interactive `ssh host 'cmd'` install hits.

    `/dev/tty` exists and passes -e and -r there, while opening it fails with
    ENXIO. The old test answered yes, so install.sh ran six `read </dev/tty`
    prompts that each failed with "No such device or address", `|| true`
    swallowed them, and every prompted setting silently took its default.

    `start_new_session` puts the child in its own session with no controlling
    terminal, which is what reproduces it, and is portable where `setsid(1)` is
    not. stdin is redirected as well, so the -t 0 fallback cannot mask the
    result.
    """
    script = f'source "{LIB_SH}"\nis_interactive_shell && echo yes || echo no'
    result = subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        check=False,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )

    assert result.stdout.strip() == "no", result.stderr


def test_is_interactive_shell_says_yes_on_a_real_terminal() -> None:
    """The other direction, or the fix would just be "always answer no"."""
    import os
    import pty

    pid, fd = pty.fork()
    if pid == 0:  # pragma: no cover - child replaces itself
        os.execvp(
            "bash",
            [
                "bash",
                "-c",
                f'source "{LIB_SH}"\nis_interactive_shell && exit 0 || exit 1',
            ],
        )

    _, status = os.waitpid(pid, 0)
    os.close(fd)

    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
