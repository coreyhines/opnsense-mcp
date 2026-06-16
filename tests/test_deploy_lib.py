"""Tests for deploy/lib.sh and deploy/ci/compute-image-tag.sh."""

from __future__ import annotations

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


def test_normalize_image_repo_defaults_to_hub() -> None:
    result = _run_lib_snippet(
        'IMAGE_REPO="localhost/opnsense-mcp"\n'
        "normalize_image_repo\n"
        'printf "%s" "${IMAGE_REPO}"'
    )
    assert result.returncode == 0
    assert result.stdout == "hub.freeblizz.com/opnsense-mcp"


def test_compute_image_tag_uses_pyproject_dev_suffix() -> None:
    result = subprocess.run(
        ["bash", str(COMPUTE_TAG)],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0
    tag = result.stdout.strip()
    assert tag.startswith("1.0.0-dev.")
    assert len(tag.split(".")[-1]) >= 7
