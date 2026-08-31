"""A workflow that checks out code must be able to run a Node action.

`actions/checkout` is Node-based. A job whose container image has no `node`
dies with:

    crun: executable file `node` not found in $PATH

The repo has hit this twice: `deploy.yml` carries a comment about it for its
alpine image, and `dependency-freshness.yml` still hit it on `python:3.12-slim`
because the note lived in a comment rather than a check.
"""

from __future__ import annotations

import pathlib

import pytest

yaml = pytest.importorskip("yaml")

WORKFLOWS = pathlib.Path(__file__).resolve().parent.parent / ".forgejo" / "workflows"

# Images that already ship node, so a job on one needs no install step.
IMAGES_WITH_NODE = ("node:", "catthehacker/", "ghcr.io/catthehacker/")


def _jobs(path: pathlib.Path) -> dict:
    return (yaml.safe_load(path.read_text()) or {}).get("jobs", {}) or {}


def _uses_checkout(job: dict) -> bool:
    return any(
        "actions/checkout" in str(step.get("uses", ""))
        for step in job.get("steps", []) or []
    )


def _installs_node(job: dict) -> bool:
    """Any step before the checkout that installs node."""
    for step in job.get("steps", []) or []:
        if "actions/checkout" in str(step.get("uses", "")):
            return False  # reached checkout without an install
        run = str(step.get("run", ""))
        if "nodejs" in run or "node " in run or "install node" in run.lower():
            return True
    return False


def test_every_checkout_job_can_run_node() -> None:
    """Either the image ships node, or a step installs it before the checkout."""
    offenders: list[str] = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        for name, job in _jobs(path).items():
            if not isinstance(job, dict) or not _uses_checkout(job):
                continue
            image = str((job.get("container") or {}).get("image", ""))
            if not image or image.startswith(IMAGES_WITH_NODE):
                continue
            if not _installs_node(job):
                offenders.append(f"{path.name}:{name} (image {image})")

    assert not offenders, (
        "these jobs run actions/checkout on an image without node and install "
        "none before it: " + ", ".join(offenders)
    )


def test_no_job_runs_an_unpinned_container_image() -> None:
    """A `:latest` image makes CI non-reproducible and silently mutable.

    `deploy/lib.sh::validate_pinned_image_tag` already refuses `latest` for the
    deploy image, so holding CI to a weaker standard was an inconsistency, not a
    considered choice. It also bites in a specific way here: the semgrep job's
    own comment says rulesets are pinned "so runs stay reproducible" while the
    image underneath them rolled forward on every pull.

    A digest would be stricter still. Version tags are what this repo uses
    elsewhere (`caddy:2.9.1-alpine`, `gitleaks:v8.30.1`, `python:3.12-alpine`),
    so that is the bar enforced here.
    """
    unpinned = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        for name, job in _jobs(path).items():
            image = job.get("container") or {}
            image = image.get("image") if isinstance(image, dict) else image
            if not isinstance(image, str):
                continue
            tag = image.rsplit(":", 1)[-1] if ":" in image.rsplit("/", 1)[-1] else ""
            if tag in ("", "latest"):
                unpinned.append(f"{path.name}:{name} -> {image}")

    assert not unpinned, (
        "container images must be pinned to a version tag, not `latest` or an "
        "implicit tag: " + ", ".join(unpinned)
    )
