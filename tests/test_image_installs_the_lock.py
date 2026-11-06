"""The images install exactly the locked dependency set.

Both images ran `pip install -r requirements.txt`, which holds floors, so pip
resolved every transitive dependency fresh at build time. The 1.3.0 image ran
fastmcp 4.2.0a3 and authlib 1.9.3 while `uv.lock`, the set the tests ran
against, held 4.0.0b5 and 1.9.1 (#126). Dependabot and Trivy scan `uv.lock`,
so their findings described a set that was not deployed.

The images now install `requirements.lock`, an `uv export` of `uv.lock`, with
`--no-deps --require-hashes`. These tests fail when an image installs anything
else, or when the export no longer matches the lock.
"""

from __future__ import annotations

import pathlib
import re
import shlex
import shutil
import subprocess
import tomllib

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
LOCK_EXPORT = REPO / "requirements.lock"
UV_LOCK = REPO / "uv.lock"
IMAGES = (REPO / "deploy" / "Containerfile", REPO / "Dockerfile")
EXPORT_CMD = ["uv", "export", "--frozen", "--no-dev", "--no-emit-project", "-q"]

# The project itself, installed without resolving anything.
_PROJECT_TARGETS = {".", "-e ."}


def _run_commands(containerfile: pathlib.Path) -> list[str]:
    """Each shell command in the file's RUN instructions, continuations joined."""
    joined = re.sub(r"\\\n", " ", containerfile.read_text())
    commands: list[str] = []
    for line in joined.splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("RUN "):
            commands.extend(c.strip() for c in stripped[4:].split("&&"))
    return commands


def _pip_installs(containerfile: pathlib.Path) -> list[list[str]]:
    """The argument lists of every `pip install` in the file."""
    found = []
    for command in _run_commands(containerfile):
        words = shlex.split(command)
        for i in range(len(words) - 1):
            if words[i].endswith("pip") and words[i + 1] == "install":
                found.append(words[i + 2 :])
                break
    return found


def _install_problems(args: list[str]) -> list[str]:
    """Why one `pip install` could put something outside the lock in the image."""
    problems = []
    if "--no-deps" not in args:
        problems.append("no --no-deps, so pip resolves dependencies itself")
    requirement_files = [args[i + 1] for i, a in enumerate(args[:-1]) if a == "-r"]
    for name in requirement_files:
        if name != LOCK_EXPORT.name:
            problems.append(f"installs from {name}, not {LOCK_EXPORT.name}")
    if requirement_files and "--require-hashes" not in args:
        problems.append("lock installed without --require-hashes")
    skip = {"-r", *requirement_files}
    targets = [a for a in args if not a.startswith("-") and a not in skip]
    flags = " ".join(a for a in args if a == "-e")
    for target in targets:
        if f"{flags} {target}".strip() not in _PROJECT_TARGETS:
            problems.append(f"installs {target!r}, which is not in the lock")
    return problems


@pytest.mark.parametrize("containerfile", IMAGES, ids=lambda p: p.name)
def test_every_image_install_comes_from_the_lock(containerfile: pathlib.Path) -> None:
    """No `pip install` in an image may resolve or fetch outside the lock."""
    installs = _pip_installs(containerfile)
    assert any(f"-r {LOCK_EXPORT.name}" in " ".join(a) for a in installs), (
        f"{containerfile.name} never installs {LOCK_EXPORT.name}"
    )
    problems = {
        " ".join(args): _install_problems(args)
        for args in installs
        if _install_problems(args)
    }
    assert not problems, f"{containerfile.name}: {problems}"


@pytest.mark.parametrize(
    "args",
    [
        ["--no-cache-dir", "-r", "requirements.txt"],
        ["--no-cache-dir", "--no-deps", "-r", "requirements.txt"],
        ["--no-cache-dir", "--no-deps", "-r", "requirements.lock"],
        ["--no-cache-dir", "--upgrade", "pip"],
        ["--no-cache-dir", "-e", "."],
        ["--no-deps", "fastmcp==4.2.0a3"],
    ],
)
def test_the_install_check_rejects_unlocked_installs(args: list[str]) -> None:
    """Each of these lets the image hold something the tests never ran."""
    assert _install_problems(args)


def _normalise(name: str) -> str:
    """PEP 503 name: `ruamel.yaml` and `ruamel-yaml` are one package."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _lock_versions() -> dict[str, str]:
    """Package name to version, from uv.lock."""
    data = tomllib.loads(UV_LOCK.read_text())
    return {_normalise(p["name"]): p["version"] for p in data["package"]}


def _export_versions() -> dict[str, str]:
    """Package name to version, from requirements.lock."""
    found = {}
    for line in LOCK_EXPORT.read_text().splitlines():
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^ ;\\]+)", line)
        if match:
            found[_normalise(match.group(1))] = match.group(2)
    return found


def test_the_export_pins_what_uv_lock_pins() -> None:
    """A bump in uv.lock without a re-export would ship the old version."""
    locked = _lock_versions()
    exported = _export_versions()
    assert exported, f"{LOCK_EXPORT.name} pins nothing"
    stale = sorted(
        f"{name} {version} (uv.lock {locked.get(name)})"
        for name, version in exported.items()
        if locked.get(name) != version
    )
    assert not stale, f"re-run `{' '.join(EXPORT_CMD)} -o {LOCK_EXPORT.name}`: {stale}"


def test_the_export_holds_every_runtime_dependency() -> None:
    """Every [project].dependencies entry must reach the image."""
    data = tomllib.loads((REPO / "pyproject.toml").read_text())
    direct = {
        _normalise(re.split(r"[\[<>=!~ ;]", dep, maxsplit=1)[0])
        for dep in data["project"]["dependencies"]
    }
    exported = set(_export_versions())
    missing = sorted(direct - exported)
    assert not missing, f"{LOCK_EXPORT.name} is missing {missing}"


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv not installed")
def test_the_export_is_current() -> None:
    """Byte-for-byte what `uv export` produces now, so nothing was hand-edited."""
    result = subprocess.run(  # noqa: S603
        EXPORT_CMD,
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
    )
    body = [ln for ln in result.stdout.splitlines() if not ln.startswith("#")]
    committed = [
        ln for ln in LOCK_EXPORT.read_text().splitlines() if not ln.startswith("#")
    ]
    assert body == committed, f"re-run `{' '.join(EXPORT_CMD)} -o {LOCK_EXPORT.name}`"
