"""The probe that lets a running server report its own runtime paths.

Defect D2a: ``config_backup action=download`` failed on the deployed server
with "OPNSENSE_BACKUP_DIR is not set" while every repo test was green,
because the repo's tests read the example quadlet — the intended config — and
never the running system. A check that inspects the intended config instead
of the deployment is not a check (tests/test_deploy_runtime_paths.py now says
so in every backup test name).

Everything here asserts on the reason codes from
``opnsense_mcp.utils.deploy_probe`` and on structured fields of the ``system``
result — never on message wording. The three deployment-shaped cases (unset,
missing, read-only) are falsifications of the original defect: if the verdict
logic collapses them into one code, stops distinguishing them, or the
``system`` call starts failing on a broken path, exactly these tests fail.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

import pytest

from opnsense_mcp.tools.system import SystemTool
from opnsense_mcp.utils.deploy_probe import (
    BACKUP_DIR,
    SSH_KEY_DIR,
    PathObservation,
    Reason,
    collect_observations,
    judge_runtime_paths,
    runtime_paths_report,
)


def _observation(
    path: str | None,
    *,
    exists: bool = False,
    is_dir: bool = False,
    writable: bool = False,
) -> PathObservation:
    """Hand-built facts, so the decision function needs no filesystem."""
    return PathObservation(
        configured_path=path, exists=exists, is_dir=is_dir, writable=writable
    )


class _StatusClient:
    """Just enough client for SystemTool's status action.

    The thing under test is the server's own environment, not the firewall,
    so the client only has to make the status call succeed.
    """

    async def get_system_status(self) -> dict[str, Any]:
        return {"hostname": "fw.example", "cpu_usage": 1.5, "memory_usage": 42.0}


async def _system_result() -> dict[str, Any]:
    """Run the system status action and return its full result."""
    tool = SystemTool(_StatusClient())
    return await tool.execute({})


# --- the decision function is pure: no filesystem involved -----------------


def test_an_unset_path_is_not_configured() -> None:
    """Nothing set the variable at all — the deployed defect, exactly."""
    verdicts = judge_runtime_paths({BACKUP_DIR: _observation(None)})
    assert verdicts[BACKUP_DIR].reason is Reason.NOT_CONFIGURED
    assert verdicts[BACKUP_DIR].ok is False
    assert verdicts[BACKUP_DIR].configured_path is None


def test_a_blank_path_is_not_configured_either() -> None:
    """A variable set to whitespace is as unset as an unset variable."""
    verdicts = judge_runtime_paths({BACKUP_DIR: _observation("   ")})
    assert verdicts[BACKUP_DIR].reason is Reason.NOT_CONFIGURED


def test_a_configured_path_that_does_not_exist_has_its_own_code() -> None:
    """Configured but missing is not the same defect as not configured."""
    verdicts = judge_runtime_paths(
        {BACKUP_DIR: _observation("/opt/containerdata/opnsense-mcp/backups")}
    )
    assert verdicts[BACKUP_DIR].reason is Reason.MISSING
    assert verdicts[BACKUP_DIR].reason is not Reason.NOT_CONFIGURED
    assert verdicts[BACKUP_DIR].ok is False


def test_a_configured_file_where_a_directory_belongs_has_its_own_code() -> None:
    """A path that exists but is not a directory is a third, distinct state."""
    verdicts = judge_runtime_paths(
        {BACKUP_DIR: _observation("/etc/hosts", exists=True, is_dir=False)}
    )
    assert verdicts[BACKUP_DIR].reason is Reason.NOT_A_DIRECTORY


def test_a_read_only_backup_directory_has_a_fourth_code() -> None:
    """The deploy mounted everything read-only; that needs its own verdict."""
    verdicts = judge_runtime_paths(
        {BACKUP_DIR: _observation("/srv/backups", exists=True, is_dir=True)}
    )
    assert verdicts[BACKUP_DIR].reason is Reason.NOT_WRITABLE
    assert verdicts[BACKUP_DIR].reason is not Reason.NOT_CONFIGURED
    assert verdicts[BACKUP_DIR].reason is not Reason.MISSING


def test_a_working_backup_directory_is_ok() -> None:
    """Baseline, so the probe is not a permanent complaint."""
    verdicts = judge_runtime_paths(
        {
            BACKUP_DIR: _observation(
                "/srv/backups", exists=True, is_dir=True, writable=True
            )
        }
    )
    assert verdicts[BACKUP_DIR].reason is Reason.OK
    assert verdicts[BACKUP_DIR].ok is True


def test_the_ssh_key_directory_does_not_need_to_be_writable() -> None:
    """The quadlet mounts /root/.ssh read-only on purpose; keys are read.

    Demanding writability there would report a defect on every healthy
    deploy and bury the real findings.
    """
    verdicts = judge_runtime_paths(
        {SSH_KEY_DIR: _observation("/root/.ssh", exists=True, is_dir=True)}
    )
    assert verdicts[SSH_KEY_DIR].reason is Reason.OK


def test_the_failure_codes_are_pairwise_distinct() -> None:
    """Collapsing "not configured" into "configured but broken" is exactly
    how D2a stayed invisible; the codes must never alias."""
    codes = [
        Reason.NOT_CONFIGURED.value,
        Reason.MISSING.value,
        Reason.NOT_A_DIRECTORY.value,
        Reason.NOT_WRITABLE.value,
        Reason.OK.value,
    ]
    assert len(set(codes)) == len(codes)


def test_an_unknown_role_name_is_loud() -> None:
    """A typo in a role name is a programming error, not a finding."""
    with pytest.raises(KeyError):
        judge_runtime_paths({"printcap_dir": _observation("/etc/printcap")})


# --- the I/O helper gathers facts and nothing else --------------------------


def test_collect_observations_stats_the_paths_the_variables_name(
    tmp_path: Path,
) -> None:
    """The environ mapping is a parameter, so no patching of the world."""
    backups = tmp_path / "backups"
    backups.mkdir()
    ssh_dir = tmp_path / "ssh"
    ssh_dir.mkdir()

    observations = collect_observations(
        {
            "OPNSENSE_BACKUP_DIR": str(backups),
            "OPNSENSE_SSH_KEY": str(ssh_dir / "id_ed25519"),
        }
    )

    assert observations[BACKUP_DIR].configured_path == str(backups)
    assert observations[BACKUP_DIR].exists
    assert observations[BACKUP_DIR].is_dir
    assert observations[BACKUP_DIR].writable

    assert observations[SSH_KEY_DIR].configured_path == str(ssh_dir)


def test_the_ssh_role_checks_the_directory_not_the_key_file() -> None:
    """A key path whose directory does not exist is a missing directory."""
    observations = collect_observations(
        {"OPNSENSE_SSH_KEY": "/opt/containerdata/opnsense-mcp/ssh/id_ed25519"}
    )
    verdicts = judge_runtime_paths(observations)
    assert (
        verdicts[SSH_KEY_DIR].configured_path == "/opt/containerdata/opnsense-mcp/ssh"
    )
    assert verdicts[SSH_KEY_DIR].reason is Reason.MISSING


def test_collect_observations_records_unset_variables_plainly(tmp_path: Path) -> None:
    """Unset, with no default key in ~/.ssh either, is None."""
    observations = collect_observations({"OPNSENSE_SSH_KEY": ""}, home=tmp_path)
    assert observations[SSH_KEY_DIR].configured_path is None


def test_a_leading_tilde_in_the_ssh_key_path_is_expanded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    observations = collect_observations({"OPNSENSE_SSH_KEY": "~/.ssh/id_ed25519"})
    assert observations[SSH_KEY_DIR].configured_path == str(tmp_path / ".ssh")


def test_the_report_covers_every_role_with_structured_fields(tmp_path: Path) -> None:
    """Every entry carries the fields callers assert on; no prose contract."""
    report = runtime_paths_report({}, home=tmp_path)

    assert set(report) == {BACKUP_DIR, SSH_KEY_DIR}
    for entry in report.values():
        assert {
            "role",
            "description",
            "env_var",
            "configured_path",
            "reason",
            "ok",
        } <= set(entry)
        assert entry["description"]
        assert entry["reason"] == Reason.NOT_CONFIGURED.value
        assert entry["ok"] is False


# --- falsification: the deployment-shaped cases, via the system tool --------


@pytest.mark.asyncio
async def test_system_reports_an_unset_backup_dir_as_not_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The original defect, reintroduced: the variable is not set at all.

    The deployed unit left OPNSENSE_BACKUP_DIR unset and
    ``config_backup action=download`` failed with "OPNSENSE_BACKUP_DIR is not
    set". The probe must name that state with its own code and the ``system``
    call must stay a success — reporting is the point, not failing.
    """
    monkeypatch.delenv("OPNSENSE_BACKUP_DIR", raising=False)

    report = runtime_paths_report()
    assert report[BACKUP_DIR]["reason"] == Reason.NOT_CONFIGURED.value
    assert report[BACKUP_DIR]["ok"] is False
    assert report[BACKUP_DIR]["configured_path"] is None

    result = await _system_result()
    assert result["status"] == "success"
    paths = result["mcp_server"]["runtime_paths"]
    assert paths[BACKUP_DIR]["reason"] == Reason.NOT_CONFIGURED.value
    assert paths[BACKUP_DIR]["ok"] is False
    assert paths[BACKUP_DIR]["env_var"] == "OPNSENSE_BACKUP_DIR"
    assert paths[BACKUP_DIR]["configured_path"] is None


@pytest.mark.asyncio
async def test_system_reports_a_missing_backup_dir_with_a_different_code(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Configured, but the bind source was never created (issue #20's shape).

    This is the empty-mount trap: the path is configured and still nothing
    is behind it. It must not be reported as "not configured" — the fixes
    differ, and collapsing the two is how the defect stayed invisible.
    """
    configured = str(tmp_path / "never-created")
    monkeypatch.setenv("OPNSENSE_BACKUP_DIR", configured)

    report = runtime_paths_report()
    assert report[BACKUP_DIR]["reason"] == Reason.MISSING.value
    assert report[BACKUP_DIR]["configured_path"] == configured

    result = await _system_result()
    assert result["status"] == "success"
    paths = result["mcp_server"]["runtime_paths"]
    assert paths[BACKUP_DIR]["reason"] == Reason.MISSING.value
    assert paths[BACKUP_DIR]["reason"] != Reason.NOT_CONFIGURED.value
    assert paths[BACKUP_DIR]["configured_path"] == configured


@pytest.mark.asyncio
async def test_system_reports_a_read_only_backup_dir_with_a_third_code(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Configured and present, but nothing can be written there.

    The install root is mounted ro; a backup directory without its own rw
    mount swaps "not set" for the quieter "cannot write". Staged with real
    permission bits, and skipped as root, where those bits do not hold.
    """
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip(
            "running as root: permission bits do not restrict writes, so the "
            "read-only case cannot be staged here"
        )

    read_only = tmp_path / "backups"
    read_only.mkdir()
    read_only.chmod(0o555)
    try:
        monkeypatch.setenv("OPNSENSE_BACKUP_DIR", str(read_only))

        report = runtime_paths_report()
        assert report[BACKUP_DIR]["reason"] == Reason.NOT_WRITABLE.value

        result = await _system_result()
        assert result["status"] == "success"
        paths = result["mcp_server"]["runtime_paths"]
        assert paths[BACKUP_DIR]["reason"] == Reason.NOT_WRITABLE.value
        assert paths[BACKUP_DIR]["reason"] != Reason.NOT_CONFIGURED.value
        assert paths[BACKUP_DIR]["reason"] != Reason.MISSING.value
        assert paths[BACKUP_DIR]["ok"] is False
    finally:
        read_only.chmod(0o755)


@pytest.mark.asyncio
async def test_system_reports_a_working_backup_dir_as_ok(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The healthy case, so a green report still means something."""
    monkeypatch.setenv("OPNSENSE_BACKUP_DIR", str(tmp_path))

    result = await _system_result()
    assert result["status"] == "success"
    paths = result["mcp_server"]["runtime_paths"]
    assert paths[BACKUP_DIR]["reason"] == Reason.OK.value
    assert paths[BACKUP_DIR]["ok"] is True
    assert paths[BACKUP_DIR]["configured_path"] == str(tmp_path)


@pytest.mark.asyncio
async def test_runtime_paths_join_the_existing_mcp_server_block() -> None:
    """The build block keeps its fields; runtime_paths is added, not swapped."""
    result = await _system_result()

    assert {"name", "package_version", "git_commit", "build_time"} <= set(
        result["mcp_server"]
    )
    assert set(result["mcp_server"]["runtime_paths"]) == {BACKUP_DIR, SSH_KEY_DIR}


# --- the key file and known_hosts, not just the directory (#104) -----------


def _ssh_home(tmp_path: Path, *, key: bool, known_hosts: str | None) -> Path:
    """A home whose ~/.ssh holds what the arguments say, and nothing else."""
    ssh = tmp_path / ".ssh"
    ssh.mkdir()
    if key:
        (ssh / "id_ed25519").write_text("not a real key\n")
    if known_hosts is not None:
        (ssh / "known_hosts").write_text(known_hosts)
    return tmp_path


_FW_KEY = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"


def _verdict(env: dict[str, str], home: Path) -> Reason:
    return judge_runtime_paths(collect_observations(env, home))[SSH_KEY_DIR].reason


def test_an_empty_key_directory_is_not_ok(tmp_path: Path) -> None:
    """Issue #20 shape: the mount exists and is empty. It used to report ok."""
    home = _ssh_home(tmp_path, key=False, known_hosts=None)
    env = {"OPNSENSE_SSH_KEY": str(home / ".ssh" / "id_ed25519")}

    assert _verdict(env, home) is Reason.KEY_MISSING


def test_a_key_without_known_hosts_is_not_ok(tmp_path: Path) -> None:
    home = _ssh_home(tmp_path, key=True, known_hosts=None)
    env = {"OPNSENSE_SSH_KEY": str(home / ".ssh" / "id_ed25519")}

    assert _verdict(env, home) is Reason.KNOWN_HOSTS_MISSING


def test_known_hosts_that_lacks_the_firewall_is_not_ok(tmp_path: Path) -> None:
    home = _ssh_home(
        tmp_path, key=True, known_hosts=f"other.example ssh-ed25519 {_FW_KEY}\n"
    )
    env = {
        "OPNSENSE_SSH_KEY": str(home / ".ssh" / "id_ed25519"),
        "OPNSENSE_FIREWALL_HOST": "fw.example",
    }

    assert _verdict(env, home) is Reason.HOST_NOT_KNOWN


def test_a_non_default_port_needs_the_bracketed_entry(tmp_path: Path) -> None:
    """Off port 22, OpenSSH records [host]:port; either form is accepted."""
    home = _ssh_home(
        tmp_path, key=True, known_hosts=f"[fw.example]:2222 ssh-ed25519 {_FW_KEY}\n"
    )
    env = {
        "OPNSENSE_SSH_KEY": str(home / ".ssh" / "id_ed25519"),
        "OPNSENSE_FIREWALL_HOST": "fw.example",
        "OPNSENSE_SSH_PORT": "2222",
    }

    assert _verdict(env, home) is Reason.OK


def test_a_complete_ssh_setup_is_ok(tmp_path: Path) -> None:
    home = _ssh_home(
        tmp_path, key=True, known_hosts=f"fw.example ssh-ed25519 {_FW_KEY}\n"
    )
    env = {
        "OPNSENSE_SSH_KEY": str(home / ".ssh" / "id_ed25519"),
        "OPNSENSE_FIREWALL_HOST": "fw.example",
    }

    assert _verdict(env, home) is Reason.OK


def test_an_unset_key_variable_falls_back_to_the_default_key(tmp_path: Path) -> None:
    """paramiko finds ~/.ssh/id_ed25519 on its own; not-configured was wrong."""
    home = _ssh_home(
        tmp_path, key=True, known_hosts=f"fw.example ssh-ed25519 {_FW_KEY}\n"
    )
    env = {"OPNSENSE_FIREWALL_HOST": "fw.example"}

    observations = collect_observations(env, home)

    assert observations[SSH_KEY_DIR].configured_path == str(home / ".ssh")
    assert _verdict(env, home) is Reason.OK
