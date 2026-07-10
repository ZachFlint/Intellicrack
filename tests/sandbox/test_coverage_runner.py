# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for the isolated coverage runner (docker/coverage_runner.py).

The runner replaced a PowerShell scheduler whose ``Start-Sleep`` poll-loop
watchdog was starved by a runaway group and whose ``taskkill /T`` could not
reap orphaned descendants, letting a single hung test group run for over four
hours. These tests exercise the real runner process against synthetic test
trees and assert the two properties that make it reliable:

* a group that hangs forever is force-killed at ``--group-timeout`` (the
  timeout is a kernel wait, not a poll loop, so CPU starvation cannot defeat
  it) and the whole run still completes promptly; and
* every process the hung group spawned is dead afterwards (a Windows Job Object
  reaps the entire subtree, including grandchildren the parent orphaned).

Each test drives the actual ``coverage_runner.py`` CLI as a subprocess, so it
validates the real end-to-end path used by the container entrypoint rather than
an in-process approximation. If the kernel-wait timeout or Job-Object kill
regresses, the hang test either exceeds its own harness timeout (loud failure)
or leaves a live child process (asserted dead).
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import psutil
import pytest


_REPO_ROOT = Path(__file__).resolve().parents[2]
_RUNNER = _REPO_ROOT / "docker" / "coverage_runner.py"

# Generous ceiling for the whole runner invocation. A working runner finishes a
# tiny synthetic suite in well under this even with an 8 s per-group timeout; a
# regressed watchdog that fails to kill the hang blows past it and fails loudly.
_RUN_HARNESS_TIMEOUT_SEC = 180.0
_GROUP_TIMEOUT_SEC = 8


def _best_effort_kill(pid: int) -> None:
    """Kill a process if it still exists, tolerating a race with its exit.

    Args:
        pid: Process id to terminate.
    """
    if not psutil.pid_exists(pid):
        return
    try:
        psutil.Process(pid).kill()
    except psutil.Error:
        return


def _write(path: Path, content: str) -> None:
    """Write ``content`` to ``path``, creating parent directories.

    Args:
        path: Destination file path.
        content: Text to write (UTF-8).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _run_runner(
    args: list[str],
    *,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Invoke the coverage runner CLI as a subprocess.

    Args:
        args: Arguments appended after the runner script path.
        env: Optional environment overrides merged over the current environment.

    Returns:
        subprocess.CompletedProcess[str]: The completed runner process.
    """
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    return subprocess.run(
        [sys.executable, str(_RUNNER), *args],
        capture_output=True,
        text=True,
        cwd=str(_REPO_ROOT),
        env=full_env,
        timeout=_RUN_HARNESS_TIMEOUT_SEC,
        check=False,
    )


def test_runner_script_exists() -> None:
    """The coverage runner script must be present on disk."""
    assert _RUNNER.is_file(), f"missing coverage runner: {_RUNNER}"


def test_list_groups_enumerates_leaf_dirs_and_ignores_children(tmp_path: Path) -> None:
    """``--list-groups`` yields one group per leaf dir and ignores test children.

    A parent that holds both loose ``test_*.py`` files and a test-bearing
    subdirectory must produce two groups, and the parent must ``--ignore`` the
    child so no test is measured twice. ``__pycache__`` and dot-directories must
    never appear as ignores. Breaking the ignore logic (e.g. dropping the child
    exclusion) makes the parent's ignore set miss the child and fails this gate.
    """
    root = tmp_path / "tests"
    _write(root / "test_top.py", "def test_top() -> None:\n    assert True\n")
    _write(root / "child" / "test_child.py", "def test_child() -> None:\n    assert True\n")
    _write(root / "leaf" / "test_leaf.py", "def test_leaf() -> None:\n    assert True\n")
    (root / "__pycache__").mkdir()
    (root / ".hidden").mkdir()

    result = _run_runner(["--tests-root", str(root), "--list-groups"])
    assert result.returncode == 0, f"list-groups failed: {result.stderr}"

    groups: dict[str, tuple[str, ...]] = {}
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        name, _target, ignore_blob = line.split("\t")
        groups[name] = tuple(part for part in ignore_blob.split(";") if part)

    assert set(groups) == {"_root", "child", "leaf"}, f"unexpected groups: {sorted(groups)}"

    root_ignores = {Path(p).resolve() for p in groups["_root"]}
    assert (root / "child").resolve() in root_ignores, "root group must ignore its test-bearing child"
    assert (root / "leaf").resolve() in root_ignores, "root group must ignore its test-bearing leaf child"
    assert (root / "__pycache__").resolve() not in root_ignores, "__pycache__ must never be an ignore"
    assert (root / ".hidden").resolve() not in root_ignores, "dot-directories must never be an ignore"
    assert groups["child"] == (), "a leaf group has no test children to ignore"


def test_hanging_group_is_bounded_and_its_children_are_reaped(tmp_path: Path) -> None:
    """A group that hangs forever is killed at the timeout and its tree reaped.

    The ``hang`` group spawns a long-lived grandchild (recording its PID) then
    sleeps far past the per-group timeout. The runner must force-kill the group
    at ``--group-timeout`` and complete the whole run within the harness
    timeout, while the sibling ``quick`` group passes and appears in the merged
    JUnit. Critically, the grandchild spawned by the hung group must be dead
    afterwards -- the Job Object reaps it even though ``taskkill``/parent-walking
    would miss it.

    Falsifiability: if the kernel-wait timeout regresses to a starvable loop the
    run exceeds ``_RUN_HARNESS_TIMEOUT_SEC`` and ``subprocess.run`` raises; if
    the Job-Object kill regresses the recorded child PID stays alive and the
    final assertion fails.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    root = tmp_path / "tests"
    pidfile = tmp_path / "grandchild.pid"
    hang_body = (
        "import os\n"
        "import subprocess\n"
        "import sys\n"
        "import time\n"
        "_child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(600)'])\n"
        "with open(os.environ['IC_HANG_PIDFILE'], 'w', encoding='utf-8') as _f:\n"
        "    _f.write(str(_child.pid))\n"
        "def test_hang() -> None:\n"
        "    time.sleep(600)\n"
    )
    _write(root / "hang" / "test_hang.py", hang_body)
    _write(root / "quick" / "test_quick.py", "def test_quick() -> None:\n    assert 2 + 2 == 4\n")

    junit_out = tmp_path / "merged_junit.xml"
    result = _run_runner(
        [
            "--tests-root",
            str(root),
            "--workspace-root",
            str(tmp_path),
            "--reports-root",
            str(tmp_path / "reports"),
            "--combine-dir",
            str(tmp_path / "combine"),
            "--junit-out",
            str(junit_out),
            "--coverage-xml",
            str(tmp_path / "cov.xml"),
            "--coverage-html",
            str(tmp_path / "covhtml"),
            "--log",
            str(tmp_path / "log.txt"),
            "--timestamp",
            "t",
            "--jobs",
            "2",
            "--group-timeout",
            str(_GROUP_TIMEOUT_SEC),
            "--fail-under",
            "0",
        ],
        env={"IC_HANG_PIDFILE": str(pidfile)},
    )

    # The hung group must be reported as a failure (exit 124) and the run must
    # have completed (subprocess.run did not raise TimeoutExpired).
    assert "FAILED GROUPS" in result.stdout, f"expected a failed group; stdout={result.stdout}"
    assert "hang=124" in result.stdout, f"hang group must time out with 124; stdout={result.stdout}"
    assert result.returncode == 1, f"a failed group must make the run exit 1; got {result.returncode}"

    # The passing sibling ran concurrently and its suite is in the merged JUnit.
    assert junit_out.is_file(), "merged JUnit report must be produced"
    merged = junit_out.read_text(encoding="utf-8")
    assert "<testsuites" in merged, "merged report must be wrapped in a <testsuites> root"
    assert "test_quick" in merged, "the passing sibling group must appear in the merged JUnit"

    # The grandchild the hung group spawned must have been reaped by the job.
    assert pidfile.is_file(), "hang group never recorded its grandchild PID"
    child_pid = int(pidfile.read_text(encoding="utf-8").strip())
    deadline = time.monotonic() + 15
    while psutil.pid_exists(child_pid) and time.monotonic() < deadline:
        time.sleep(0.2)
    if psutil.pid_exists(child_pid):
        _best_effort_kill(child_pid)
        pytest.fail(f"orphaned grandchild pid {child_pid} survived the group kill")


def test_passing_group_produces_merged_reports(tmp_path: Path) -> None:
    """A passing group yields exit 0, a merged JUnit, and a coverage XML.

    This gates the reporting plumbing: JUnit merge, ``coverage combine`` over
    the per-group shard, and the ``--fail-under`` gate. The group's test imports
    a real ``src/intellicrack`` module so genuine coverage data is produced;
    with the repository as workspace and ``--fail-under 0`` the run must exit 0
    and write both report artifacts. If merge or the coverage pipeline
    regresses, the artifacts are missing or malformed and the assertions fail.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    src_path = _REPO_ROOT / "src"
    ok_body = (
        "import sys\n"
        f"sys.path.insert(0, r'{src_path}')\n"
        "from intellicrack.core import types as _types\n"
        "def test_ok() -> None:\n"
        "    assert _types is not None\n"
    )
    root = tmp_path / "tests"
    _write(root / "ok" / "test_ok.py", ok_body)

    junit_out = tmp_path / "merged_junit.xml"
    coverage_xml = tmp_path / "cov.xml"
    result = _run_runner(
        [
            "--tests-root",
            str(root),
            "--workspace-root",
            str(_REPO_ROOT),
            "--reports-root",
            str(tmp_path / "reports"),
            "--combine-dir",
            str(tmp_path / "combine"),
            "--junit-out",
            str(junit_out),
            "--coverage-xml",
            str(coverage_xml),
            "--coverage-html",
            str(tmp_path / "covhtml"),
            "--log",
            str(tmp_path / "log.txt"),
            "--timestamp",
            "t",
            "--jobs",
            "1",
            "--group-timeout",
            "120",
            "--fail-under",
            "0",
        ],
    )

    assert result.returncode == 0, f"passing group must exit 0; stdout={result.stdout} stderr={result.stderr}"
    assert junit_out.is_file(), "merged JUnit report must be produced"
    assert "test_ok" in junit_out.read_text(encoding="utf-8"), "merged JUnit must contain the passing test"
    assert coverage_xml.is_file(), "coverage XML must be produced"
