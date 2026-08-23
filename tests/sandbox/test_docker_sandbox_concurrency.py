# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for running two sandbox containers at the same time.

The host driver (:file:`scripts/sandbox/docker_sandbox.py`) used to key every
piece of per-run state on the *test type* rather than on the individual run: a
single ``intellicrack-sandbox-<type>`` container name, one
``reports/tests/_run_spec.json`` holding the pytest argv, one
``_last_exitcode``, one ``test-log.txt``, and report filenames resolved only to
the minute. Two concurrent runs therefore destroyed each other -- the second
run's spec overwrote the first's argv, and ``_remove_stale_container``
force-removed the sibling that was still running.

These tests drive the real derivation functions and the real spec/exit-code
writers; nothing is mocked. Container reaping is exercised against a stub
``docker`` executable placed first on ``PATH``: the stub is a genuine program
that answers ``docker ps`` from an inventory file and records every ``docker
rm`` it receives, so the assertions observe real subprocess behaviour rather
than a stubbed return value. No Docker daemon is contacted and no container is
started, which is what lets this file run inside the sandbox container itself.
"""

from __future__ import annotations

import json
import os
import re
import sys
import textwrap
import time
from pathlib import Path, PureWindowsPath
from typing import TYPE_CHECKING, cast

import pytest

from scripts.sandbox import (
    docker_sandbox,
    reporting,
    test_types as sandbox_test_types,
)
from scripts.sandbox.test_types import (
    TestRunSpec,
    TestType,
    build_pytest_args,
    new_run_id,
    run_token,
    to_pyargs_target,
)


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import PurePosixPath


_DOCKER_MODULE_MEMBERS = vars(docker_sandbox)
_build_docker_run_argv = cast("Callable[..., list[str]]", _DOCKER_MODULE_MEMBERS["_build_docker_run_argv"])
_write_spec_file = cast("Callable[[TestRunSpec], Path]", _DOCKER_MODULE_MEMBERS["_write_spec_file"])
_write_exit_code = cast("Callable[[TestRunSpec, int], Path]", _DOCKER_MODULE_MEMBERS["_write_exit_code"])
_remove_stale_container = cast("Callable[[str], None]", _DOCKER_MODULE_MEMBERS["_remove_stale_container"])
_discard_control_files = cast("Callable[[TestRunSpec], tuple[Path, ...]]", _DOCKER_MODULE_MEMBERS["_discard_control_files"])
_should_retain_control_files = cast("Callable[[int], bool]", _DOCKER_MODULE_MEMBERS["_should_retain_control_files"])
_select_reapable_control_files = cast(
    "Callable[..., tuple[Path, ...]]",
    _DOCKER_MODULE_MEMBERS["_select_reapable_control_files"],
)
_reap_orphaned_control_files = cast("Callable[..., tuple[Path, ...]]", _DOCKER_MODULE_MEMBERS["_reap_orphaned_control_files"])
_select_removable_containers = cast(
    "Callable[..., tuple[str, ...]]",
    _DOCKER_MODULE_MEMBERS["_select_removable_containers"],
)

_TYPES_MODULE_MEMBERS = vars(sandbox_test_types)
_artifact_paths = cast("Callable[[TestRunSpec], dict[str, PurePosixPath]]", _TYPES_MODULE_MEMBERS["_artifact_paths"])

_SHARED_MINUTE = "08-06-2026_14-22"
_DOCKER_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")
_JUNIT_TEMPLATE = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<testsuites><testsuite name="pytest" errors="0" failures="0" skipped="0" '
    'tests="{tests}" time="1.5"></testsuite></testsuites>'
)


def _spec(module: str, *, run_id: str | None = None, timestamp: str = _SHARED_MINUTE) -> TestRunSpec:
    """Build a module-mode run specification.

    Args:
        module: Test path the run targets, for example ``tests/sandbox``.
        run_id: Explicit run identity; a fresh one is generated when omitted.
        timestamp: Artifact timestamp, defaulting to the shared minute used by
            the same-minute collision gates.

    Returns:
        TestRunSpec: The constructed specification.
    """
    if run_id is None:
        return TestRunSpec(test_type=TestType.MODULE, timestamp=timestamp, module=module)
    return TestRunSpec(test_type=TestType.MODULE, timestamp=timestamp, module=module, run_id=run_id)


def _argv_for(spec: TestRunSpec, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Build the real ``docker run`` argv for a spec with only the CLI path stubbed.

    Args:
        spec: The run specification to build an argv for.
        monkeypatch: Fixture used to stub the ``docker`` executable lookup.

    Returns:
        list[str]: The constructed ``docker run`` argument vector.
    """
    monkeypatch.setattr(docker_sandbox, "_docker_binary", lambda: "docker")
    return _build_docker_run_argv(
        spec,
        "intellicrack-sandbox:latest",
        memory="32g",
        cpus="16",
        network="none",
        writable_workspace=False,
        interactive=False,
    )


def _flag_value(argv: list[str], flag: str) -> str:
    """Return the token immediately following ``flag`` in ``argv``.

    Args:
        argv: The ``docker run`` argument vector.
        flag: Flag whose adjacent value is wanted.

    Returns:
        str: The value token that follows the flag.
    """
    return argv[argv.index(flag) + 1]


def _env_value(argv: list[str], key: str) -> str:
    """Return the value of a ``--env KEY=VALUE`` pair in ``argv``.

    Args:
        argv: The ``docker run`` argument vector.
        key: Environment variable name to look up.

    Returns:
        str: The value assigned to ``key``.

    Raises:
        AssertionError: If no ``--env`` pair sets ``key``.
    """
    prefix = f"{key}="
    for index, token in enumerate(argv):
        if token.startswith(prefix) and index > 0 and argv[index - 1] == "--env":
            return token.removeprefix(prefix)
    message = f"{key} is not forwarded as a --env pair; argv={argv!r}"
    raise AssertionError(message)


def _install_stub_docker(
    directory: Path,
    inventory: dict[str, dict[str, object]],
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Place a stub ``docker`` executable first on ``PATH``.

    The stub answers ``docker ps`` from ``inventory`` (a real JSON file holding
    each container's state and whether it carries the sandbox label) and
    appends every ``docker rm`` invocation to a log file, so the caller can see
    exactly which containers the driver decided to remove.

    Args:
        directory: Directory the stub and its state files are written to.
        inventory: Mapping of container name to ``{"state": str, "labeled": bool}``.
        monkeypatch: Fixture used to prepend ``directory`` to ``PATH``.

    Returns:
        Path: The log file the stub appends its ``docker rm`` invocations to.
    """
    directory.mkdir(parents=True, exist_ok=True)
    inventory_path = directory / "inventory.json"
    inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
    rm_log = directory / "docker_rm.log"
    stub_py = directory / "docker_stub.py"
    stub_py.write_text(
        textwrap.dedent(
            f"""\
            import json
            import sys
            from pathlib import Path

            INVENTORY = Path(r"{inventory_path}")
            RM_LOG = Path(r"{rm_log}")


            def main():
                argv = sys.argv[1:]
                if not argv:
                    return 0
                if argv[0] == "rm":
                    with RM_LOG.open("a", encoding="utf-8") as handle:
                        handle.write(" ".join(argv) + "\\n")
                    return 0
                if argv[0] != "ps":
                    return 0
                entries = json.loads(INVENTORY.read_text(encoding="utf-8"))
                filters = [argv[i + 1] for i, tok in enumerate(argv) if tok == "--filter"]
                selected = []
                for name, meta in entries.items():
                    keep = True
                    for flt in filters:
                        if flt.startswith("label="):
                            keep = keep and bool(meta["labeled"])
                        elif flt.startswith("status="):
                            keep = keep and meta["state"] == flt.split("=", 1)[1]
                        elif flt.startswith("name="):
                            keep = keep and flt.split("=", 1)[1] in name
                    if keep:
                        selected.append(name)
                if "-a" not in argv:
                    selected = [n for n in selected if entries[n]["state"] == "running"]
                sys.stdout.write("\\n".join(sorted(selected)))
                return 0


            sys.exit(main())
            """,
        ),
        encoding="utf-8",
    )
    (directory / "docker.cmd").write_text(
        f'@echo off\r\n"{sys.executable}" "{stub_py}" %*\r\nexit /b %ERRORLEVEL%\r\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("PATH", f"{directory}{os.pathsep}{os.environ.get('PATH', '')}")
    return rm_log


def _removed_names(rm_log: Path) -> list[str]:
    """Return the container names the stub Docker CLI was asked to remove.

    Args:
        rm_log: Log file written by the stub Docker CLI.

    Returns:
        list[str]: Container names passed to ``docker rm -f``.
    """
    if not rm_log.is_file():
        return []
    return [line.split()[-1] for line in rm_log.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_default_run_ids_differ_for_two_specs() -> None:
    """Two specs built from identical arguments still get distinct identities."""
    first = _spec("tests/sandbox")
    second = _spec("tests/sandbox")
    assert first.run_id != second.run_id, "identical specs must not share a run identity"
    assert run_token(first) != run_token(second)


def test_run_id_is_filesystem_and_docker_safe() -> None:
    """A generated run id contains only characters valid in names and paths."""
    for _ in range(20):
        candidate = new_run_id()
        assert _DOCKER_NAME_PATTERN.match(candidate), f"run id is not name-safe: {candidate!r}"


def test_concurrent_runs_get_distinct_container_names(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two same-type runs must claim different ``docker run --name`` values.

    Args:
        monkeypatch: Fixture used to stub the ``docker`` executable lookup.
    """
    first = _argv_for(_spec("tests/sandbox"), monkeypatch)
    second = _argv_for(_spec("tests/test_core"), monkeypatch)
    name_a = _flag_value(first, "--name")
    name_b = _flag_value(second, "--name")

    assert name_a != name_b, f"concurrent runs collided on container name {name_a!r}"
    assert _DOCKER_NAME_PATTERN.match(name_a), f"illegal Docker container name: {name_a!r}"
    assert _DOCKER_NAME_PATTERN.match(name_b), f"illegal Docker container name: {name_b!r}"
    assert name_a.startswith("intellicrack-sandbox-"), name_a


def test_container_name_is_stable_within_one_run(monkeypatch: pytest.MonkeyPatch) -> None:
    """Building a run's argv twice yields the same container name.

    Args:
        monkeypatch: Fixture used to stub the ``docker`` executable lookup.
    """
    spec = _spec("tests/sandbox")
    assert _flag_value(_argv_for(spec, monkeypatch), "--name") == docker_sandbox.container_name_for(spec)
    assert docker_sandbox.container_name_for(spec) == docker_sandbox.container_name_for(spec)


def test_concurrent_runs_get_distinct_container_spec_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    """``SANDBOX_SPEC_PATH`` must address a different file for each run.

    Args:
        monkeypatch: Fixture used to stub the ``docker`` executable lookup.
    """
    spec_a = _spec("tests/sandbox")
    spec_b = _spec("tests/test_core")
    path_a = _env_value(_argv_for(spec_a, monkeypatch), "SANDBOX_SPEC_PATH")
    path_b = _env_value(_argv_for(spec_b, monkeypatch), "SANDBOX_SPEC_PATH")

    assert path_a != path_b, f"concurrent runs collided on spec path {path_a!r}"
    assert path_a == docker_sandbox.container_spec_path(spec_a)
    assert path_b == docker_sandbox.container_spec_path(spec_b)
    assert PureWindowsPath(path_a).name == docker_sandbox.host_spec_path(spec_a).name


def test_concurrent_runs_get_distinct_container_exit_code_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    """``SANDBOX_EXITCODE_PATH`` must address a different file for each run.

    Args:
        monkeypatch: Fixture used to stub the ``docker`` executable lookup.
    """
    spec_a = _spec("tests/sandbox")
    spec_b = _spec("tests/test_core")
    path_a = _env_value(_argv_for(spec_a, monkeypatch), "SANDBOX_EXITCODE_PATH")
    path_b = _env_value(_argv_for(spec_b, monkeypatch), "SANDBOX_EXITCODE_PATH")

    assert path_a != path_b, f"concurrent runs collided on exit-code path {path_a!r}"
    assert PureWindowsPath(path_a).name == docker_sandbox.host_exit_code_path(spec_a).name
    assert PureWindowsPath(path_b).name == docker_sandbox.host_exit_code_path(spec_b).name


def test_run_id_is_forwarded_to_the_container(monkeypatch: pytest.MonkeyPatch) -> None:
    """The container receives the run identity used to name its artifacts.

    Args:
        monkeypatch: Fixture used to stub the ``docker`` executable lookup.
    """
    spec = _spec("tests/sandbox")
    assert _env_value(_argv_for(spec, monkeypatch), "SANDBOX_RUN_ID") == spec.run_id


def test_both_spec_files_survive_with_their_own_pytest_argv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two runs writing their specs must each keep their own pytest argv.

    This is the exact failure the single ``_run_spec.json`` produced: the
    second run overwrote the first's argv, so a container executed a command
    line nobody launched. Both files must exist afterwards and each must carry
    only its own module target.

    Args:
        tmp_path: Pytest-provided temporary directory used as the reports root.
        monkeypatch: Fixture used to redirect the reports root.
    """
    monkeypatch.setattr(docker_sandbox, "_REPORTS_ROOT", tmp_path)
    spec_a = _spec("tests/sandbox")
    spec_b = _spec("tests/test_core")

    path_a = _write_spec_file(spec_a)
    path_b = _write_spec_file(spec_b)

    assert path_a != path_b, f"both runs wrote the same spec file {path_a}"
    assert path_a.is_file(), "the first run's spec file did not survive the second run"
    assert path_b.is_file()

    payload_a = json.loads(path_a.read_text(encoding="utf-8"))
    payload_b = json.loads(path_b.read_text(encoding="utf-8"))
    argv_a = list(payload_a["pytest_args"])
    argv_b = list(payload_b["pytest_args"])

    target_a = to_pyargs_target("tests/sandbox")
    target_b = to_pyargs_target("tests/test_core")
    assert target_a in argv_a, f"first run lost its own argv: {argv_a!r}"
    assert target_b not in argv_a, f"first run picked up the second run's argv: {argv_a!r}"
    assert target_b in argv_b, f"second run lost its own argv: {argv_b!r}"
    assert target_a not in argv_b, f"second run picked up the first run's argv: {argv_b!r}"
    assert payload_a["run_id"] == spec_a.run_id
    assert payload_b["run_id"] == spec_b.run_id


def test_both_exit_code_files_survive_with_their_own_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each run must record its own exit code without clobbering a sibling.

    Args:
        tmp_path: Pytest-provided temporary directory used as the reports root.
        monkeypatch: Fixture used to redirect the reports root.
    """
    monkeypatch.setattr(docker_sandbox, "_REPORTS_ROOT", tmp_path)
    spec_a = _spec("tests/sandbox")
    spec_b = _spec("tests/test_core")

    path_a = _write_exit_code(spec_a, 0)
    path_b = _write_exit_code(spec_b, 7)

    assert path_a != path_b, f"both runs wrote the same exit-code file {path_a}"
    assert path_a.read_text(encoding="utf-8") == "0", "the first run's exit code was overwritten"
    assert path_b.read_text(encoding="utf-8") == "7"


def test_same_minute_runs_produce_distinct_artifact_paths() -> None:
    """Runs sharing a timestamp to the minute must not share artifact names."""
    spec_a = _spec("tests/sandbox", timestamp=_SHARED_MINUTE)
    spec_b = _spec("tests/test_core", timestamp=_SHARED_MINUTE)
    assert spec_a.timestamp == spec_b.timestamp

    paths_a = _artifact_paths(spec_a)
    paths_b = _artifact_paths(spec_b)

    for kind in ("junit", "coverage_xml", "coverage_html", "html_report", "summary", "bench", "log"):
        assert paths_a[kind] != paths_b[kind], f"same-minute runs collided on the {kind} artifact"
    assert paths_a["shared_log"] == paths_b["shared_log"], "the aggregate history stays one shared file"


def test_same_minute_runs_get_distinct_pytest_report_arguments() -> None:
    """The pytest argv itself must point each run at its own report files."""
    spec_a = _spec("tests/sandbox", timestamp=_SHARED_MINUTE)
    spec_b = _spec("tests/test_core", timestamp=_SHARED_MINUTE)

    junit_a = next(arg for arg in build_pytest_args(spec_a) if arg.startswith("--junitxml="))
    junit_b = next(arg for arg in build_pytest_args(spec_b) if arg.startswith("--junitxml="))
    html_a = next(arg for arg in build_pytest_args(spec_a) if arg.startswith("--html="))
    html_b = next(arg for arg in build_pytest_args(spec_b) if arg.startswith("--html="))

    assert junit_a != junit_b, f"same-minute runs share a JUnit path: {junit_a}"
    assert html_a != html_b, f"same-minute runs share an HTML report path: {html_a}"
    assert spec_a.run_id in junit_a
    assert spec_b.run_id in junit_b


def test_same_minute_runs_get_distinct_run_logs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Each run gets its own container log while sharing one aggregate history.

    Args:
        tmp_path: Pytest-provided temporary directory used as the reports root.
        monkeypatch: Fixture used to redirect the reports root.
    """
    monkeypatch.setattr(reporting, "_REPORTS_ROOT", tmp_path)
    log_a = reporting.run_log_path(TestType.MODULE.value, _SHARED_MINUTE, "p1-aaaaaa")
    log_b = reporting.run_log_path(TestType.MODULE.value, _SHARED_MINUTE, "p2-bbbbbb")

    assert log_a != log_b, f"same-minute runs share a container log: {log_a}"
    assert log_a != reporting.shared_log_path()
    assert log_b != reporting.shared_log_path()


def test_aggregate_history_keeps_both_runs_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Folding per-run logs into ``test-log.txt`` must lose neither run's output.

    Args:
        tmp_path: Pytest-provided temporary directory used as the reports root.
        monkeypatch: Fixture used to redirect the reports root.
    """
    monkeypatch.setattr(reporting, "_REPORTS_ROOT", tmp_path)
    log_a = reporting.run_log_path(TestType.MODULE.value, _SHARED_MINUTE, "p1-aaaaaa")
    log_b = reporting.run_log_path(TestType.MODULE.value, _SHARED_MINUTE, "p2-bbbbbb")
    log_a.parent.mkdir(parents=True, exist_ok=True)
    log_a.write_text("RUN A: 3 passed\n", encoding="utf-8")
    log_b.write_text("RUN B: 7 passed\n", encoding="utf-8")

    assert reporting.merge_run_log_into_shared(log_a) is True
    assert reporting.merge_run_log_into_shared(log_b) is True

    aggregate_path = reporting.shared_log_path()
    assert aggregate_path.is_file(), "the aggregate test-log.txt history was never written"
    aggregate = aggregate_path.read_text(encoding="utf-8")
    assert "RUN A: 3 passed" in aggregate, "the first run's output was lost from the aggregate history"
    assert "RUN B: 7 passed" in aggregate, "the second run's output was lost from the aggregate history"


def test_harvest_reads_each_concurrent_runs_own_junit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Report harvesting must attribute each run the counts it actually produced.

    Args:
        tmp_path: Pytest-provided temporary directory used as the reports root.
        monkeypatch: Fixture used to redirect the reports root.
    """
    monkeypatch.setattr(reporting, "_REPORTS_ROOT", tmp_path)
    run_a = "p1-aaaaaa"
    run_b = "p2-bbbbbb"
    suffix_a = reporting.artifact_suffix(TestType.MODULE.value, _SHARED_MINUTE, run_a)
    suffix_b = reporting.artifact_suffix(TestType.MODULE.value, _SHARED_MINUTE, run_b)
    assert suffix_a != suffix_b, f"same-minute runs share the artifact suffix {suffix_a!r}"
    (tmp_path / f"junit_{suffix_a}.xml").write_text(_JUNIT_TEMPLATE.format(tests=3), encoding="utf-8")
    (tmp_path / f"junit_{suffix_b}.xml").write_text(_JUNIT_TEMPLATE.format(tests=7), encoding="utf-8")

    record_a = reporting.harvest_reports(TestType.MODULE, _SHARED_MINUTE, 0, run_id=run_a)
    record_b = reporting.harvest_reports(TestType.MODULE, _SHARED_MINUTE, 0, run_id=run_b)

    assert record_a.counts.tests == 3, f"run A harvested another run's JUnit: {record_a.counts}"
    assert record_b.counts.tests == 7, f"run B harvested another run's JUnit: {record_b.counts}"
    assert record_a.run_id == run_a
    assert record_b.run_id == run_b


def _write_control_files(spec: TestRunSpec, exit_code: int) -> tuple[Path, Path]:
    """Write a run's spec and exit-code files through the real writers.

    Args:
        spec: The run whose control files are written.
        exit_code: Exit code to record for the run.

    Returns:
        tuple[Path, Path]: The spec path and the exit-code path.
    """
    return _write_spec_file(spec), _write_exit_code(spec, exit_code)


def _age_file(path: Path, seconds: float) -> None:
    """Backdate a real file's modification time.

    Args:
        path: File to backdate.
        seconds: How far into the past to move its mtime.
    """
    stamp = path.stat().st_mtime - seconds
    os.utime(path, (stamp, stamp))


def test_completed_run_discards_its_own_control_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A finished run must not leave its ephemeral control files behind.

    Args:
        tmp_path: Pytest-provided temporary directory used as the reports root.
        monkeypatch: Fixture used to redirect the reports root.
    """
    monkeypatch.setattr(docker_sandbox, "_REPORTS_ROOT", tmp_path)
    spec = _spec("tests/sandbox")
    spec_path, exit_path = _write_control_files(spec, 0)
    assert spec_path.is_file()
    assert exit_path.is_file()

    _discard_control_files(spec)

    assert not spec_path.exists(), "a completed run left its spec file behind"
    assert not exit_path.exists(), "a completed run left its exit-code file behind"


def test_discarding_one_run_leaves_a_concurrent_siblings_control_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cleaning up one run must never touch a sibling that is still running.

    Args:
        tmp_path: Pytest-provided temporary directory used as the reports root.
        monkeypatch: Fixture used to redirect the reports root.
    """
    monkeypatch.setattr(docker_sandbox, "_REPORTS_ROOT", tmp_path)
    finished = _spec("tests/sandbox")
    sibling = _spec("tests/test_core")
    finished_spec, finished_exit = _write_control_files(finished, 0)
    sibling_spec, sibling_exit = _write_control_files(sibling, 0)

    _discard_control_files(finished)

    assert not finished_spec.exists()
    assert not finished_exit.exists()
    assert sibling_spec.is_file(), "cleanup deleted a concurrently running sibling's spec file"
    assert sibling_exit.is_file(), "cleanup deleted a concurrently running sibling's exit-code file"
    assert to_pyargs_target("tests/test_core") in json.loads(sibling_spec.read_text(encoding="utf-8"))["pytest_args"]


def test_control_files_survive_a_failed_run_and_vanish_after_a_clean_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only a clean run discards its control files; a failure keeps them for diagnosis.

    Args:
        tmp_path: Pytest-provided temporary directory used as the reports root.
        monkeypatch: Fixture used to redirect the reports root.
    """
    monkeypatch.setattr(docker_sandbox, "_REPORTS_ROOT", tmp_path)
    for exit_code, must_survive in ((0, False), (1, True), (124, True)):
        spec = _spec("tests/sandbox")
        spec_path, exit_path = _write_control_files(spec, exit_code)
        if not _should_retain_control_files(exit_code):
            _discard_control_files(spec)
        assert spec_path.exists() is must_survive, f"exit {exit_code}: spec survival should be {must_survive}"
        assert exit_path.exists() is must_survive, f"exit {exit_code}: exit-code survival should be {must_survive}"


def test_reaper_spares_live_and_recent_control_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The age reaper removes only stale files belonging to no live run.

    Covers the race that makes an age floor necessary: a run writes its spec
    before ``docker run`` creates the container that marks its token live, so a
    freshly written file must survive even though no container claims it yet.

    Args:
        tmp_path: Pytest-provided temporary directory used as the reports root.
        monkeypatch: Fixture used to redirect the reports root.
    """
    monkeypatch.setattr(docker_sandbox, "_REPORTS_ROOT", tmp_path)
    own = _spec("tests/sandbox", run_id="p1-aaaaaa")
    live = _spec("tests/test_core", run_id="p2-bbbbbb")
    just_written = _spec("tests/test_bridges", run_id="p3-cccccc")
    orphan = _spec("tests/test_ui", run_id="p4-dddddd")
    for spec in (own, live, just_written, orphan):
        _write_control_files(spec, 0)
    for spec in (own, live, orphan):
        _age_file(docker_sandbox.host_spec_path(spec), 172800.0)
        _age_file(docker_sandbox.host_exit_code_path(spec), 172800.0)
    junit = tmp_path / f"junit_{run_token(orphan)}.xml"
    junit.write_text("<testsuites/>", encoding="utf-8")
    _age_file(junit, 172800.0)

    targets = _select_reapable_control_files(
        tmp_path.iterdir(),
        frozenset({run_token(live)}),
        own_token=run_token(own),
        now=time.time(),
        retention_seconds=86400.0,
    )

    assert junit not in targets, "the reaper targeted a report artifact"
    assert docker_sandbox.host_spec_path(orphan) in targets, f"a stale orphan was not reaped: {targets!r}"
    assert docker_sandbox.host_exit_code_path(orphan) in targets
    assert docker_sandbox.host_spec_path(live) not in targets, "the reaper targeted a live sibling's spec file"
    assert docker_sandbox.host_spec_path(own) not in targets, "the reaper targeted this run's own spec file"
    assert docker_sandbox.host_spec_path(just_written) not in targets, "the reaper targeted a freshly written spec file"


@pytest.mark.skipif(sys.platform != "win32", reason="drives a Windows .cmd stub for the Windows container driver")
def test_reaper_derives_live_runs_from_running_containers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End to end, the reaper spares files whose container Docker reports running.

    Args:
        tmp_path: Pytest-provided temporary directory holding reports and the stub CLI.
        monkeypatch: Fixture used to redirect the reports root and stub ``docker``.
    """
    reports = tmp_path / "reports"
    reports.mkdir()
    monkeypatch.setattr(docker_sandbox, "_REPORTS_ROOT", reports)
    own = _spec("tests/sandbox", run_id="p1-aaaaaa")
    live = _spec("tests/test_core", run_id="p2-bbbbbb")
    orphan = _spec("tests/test_ui", run_id="p4-dddddd")
    for spec in (own, live, orphan):
        _write_control_files(spec, 0)
        _age_file(docker_sandbox.host_spec_path(spec), 172800.0)
        _age_file(docker_sandbox.host_exit_code_path(spec), 172800.0)
    _install_stub_docker(
        tmp_path / "bin",
        {docker_sandbox.container_name_for(live): {"state": "running", "labeled": True}},
        monkeypatch,
    )

    removed = _reap_orphaned_control_files(own_token=run_token(own))

    assert docker_sandbox.host_spec_path(orphan) in removed, f"the stale orphan was not reaped: {removed!r}"
    assert not docker_sandbox.host_spec_path(orphan).exists()
    assert docker_sandbox.host_spec_path(live).is_file(), "the reaper deleted a running sibling's spec file"
    assert docker_sandbox.host_spec_path(own).is_file(), "the reaper deleted this run's own spec file"


def test_selection_never_targets_a_running_sibling() -> None:
    """A container Docker reports as running is never selected for removal."""
    sibling = "intellicrack-sandbox-module_08-06-2026_14-22_p999-ffffff"
    orphan = "intellicrack-sandbox-module_08-05-2026_09-01_p111-000000"
    own = "intellicrack-sandbox-module_08-06-2026_14-22_p222-111111"

    targets = _select_removable_containers(
        frozenset({orphan}),
        frozenset({sibling}),
        own_name=own,
        own_exists=False,
    )

    assert sibling not in targets, f"a live sibling was selected for removal: {targets!r}"
    assert targets == (orphan,), f"the orphan must still be reaped: {targets!r}"


def test_selection_includes_own_name_even_when_running() -> None:
    """This run's own name is reaped regardless of the state Docker reports."""
    own = "intellicrack-sandbox-module_08-06-2026_14-22_p222-111111"

    targets = _select_removable_containers(
        frozenset(),
        frozenset({own}),
        own_name=own,
        own_exists=True,
    )

    assert targets == (own,), f"an existing container under this run's own name must be removed: {targets!r}"


@pytest.mark.skipif(sys.platform != "win32", reason="drives a Windows .cmd stub for the Windows container driver")
def test_cleanup_spares_a_live_sibling_and_reaps_an_orphan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real cleanup must leave a running sibling alone and still reap leftovers.

    A stub ``docker`` on ``PATH`` reports one running sibling container, one
    exited orphan, and one unrelated running image. The driver must issue
    ``docker rm -f`` for the orphan only.

    Args:
        tmp_path: Pytest-provided temporary directory holding the stub CLI.
        monkeypatch: Fixture used to prepend the stub directory to ``PATH``.
    """
    sibling = "intellicrack-sandbox-module_08-06-2026_14-22_p999-ffffff"
    orphan = "intellicrack-sandbox-module_08-05-2026_09-01_p111-000000"
    unrelated = "some-other-project-container"
    own = "intellicrack-sandbox-module_08-06-2026_14-22_p222-111111"
    rm_log = _install_stub_docker(
        tmp_path,
        {
            sibling: {"state": "running", "labeled": True},
            orphan: {"state": "exited", "labeled": True},
            unrelated: {"state": "exited", "labeled": False},
        },
        monkeypatch,
    )

    _remove_stale_container(own)

    removed = _removed_names(rm_log)
    assert sibling not in removed, f"cleanup killed a concurrently running sibling; removed={removed!r}"
    assert unrelated not in removed, f"cleanup removed an unlabeled foreign container; removed={removed!r}"
    assert orphan in removed, f"a genuinely orphaned container was not reaped; removed={removed!r}"


@pytest.mark.skipif(sys.platform != "win32", reason="drives a Windows .cmd stub for the Windows container driver")
def test_cleanup_reaps_a_leftover_under_its_own_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A leftover container holding this run's own name is still force-removed.

    Args:
        tmp_path: Pytest-provided temporary directory holding the stub CLI.
        monkeypatch: Fixture used to prepend the stub directory to ``PATH``.
    """
    own = "intellicrack-sandbox-module_08-06-2026_14-22_p222-111111"
    sibling = "intellicrack-sandbox-module_08-06-2026_14-22_p999-ffffff"
    rm_log = _install_stub_docker(
        tmp_path,
        {
            own: {"state": "created", "labeled": True},
            sibling: {"state": "running", "labeled": True},
        },
        monkeypatch,
    )

    _remove_stale_container(own)

    removed = _removed_names(rm_log)
    assert own in removed, f"a leftover under this run's own name must be removed; removed={removed!r}"
    assert sibling not in removed, f"cleanup killed a concurrently running sibling; removed={removed!r}"
