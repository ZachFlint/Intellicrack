# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Isolated per-directory coverage runner with bulletproof process control.

Runs one ``pytest`` process per *leaf* test directory (a directory that
directly contains one or more ``test_*.py`` files, excluding its own
subdirectories which are visited as their own groups). Process isolation stops
a native subsystem's teardown (Frida, Ghidra/JPype, Qt) in one group from
poisoning the interpreter state of an unrelated group.

Two reliability guarantees distinguish this runner from the previous
PowerShell orchestrator, which failed in production and let a single hung
group run for ~15 000 s:

* **Kernel-wait timeouts.** Each group's deadline is enforced by
  ``Popen.wait(timeout=...)`` -- a kernel wait object -- not a Python poll
  loop. A runaway group that pegs every CPU cannot starve the watchdog,
  because the watchdog is the OS scheduler, not a ``Start-Sleep`` loop.
* **Job-Object tree kill.** On timeout the entire process subtree is
  terminated via a Windows Job Object (``TerminateJobObject``), which reaps
  grandchildren orphaned by an intermediate parent's exit. ``taskkill /T`` and
  parent-walking (``psutil.children``) both miss orphaned descendants; a Job
  Object cannot, because job membership is inherited and inescapable.

Coverage data is written to a private per-group parallel data file so
concurrent groups never race a shared writer; the shards are merged with
``coverage combine`` and a single 95 % gate is applied to the whole suite.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar
from xml.etree import ElementTree as ET

import psutil
from defusedxml import ElementTree as DefusedET


# Declared as a plain ``bool`` (not ``Final``) so the type checker does not
# constant-fold ``sys.platform == "win32"`` to a literal ``True`` on Windows
# hosts, which would flag the non-Windows guard branches as unreachable while
# still leaving them essential for the non-Windows CI runtime.
_IS_WINDOWS: bool = sys.platform == "win32"


# ---------------------------------------------------------------------------
# Windows Job Object interop
# ---------------------------------------------------------------------------
# A Job Object is the only Windows mechanism that terminates a process and
# every descendant it spawned regardless of reparenting. We create one job per
# group, assign the group's pytest process to it immediately after launch, and
# terminate the whole job on timeout.
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: int = 0x2000
_JOBOBJECT_EXTENDED_LIMIT_INFORMATION_CLASS: int = 9
_PROCESS_TERMINATE: int = 0x0001
_PROCESS_SET_QUOTA: int = 0x0100

_EXIT_TIMEOUT: int = 124
_EXIT_NO_TESTS: int = 5


if sys.platform == "win32":
    _kernel32: ctypes.WinDLL = ctypes.WinDLL("kernel32", use_last_error=True)

    _kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    _kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]

    _kernel32.SetInformationJobObject.restype = wintypes.BOOL
    _kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]

    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

    _kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    _kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]

    _kernel32.TerminateJobObject.restype = wintypes.BOOL
    _kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]

    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]


class _JobBasicLimitInformation(ctypes.Structure):
    """Layout of ``JOBOBJECT_BASIC_LIMIT_INFORMATION`` (winnt.h)."""

    _fields_: ClassVar = [
        ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
        ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _IoCounters(ctypes.Structure):
    """Layout of ``IO_COUNTERS`` (winnt.h)."""

    _fields_: ClassVar = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class _JobExtendedLimitInformation(ctypes.Structure):
    """Layout of ``JOBOBJECT_EXTENDED_LIMIT_INFORMATION`` (winnt.h)."""

    _fields_: ClassVar = [
        ("BasicLimitInformation", _JobBasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


def _kill_process_tree(pid: int, timeout: float = 10.0) -> None:
    """Force-kill a process and every descendant reachable by parent links.

    This is the cross-platform fallback used when a Job Object could not be
    created or the target process was never assigned to one. It cannot reach
    descendants orphaned by an intermediate parent's exit (only a Job Object
    can), so it is a belt-and-suspenders complement to the job kill rather
    than the primary mechanism on Windows.

    Args:
        pid: Process id of the subtree root.
        timeout: Seconds to wait for the killed processes to disappear.
    """
    try:
        root = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return
    try:
        victims = root.children(recursive=True)
    except psutil.NoSuchProcess:
        victims = []
    victims.append(root)
    for victim in victims:
        try:
            victim.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    psutil.wait_procs(victims, timeout=timeout)


def _create_job() -> int | None:
    """Create a kill-on-close Windows Job Object.

    Returns:
        int | None: The job handle as an integer, or ``None`` on a non-Windows
        host or if the job could not be created.
    """
    if not _IS_WINDOWS:
        return None
    handle: int | None = _kernel32.CreateJobObjectW(None, None)
    if not handle:
        return None
    info = _JobExtendedLimitInformation()
    info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    ok: int = _kernel32.SetInformationJobObject(
        handle,
        _JOBOBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
        ctypes.byref(info),
        ctypes.sizeof(info),
    )
    if not ok:
        _kernel32.CloseHandle(handle)
        return None
    return handle


def _assign_to_job(job: int, pid: int) -> bool:
    """Assign a process to a Job Object so its subtree can be killed wholesale.

    Args:
        job: Job handle returned by :func:`_create_job`.
        pid: Process id to assign.

    Returns:
        bool: ``True`` if the process was assigned to the job.
    """
    if not _IS_WINDOWS:
        return False
    inherit_handles = 0
    process: int | None = _kernel32.OpenProcess(
        _PROCESS_SET_QUOTA | _PROCESS_TERMINATE,
        inherit_handles,
        pid,
    )
    if not process:
        return False
    try:
        assigned: int = _kernel32.AssignProcessToJobObject(job, process)
        return bool(assigned)
    finally:
        _kernel32.CloseHandle(process)


def _terminate_job(job: int, exit_code: int) -> None:
    """Terminate every process in a Job Object.

    Args:
        job: Job handle returned by :func:`_create_job`.
        exit_code: Exit code reported for the terminated processes.
    """
    if not _IS_WINDOWS:
        return
    _kernel32.TerminateJobObject(job, exit_code)


def _close_job(job: int) -> None:
    """Close a Job Object handle.

    Because the job is created with ``KILL_ON_JOB_CLOSE``, closing the final
    handle also terminates any process still assigned to it, guaranteeing no
    survivors even if a timeout path is skipped.

    Args:
        job: Job handle returned by :func:`_create_job`.
    """
    if not _IS_WINDOWS:
        return
    _kernel32.CloseHandle(job)


class _ProcessGuard:
    """Confines one subprocess tree so it can be force-terminated wholesale.

    On Windows the guard owns a Job Object; the group's pytest process is
    adopted into it right after launch and the whole job is terminated on
    timeout. On other platforms (and if job creation fails) the guard degrades
    to a ``psutil`` parent-walking kill, which is sufficient for the
    non-Windows CI path.
    """

    def __init__(self) -> None:
        """Create the guard, allocating a Job Object on Windows."""
        self._job: int | None = _create_job()

    def adopt(self, pid: int) -> bool:
        """Assign a freshly launched process to this guard's Job Object.

        Args:
            pid: Process id of the launched pytest process.

        Returns:
            bool: ``True`` if the process was assigned to a Job Object.
        """
        if self._job is None:
            return False
        return _assign_to_job(self._job, pid)

    def kill(self, pid: int) -> None:
        """Terminate the guarded process subtree.

        The Job Object kill is authoritative on Windows; the ``psutil`` sweep
        runs afterwards as a fallback for the non-job path.

        Args:
            pid: Process id of the subtree root.
        """
        if self._job is not None:
            _terminate_job(self._job, _EXIT_TIMEOUT)
        _kill_process_tree(pid)

    def close(self) -> None:
        """Release the Job Object handle, killing any survivors."""
        if self._job is not None:
            _close_job(self._job)
            self._job = None


@dataclass(frozen=True)
class Group:
    """A single isolated coverage group.

    Attributes:
        name: Stable identifier derived from the directory's path relative to
            the tests root (path separators replaced with ``__``; the root
            itself is ``_root``).
        target: Absolute path to the leaf test directory.
        dotted: Importable package name for the same directory, for example
            ``tests.bridges.completeness.ghidra``, or ``None`` when the chain
            from the tests root down to this directory is not a package.
            Collection is addressed by import path rather than by filesystem
            path because a filesystem target makes pytest build the package
            chain twice inside the container, running every test in the group
            twice.
        ignores: Immediate child test directories excluded via ``--ignore`` so
            they run as their own groups instead of being double-counted here.
    """

    name: str
    target: Path
    dotted: str | None
    ignores: tuple[Path, ...]


@dataclass(frozen=True)
class GroupResult:
    """Outcome of running one coverage group.

    Attributes:
        name: The group name.
        exit_code: pytest exit code (``0`` pass, ``1`` failed, ``5`` no tests,
            ``124`` watchdog-killed).
        duration: Wall-clock seconds the group ran.
        junit: Path to the group's JUnit XML file (may not exist on crash).
    """

    name: str
    exit_code: int
    duration: float
    junit: Path


def _is_package_chain(root: Path, parts: tuple[str, ...]) -> bool:
    """Report whether ``root`` and every directory under it is a package.

    ``--pyargs`` resolves a target by importing it, so a dotted name is only
    usable when the whole chain carries ``__init__.py``. A namespace directory
    anywhere along it makes the import fail, and pytest reports that as a usage
    error rather than running the group.

    Args:
        root: The tests root the dotted name is anchored at.
        parts: Path components from ``root`` down to the group directory.

    Returns:
        bool: True when ``root`` and each named component hold ``__init__.py``.
    """
    directory = root
    if not (directory / "__init__.py").is_file():
        return False
    for part in parts:
        directory /= part
        if not (directory / "__init__.py").is_file():
            return False
    return True


def discover_groups(tests_root: Path) -> list[Group]:
    """Enumerate every leaf test directory beneath ``tests_root``.

    A directory becomes a group when it directly holds one or more
    ``test_*.py`` files. Its immediate child directories are recorded as
    ignores (excluding ``__pycache__`` and dot-directories) because they are
    visited as their own groups, guaranteeing every leaf directory runs in its
    own pytest process.

    Args:
        tests_root: Root ``tests`` directory to scan.

    Returns:
        list[Group]: Groups sorted by name.
    """
    root = tests_root.resolve()
    candidates: list[Path] = [root]
    candidates.extend(sorted(p for p in root.rglob("*") if p.is_dir()))

    groups: list[Group] = []
    for directory in candidates:
        loose_tests = [p for p in directory.glob("test_*.py") if p.is_file()]
        if not loose_tests:
            continue
        ignores = tuple(
            sorted(
                child
                for child in directory.iterdir()
                if child.is_dir()
                and child.name != "__pycache__"
                and not child.name.startswith(".")
            ),
        )
        relative = directory.relative_to(root)
        is_root = str(relative) == "."
        name = "_root" if is_root else str(relative).replace("\\", "__").replace("/", "__")
        parts = () if is_root else relative.parts
        dotted = ".".join((root.name, *parts)) if _is_package_chain(root, parts) else None
        groups.append(Group(name=name, target=directory, dotted=dotted, ignores=ignores))

    groups.sort(key=lambda group: group.name)
    return groups


def group_collection_target(group: Group, tests_root: Path, workspace_root: Path) -> list[str]:
    """Choose how one group's tests are addressed on the pytest command line.

    An import-path target is used whenever it is genuinely resolvable, because
    a filesystem target makes pytest build the group's package chain twice and
    run every test in it twice. Resolvability takes two things: the chain has
    to be a real package (:func:`_is_package_chain`), and the directory that
    chain is anchored at has to be the one pytest runs from, since that is the
    only path entry the target is looked up against. When either fails the
    filesystem path is used, which still collects the right tests - twice, but
    correctly - rather than failing the group with a usage error.

    Args:
        group: The group to address.
        tests_root: Root the groups were discovered under.
        workspace_root: Working directory pytest is launched in.

    Returns:
        list[str]: The target tokens, either ``["--pyargs", "<dotted>"]`` or a
            single filesystem path.
    """
    anchored = tests_root.resolve().parent == workspace_root.resolve()
    if group.dotted is not None and anchored:
        return ["--pyargs", group.dotted]
    return [str(group.target)]


def _pytest_command(
    group: Group,
    junit: Path,
    extra: list[str],
    *,
    tests_root: Path,
    workspace_root: Path,
) -> list[str]:
    """Build the ``pytest`` argument vector for one group.

    Args:
        group: The group to run.
        junit: Path the group's JUnit XML report is written to.
        extra: Additional pytest arguments forwarded from the caller.
        tests_root: Root the groups were discovered under.
        workspace_root: Working directory pytest is launched in.

    Returns:
        list[str]: Argument vector beginning with the current interpreter.
    """
    args: list[str] = group_collection_target(group, tests_root, workspace_root)
    args.extend(f"--ignore={ignore}" for ignore in group.ignores)
    args.extend(
        [
            "--cov=src/intellicrack",
            "--cov-branch",
            "--cov-report=",
            "--cov-fail-under=0",
            "-p",
            "no:randomly",
            "-p",
            "no:cacheprovider",
            f"--junitxml={junit}",
            "-q",
            "-ra",
            "--strict-markers",
        ],
    )
    args.extend(extra)
    return [sys.executable, "-m", "pytest", *args]


def _flush_group_log(
    entry_name: str,
    exit_code: int,
    duration: float,
    out_path: Path,
    err_path: Path,
    log_path: Path,
    lock: threading.Lock,
) -> None:
    """Append a finished group's captured output to the shared log atomically.

    Holding ``lock`` guarantees concurrent groups never interleave their
    output blocks in the shared log.

    Args:
        entry_name: Group name.
        exit_code: Group exit code.
        duration: Group wall-clock duration in seconds.
        out_path: Captured stdout temp file.
        err_path: Captured stderr temp file.
        log_path: Shared log file to append to.
        lock: Serialises writes to ``log_path``.
    """
    rule = "-" * 80
    header = (
        f"\n{rule}\nCOVERAGE GROUP: {entry_name}   exit={exit_code}   "
        f"duration={duration:.2f}s\n{rule}\n"
    )
    body = ""
    if out_path.exists():
        body += out_path.read_text(encoding="utf-8", errors="replace")
    if err_path.exists():
        err_text = err_path.read_text(encoding="utf-8", errors="replace")
        if err_text.strip():
            body += f"\n[stderr]\n{err_text}"
    with lock:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(header)
            handle.write(body)
        print(f"END GROUP: {entry_name}   exit={exit_code}   duration={duration:.2f}s", flush=True)
    for temp in (out_path, err_path):
        temp.unlink(missing_ok=True)


def run_group(
    group: Group,
    *,
    tests_root: Path,
    workspace_root: Path,
    reports_root: Path,
    combine_dir: Path,
    timestamp: str,
    timeout: float,
    extra: list[str],
    log_path: Path,
    log_lock: threading.Lock,
) -> GroupResult:
    """Run one coverage group in an isolated, force-killable pytest process.

    The group's deadline is enforced by ``Popen.wait(timeout=...)`` -- a kernel
    wait, immune to CPU starvation -- and on expiry the entire process subtree
    is terminated through a Windows Job Object.

    Args:
        group: The group to run.
        tests_root: Root the groups were discovered under, used to decide
            whether the group can be addressed by import path.
        workspace_root: Working directory for pytest (repo root, so the
            relative ``--cov=src/intellicrack`` source path resolves).
        reports_root: Directory the per-group JUnit XML is written to.
        combine_dir: Private directory for this group's coverage shard and
            captured output temp files.
        timestamp: Run timestamp used in the JUnit filename.
        timeout: Per-group wall-clock timeout in seconds.
        extra: Additional pytest arguments forwarded from the caller.
        log_path: Shared log file to append captured output to.
        log_lock: Serialises writes to ``log_path``.

    Returns:
        GroupResult: The group's exit code, duration, and JUnit path.
    """
    safe = "".join(char if char.isalnum() or char == "_" else "_" for char in group.name)
    junit = reports_root / f"junit_coverage_{timestamp}__{group.name}.xml"
    out_path = combine_dir / f"{safe}.out"
    err_path = combine_dir / f"{safe}.err"

    env = os.environ.copy()
    env["COVERAGE_FILE"] = str(combine_dir / f".coverage.{safe}")

    command = _pytest_command(group, junit, extra, tests_root=tests_root, workspace_root=workspace_root)

    with log_lock:
        print(f"START GROUP: {group.name}", flush=True)

    start = time.monotonic()
    guard = _ProcessGuard()
    exit_code: int
    try:
        with out_path.open("w", encoding="utf-8") as out_handle, err_path.open("w", encoding="utf-8") as err_handle:
            proc = subprocess.Popen(
                command,
                cwd=str(workspace_root),
                env=env,
                stdout=out_handle,
                stderr=err_handle,
                stdin=subprocess.DEVNULL,
                text=True,
            )
            guard.adopt(proc.pid)
            try:
                exit_code = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                guard.kill(proc.pid)
                try:
                    proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    print(
                        f"WARNING: group {group.name} pid {proc.pid} survived job termination",
                        file=sys.stderr,
                        flush=True,
                    )
                exit_code = _EXIT_TIMEOUT
    finally:
        guard.close()

    duration = time.monotonic() - start
    _flush_group_log(group.name, exit_code, duration, out_path, err_path, log_path, log_lock)
    return GroupResult(name=group.name, exit_code=exit_code, duration=duration, junit=junit)


def merge_junit(junit_files: list[Path], out_path: Path) -> None:
    """Merge per-group JUnit reports into one ``<testsuites>`` document.

    Args:
        junit_files: Per-group JUnit XML paths (missing files are skipped).
        out_path: Destination path for the merged report.
    """
    root = ET.Element("testsuites")
    for junit in junit_files:
        if not junit.exists():
            continue
        try:
            node = DefusedET.parse(junit).getroot()
        except DefusedET.ParseError:
            continue
        if node is None:
            continue
        if node.tag == "testsuites":
            root.extend(list(node))
        elif node.tag == "testsuite":
            root.append(node)
    ET.ElementTree(root).write(out_path, encoding="utf-8", xml_declaration=True)


def _coverage_command(args: list[str]) -> list[str]:
    """Build a ``coverage`` invocation for the current interpreter.

    Args:
        args: ``coverage`` subcommand and its arguments.

    Returns:
        list[str]: Full argument vector.
    """
    return [sys.executable, "-m", "coverage", *args]


def run_coverage_report(
    *,
    workspace_root: Path,
    combine_dir: Path,
    coverage_xml: Path,
    coverage_html: Path,
    fail_under: int,
    log_path: Path,
) -> int:
    """Combine per-group shards and emit the merged coverage reports and gate.

    Args:
        workspace_root: Working directory for coverage (repo root).
        combine_dir: Directory holding the per-group ``.coverage.*`` shards.
        coverage_xml: Destination path for the Cobertura XML report.
        coverage_html: Destination directory for the HTML report.
        fail_under: Minimum whole-suite line coverage percentage for the gate.
        log_path: Shared log file the coverage output is appended to.

    Returns:
        int: ``0`` if coverage met the gate, non-zero otherwise.
    """
    env = os.environ.copy()
    env["COVERAGE_FILE"] = str(combine_dir / ".coverage")
    invocations = [
        _coverage_command(["combine", str(combine_dir)]),
        _coverage_command(["xml", "-o", str(coverage_xml)]),
        _coverage_command(["html", "-d", str(coverage_html)]),
        _coverage_command(["report", "--fail-under", str(fail_under), "--show-missing"]),
    ]
    gate = 0
    with log_path.open("a", encoding="utf-8") as handle:
        for invocation in invocations:
            completed = subprocess.run(
                invocation,
                cwd=str(workspace_root),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
            handle.write(completed.stdout)
            sys.stdout.write(completed.stdout)
            gate = completed.returncode
    return gate


def orchestrate(
    *,
    tests_root: Path,
    workspace_root: Path,
    reports_root: Path,
    combine_dir: Path,
    junit_out: Path,
    coverage_xml: Path,
    coverage_html: Path,
    log_path: Path,
    timestamp: str,
    jobs: int,
    group_timeout: float,
    fail_under: int,
    extra: list[str],
) -> int:
    """Run every group with bounded concurrency, then report and gate.

    Args:
        tests_root: Root ``tests`` directory to scan.
        workspace_root: Working directory for pytest/coverage (repo root).
        reports_root: Directory for per-group and merged JUnit reports.
        combine_dir: Private directory for coverage shards (recreated fresh).
        junit_out: Destination for the merged JUnit report.
        coverage_xml: Destination for the merged Cobertura XML report.
        coverage_html: Destination directory for the merged HTML report.
        log_path: Shared log file.
        timestamp: Run timestamp used in per-group JUnit filenames.
        jobs: Maximum number of concurrent group processes.
        group_timeout: Per-group wall-clock timeout in seconds.
        fail_under: Minimum whole-suite coverage percentage for the gate.
        extra: Additional pytest arguments forwarded to every group.

    Returns:
        int: ``0`` on success; ``1`` if any group failed; otherwise the
        coverage gate's non-zero exit code.
    """
    groups = discover_groups(tests_root)
    shutil.rmtree(combine_dir, ignore_errors=True)
    combine_dir.mkdir(parents=True, exist_ok=True)

    print(
        f"COVERAGE ISOLATED START   groups={len(groups)}   jobs={jobs}   "
        f"group_timeout={group_timeout:.0f}s",
        flush=True,
    )

    log_lock = threading.Lock()
    results: list[GroupResult] = []
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as executor:
        futures: list[Future[GroupResult]] = [
            executor.submit(
                run_group,
                group,
                tests_root=tests_root,
                workspace_root=workspace_root,
                reports_root=reports_root,
                combine_dir=combine_dir,
                timestamp=timestamp,
                timeout=group_timeout,
                extra=extra,
                log_path=log_path,
                log_lock=log_lock,
            )
            for group in groups
        ]
        results = [future.result() for future in futures]

    merge_junit([result.junit for result in results], junit_out)
    gate = run_coverage_report(
        workspace_root=workspace_root,
        combine_dir=combine_dir,
        coverage_xml=coverage_xml,
        coverage_html=coverage_html,
        fail_under=fail_under,
        log_path=log_path,
    )

    failed = [f"{result.name}={result.exit_code}" for result in results if result.exit_code not in {0, _EXIT_NO_TESTS}]
    summary = (
        f"\n{'=' * 80}\nCOVERAGE ISOLATED SUMMARY   groups={len(groups)}   "
        f"failed={len(failed)}   coverage_gate_exit={gate}\n"
    )
    if failed:
        summary += f"FAILED GROUPS: {', '.join(failed)}\n"
    summary += "=" * 80
    print(summary, flush=True)
    with log_lock, log_path.open("a", encoding="utf-8") as handle:
        handle.write(summary + "\n")

    if failed:
        return 1
    return gate


def _list_groups(tests_root: Path) -> int:
    """Print discovered groups as ``name<TAB>target<TAB>ignore;ignore`` lines.

    Args:
        tests_root: Root ``tests`` directory to scan.

    Returns:
        int: Always ``0``.
    """
    for group in discover_groups(tests_root):
        ignores = ";".join(str(ignore) for ignore in group.ignores)
        print(f"{group.name}\t{group.target}\t{ignores}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser.

    Returns:
        argparse.ArgumentParser: The configured parser.
    """
    parser = argparse.ArgumentParser(description="Isolated per-directory coverage runner.")
    parser.add_argument("--tests-root", required=True, type=Path)
    parser.add_argument("--list-groups", action="store_true")
    parser.add_argument("--workspace-root", type=Path, default=Path.cwd())
    parser.add_argument("--reports-root", type=Path)
    parser.add_argument("--combine-dir", type=Path)
    parser.add_argument("--junit-out", type=Path)
    parser.add_argument("--coverage-xml", type=Path)
    parser.add_argument("--coverage-html", type=Path)
    parser.add_argument("--log", type=Path)
    parser.add_argument("--timestamp", default="run")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--group-timeout", type=float, default=900.0)
    parser.add_argument("--fail-under", type=int, default=95)
    parser.add_argument("pytest_extra", nargs="*", default=[])
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the coverage runner.

    Args:
        argv: Argument list excluding the program name; defaults to
            ``sys.argv[1:]``.

    Returns:
        int: Process exit code.
    """
    parser = _build_parser()
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    tests_root: Path = args.tests_root

    if args.list_groups:
        return _list_groups(tests_root)

    run_paths: dict[str, Path | None] = {
        "--reports-root": args.reports_root,
        "--combine-dir": args.combine_dir,
        "--junit-out": args.junit_out,
        "--coverage-xml": args.coverage_xml,
        "--coverage-html": args.coverage_html,
        "--log": args.log,
    }
    missing = [flag for flag, value in run_paths.items() if value is None]
    if missing:
        parser.error("missing required arguments for a coverage run: " + ", ".join(missing))

    reports_root: Path = args.reports_root
    combine_dir: Path = args.combine_dir
    junit_out: Path = args.junit_out
    coverage_xml: Path = args.coverage_xml
    coverage_html: Path = args.coverage_html
    log_path: Path = args.log
    return orchestrate(
        tests_root=tests_root,
        workspace_root=args.workspace_root,
        reports_root=reports_root,
        combine_dir=combine_dir,
        junit_out=junit_out,
        coverage_xml=coverage_xml,
        coverage_html=coverage_html,
        log_path=log_path,
        timestamp=args.timestamp,
        jobs=args.jobs,
        group_timeout=args.group_timeout,
        fail_under=args.fail_under,
        extra=list(args.pytest_extra),
    )


if __name__ == "__main__":
    raise SystemExit(main())
