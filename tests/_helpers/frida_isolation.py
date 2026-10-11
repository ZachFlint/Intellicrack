# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Subprocess isolation for the real self-attach Frida bridge tests.

Frida self-attach exercises native frida-core/Gum code that, rarely and
non-deterministically, raises a ``Windows fatal exception: access violation``
deep in a full-suite run -- a native abort that terminates the whole pytest
process (exit 255, no junit) instead of failing one test, which is why the
``python-test`` CI job can fail to report at all.

Because a child process that faults returns its exit code to the parent rather
than taking the parent down, running those tests in a child contains the crash:
the suite still completes and the crash is reported as ordinary failures.

Isolation is per *module*, not per test. A module that self-attaches Frida is
run once in a child, and the child appends every test result to a file as it
goes, so per-test outcomes are still reported individually by the parent. Per-
test isolation was measured at roughly 32s per test (each child re-imports
PyQt6, intellicrack and frida), which would add close to an hour to the suite;
per-module isolation pays that start-up once per module instead. If the child
dies part-way through, the results it already flushed are still used and only
the tests it never reported are failed with the crash detail.

A child can also deadlock instead of crashing, with every thread idle inside
native Frida code. The parent therefore watches the result file as it grows and
kills the child's whole process tree when no new result has been flushed for
``_CHILD_STALL_SECONDS``, a limit sized from the normal duration of a module
(under three minutes) rather than from the hard ceiling. The child also runs
with a short pytest ``faulthandler_timeout`` so the all-thread traceback that
shows where it was stuck is already on its stderr when it is killed, and that
traceback is carried into the failure detail.

A module opts in either by requesting the ``self_attached_bridge`` fixture or by
declaring ``pytestmark`` with the ``frida_selfattach`` marker at module level.
Self-attach that reaches frida-core any other way -- a differently named fixture,
dispatch through a ``ToolRegistry``, or a panel's own attach handler -- would
inject the Frida agent into the pytest process itself, where the fault it can
leave behind detonates later in whatever unrelated test runs next. The static
classifier below (:func:`classify_self_attach_modules`) finds every such module
so a gate can insist each one is isolated.

The plugin is registered from ``tests/conftest.py`` so it loads for the whole
session regardless of optional native modules; its hooks are no-ops for every
test that is not in a Frida self-attach module.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal, cast

import pytest

from scripts.sandbox.test_types import to_pyargs_argv
from tests._helpers.process_cleanup import kill_pid_tree


if TYPE_CHECKING:
    from collections.abc import Mapping

    from _pytest.reports import TestReport
    from _pytest.runner import SetupState


_Phase = Literal["setup", "call", "teardown"]
"""The three pytest run phases a synthesized report can describe."""

_Outcome = Literal["passed", "failed", "skipped"]
"""The outcomes pytest accepts on a :class:`TestReport`."""

_SkipLocation = tuple[str, int, str]
"""The ``(path, lineno, reason)`` pytest requires as a skipped report's ``longrepr``."""

_StopReason = Literal["exited", "timeout", "stalled"]
"""Why :func:`run_child_with_progress_watch` stopped waiting for a child."""

MARKER_NAME = "frida_selfattach"
_MARKER_DESCRIPTION = (
    "run this test in an isolated child pytest process so a native Frida self-attach crash "
    "(access violation) fails only these tests instead of aborting the whole run; auto-applied "
    "to every test in a module that uses the self_attached_bridge fixture, or applied to a whole "
    "module through a module-level pytestmark"
)
_SELF_ATTACH_FIXTURE = "self_attached_bridge"
_PYTESTMARK_NAME = "pytestmark"
_MARK_NAMESPACE = "mark"
_USEFIXTURES_NAME = "usefixtures"
_FRIDA_MODULES = frozenset({"frida", "intellicrack.bridges.frida_bridge"})
"""Imports that bring real frida-core into a test module."""
_DEVICE_ACQUIRERS = frozenset({"initialize", "get_local_device"})
"""Calls that resolve a real local Frida device rather than a test double."""
_SELF_PID_CALL = "getpid"
_TEST_FILE_PREFIX = "test_"
_TEST_FILE_SUFFIX = "_test.py"
_CHILD_ENV_FLAG = "IC_FRIDA_SELFATTACH_ISOLATED_CHILD"
_RESULT_FILE_ENV = "IC_FRIDA_SELFATTACH_RESULT_FILE"
_CHILD_TIMEOUT_SECONDS = 1800.0
_CHILD_STALL_SECONDS = 300.0
"""Longest a module's child may go without flushing a result before it is killed as hung.

A healthy Frida module finishes in under three minutes in total, including the
roughly 30 s the child spends importing PyQt6, intellicrack and frida before its
first result, so five minutes without any new result is a deadlock and not a slow test.
"""
_CHILD_POLL_SECONDS = 1.0
_CHILD_REAP_SECONDS = 30.0
_CHILD_FAULTHANDLER_SECONDS = 120
"""Per-test ``faulthandler_timeout`` the child runs with, well below :data:`_CHILD_STALL_SECONDS`."""
_STDOUT_TAIL = 6000
_STDERR_LIMIT = 8000
"""Most stderr a failure detail carries: the start of a fatal-exception dump, which names the faulting thread, plus its end."""
_STDERR_HEAD_SHARE = 3

_MODULE_RESULTS: dict[str, ModuleResult] = {}
"""Per-module child results, keyed by the module's rootdir-relative path."""


@dataclass(frozen=True)
class ModuleResult:
    """Outcomes recovered from one isolated module run.

    Attributes:
        outcomes: Node key (the part of a node id after ``::``) mapped to the
            outcome the child reported for it.
        skips: Node key mapped to the location and reason of the child's skip,
            for every test whose outcome is ``"skipped"``.
        detail: The child's tail output, present when the child exited non-zero.
        complete: ``True`` when the child exited cleanly; ``False`` when it
            crashed or timed out, so unreported tests must be failed.
    """

    outcomes: Mapping[str, _Outcome]
    skips: Mapping[str, _SkipLocation]
    detail: str | None
    complete: bool


@dataclass(frozen=True)
class ChildRun:
    """What happened to one child process watched by :func:`run_child_with_progress_watch`.

    Attributes:
        stop_reason: ``"exited"`` when the child ended on its own, ``"timeout"``
            when it outlived the hard ceiling, ``"stalled"`` when it went too
            long without flushing a new result. Both of the latter were killed.
        returncode: The child's exit code (the kill's exit code when it was killed).
        stdout: Everything the child wrote to stdout.
        stderr: Everything the child wrote to stderr, including any
            ``faulthandler`` all-thread traceback it dumped before being killed.
        limit_seconds: The limit that ended the wait, or ``0.0`` when the child exited on its own.
    """

    stop_reason: _StopReason
    returncode: int | None
    stdout: str
    stderr: str
    limit_seconds: float


def _as_text(value: str | bytes | None) -> str:
    """Return captured subprocess output as text.

    Args:
        value: Output as a partial ``TimeoutExpired`` carries it.

    Returns:
        str: ``value`` decoded when it is bytes, ``""`` when it is absent.
    """
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def clip_output(text: str, limit: int) -> str:
    """Shorten captured output to ``limit`` characters while keeping both its start and its end.

    A ``faulthandler`` fatal-exception dump opens with the faulting thread, so
    keeping only the tail of a long stderr hides the part that names the crash.

    Args:
        text: The captured output.
        limit: Most characters of ``text`` to keep.

    Returns:
        str: ``text`` when it fits, otherwise its first third and last two thirds joined by a marker.
    """
    if len(text) <= limit:
        return text
    head = limit // _STDERR_HEAD_SHARE
    tail = limit - head
    return f"{text[:head]}\n...[{len(text) - limit} characters omitted]...\n{text[-tail:]}"


def _file_size(path: str | None) -> int:
    """Return a file's size, or ``0`` when it is absent or unnamed.

    Args:
        path: File to measure, or ``None``.

    Returns:
        int: The size in bytes.
    """
    if path is None:
        return 0
    try:
        return Path(path).stat().st_size
    except OSError:
        return 0


def _hang_reason(
    *,
    elapsed: float,
    idle: float,
    timeout_seconds: float,
    stall_seconds: float | None,
) -> tuple[_StopReason, float] | None:
    """Decide whether a running child has outlived a limit.

    Args:
        elapsed: Seconds since the child started.
        idle: Seconds since the child last flushed a result.
        timeout_seconds: Hard ceiling on ``elapsed``.
        stall_seconds: Ceiling on ``idle``, or ``None`` to not watch for stalls.

    Returns:
        tuple[_StopReason, float] | None: The reason and the limit that was
            exceeded, or ``None`` while the child is still within bounds.
    """
    if elapsed >= timeout_seconds:
        return "timeout", timeout_seconds
    if stall_seconds is not None and idle >= stall_seconds:
        return "stalled", stall_seconds
    return None


def run_child_with_progress_watch(
    command: list[str],
    *,
    cwd: str,
    env: Mapping[str, str],
    timeout_seconds: float,
    stall_seconds: float | None,
    result_path: str | None,
    poll_seconds: float = _CHILD_POLL_SECONDS,
) -> ChildRun:
    """Run ``command`` and kill its process tree if it outlives a limit or stops reporting.

    Progress is the growth of ``result_path``, which the child appends to as each
    test phase finishes. A child that is alive but has flushed nothing new for
    ``stall_seconds`` is deadlocked rather than slow, so it is killed together
    with every process it spawned (a hung Frida target such as ``notepad.exe``
    would otherwise outlive it) instead of holding the caller until the hard
    ceiling.

    Args:
        command: Child argv.
        cwd: Working directory for the child.
        env: Environment for the child.
        timeout_seconds: Wall-clock ceiling for the whole run.
        stall_seconds: Longest the child may go without growing ``result_path``,
            or ``None`` to enforce only the ceiling.
        result_path: File whose growth counts as progress, or ``None`` when there is none.
        poll_seconds: How often to check the limits.

    Returns:
        ChildRun: The child's output and why the wait ended.
    """
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=dict(env),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    started = time.monotonic()
    last_progress = started
    last_size = _file_size(result_path)
    hang: tuple[_StopReason, float] | None = None
    while hang is None:
        try:
            stdout, stderr = process.communicate(timeout=poll_seconds)
        except subprocess.TimeoutExpired:
            now = time.monotonic()
            size = _file_size(result_path)
            if size != last_size:
                last_size = size
                last_progress = now
            hang = _hang_reason(
                elapsed=now - started,
                idle=now - last_progress,
                timeout_seconds=timeout_seconds,
                stall_seconds=stall_seconds if result_path is not None else None,
            )
        else:
            return ChildRun("exited", process.returncode, stdout, stderr, 0.0)
    kill_pid_tree(process.pid)
    try:
        stdout, stderr = process.communicate(timeout=_CHILD_REAP_SECONDS)
    except subprocess.TimeoutExpired as exc:
        stdout, stderr = _as_text(exc.stdout), _as_text(exc.stderr)
    return ChildRun(hang[0], process.returncode, stdout, stderr, hang[1])


def in_isolated_child() -> bool:
    """Report whether the current process is an isolation child.

    Returns:
        bool: ``True`` when running inside the child pytest process this plugin
            spawns, in which case tests run in-process without re-isolating.
    """
    return os.environ.get(_CHILD_ENV_FLAG) == "1"


def install(config: pytest.Config) -> None:
    """Register the marker and this plugin on ``config``.

    Called from the global ``tests/conftest.py`` ``pytest_configure`` so the
    hooks below participate in collection and the run loop for the whole session.

    Args:
        config: The active pytest configuration.
    """
    config.addinivalue_line("markers", f"{MARKER_NAME}: {_MARKER_DESCRIPTION}")
    if not config.pluginmanager.has_plugin("ic_frida_isolation"):
        config.pluginmanager.register(sys.modules[__name__], "ic_frida_isolation")


def _node_key(nodeid: str) -> str:
    """Return the within-module portion of ``nodeid``.

    The path component differs between parent and child when the parent
    addressed tests as importable ``--pyargs`` targets, so only the part after
    the first ``::`` -- unique within one module -- is used to match them up.

    Args:
        nodeid: A pytest node id.

    Returns:
        str: Everything after the first ``::``, or the whole id when absent.
    """
    _, separator, node_part = nodeid.partition("::")
    return node_part if separator else nodeid


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Mark every test in a self-attach Frida module for isolation.

    Whole modules are marked (not just the tests requesting the fixture) so the
    module can be run once in a child without any of its tests also running
    in-process in the parent.

    Args:
        items: The collected test items, modified in place.
    """
    self_attach_modules = {str(item.location[0]) for item in items if _SELF_ATTACH_FIXTURE in getattr(item, "fixturenames", ())}
    if not self_attach_modules:
        return
    for item in items:
        if str(item.location[0]) in self_attach_modules:
            item.add_marker(MARKER_NAME)


def _called_name(call: ast.Call) -> str | None:
    """Return the bare name a call invokes, ignoring its receiver.

    Args:
        call: A call expression.

    Returns:
        str | None: ``attach`` for both ``attach(...)`` and ``bridge.attach(...)``,
            or ``None`` when the callee is not a plain name or attribute.
    """
    func = call.func
    if isinstance(func, ast.Attribute):
        return func.attr
    return func.id if isinstance(func, ast.Name) else None


def _imports_frida(tree: ast.Module) -> bool:
    """Report whether a module imports real frida-core anywhere.

    Args:
        tree: Parsed test module.

    Returns:
        bool: ``True`` when the module imports ``frida`` or the Frida bridge.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(alias.name in _FRIDA_MODULES for alias in node.names):
            return True
        if isinstance(node, ast.ImportFrom) and node.module in _FRIDA_MODULES:
            return True
    return False


def self_attaches_frida(tree: ast.Module) -> bool:
    """Report whether a test module injects the Frida agent into its own process.

    A module self-attaches when it imports real Frida, resolves a real local
    device, and targets the current process id. The device requirement is what
    separates a real injection from a module that only hands ``os.getpid()`` to
    a fake device, which never reaches frida-core. The route to the attach is
    deliberately not constrained: a direct ``bridge.attach(os.getpid())``, a
    ``ToolRegistry`` dispatch of ``frida.attach`` and a panel's attach handler
    all inject the same agent into the same process.

    Args:
        tree: Parsed test module.

    Returns:
        bool: ``True`` when the module performs a real Frida self-attach.
    """
    if not _imports_frida(tree):
        return False
    called = {name for node in ast.walk(tree) if isinstance(node, ast.Call) and (name := _called_name(node)) is not None}
    return _SELF_PID_CALL in called and not called.isdisjoint(_DEVICE_ACQUIRERS)


def _requests_self_attach_fixture(tree: ast.Module) -> bool:
    """Report whether any function or ``usefixtures`` in a module requests the self-attach fixture.

    Args:
        tree: Parsed test module.

    Returns:
        bool: ``True`` when the module requests ``self_attached_bridge``, which
            makes :func:`pytest_collection_modifyitems` isolate it.
    """
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            params = (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
            if any(param.arg == _SELF_ATTACH_FIXTURE for param in params):
                return True
        if (
            isinstance(node, ast.Call)
            and _called_name(node) == _USEFIXTURES_NAME
            and any(isinstance(arg, ast.Constant) and arg.value == _SELF_ATTACH_FIXTURE for arg in node.args)
        ):
            return True
    return False


def _is_isolation_mark(node: ast.AST) -> bool:
    """Report whether an expression is the ``pytest.mark.frida_selfattach`` marker.

    Args:
        node: Any expression node.

    Returns:
        bool: ``True`` for an attribute access naming :data:`MARKER_NAME` on a ``mark`` namespace.
    """
    return (
        isinstance(node, ast.Attribute)
        and node.attr == MARKER_NAME
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == _MARK_NAMESPACE
    )


def _marked_for_isolation(tree: ast.Module) -> bool:
    """Report whether a module's own ``pytestmark`` carries the isolation marker.

    Only a module-level ``pytestmark`` counts. A class-level one isolates just
    that class, leaving the module's other tests to run in the parent process.

    Args:
        tree: Parsed test module.

    Returns:
        bool: ``True`` when a module-level ``pytestmark`` includes :data:`MARKER_NAME`.
    """
    for statement in tree.body:
        if isinstance(statement, ast.Assign):
            targets: list[ast.expr] = statement.targets
            value: ast.expr | None = statement.value
        elif isinstance(statement, ast.AnnAssign):
            targets = [statement.target]
            value = statement.value
        else:
            continue
        if value is None or not any(isinstance(target, ast.Name) and target.id == _PYTESTMARK_NAME for target in targets):
            continue
        if any(_is_isolation_mark(node) for node in ast.walk(value)):
            return True
    return False


def declares_isolation(tree: ast.Module) -> bool:
    """Report whether a test module will be run in an isolated child process.

    Args:
        tree: Parsed test module.

    Returns:
        bool: ``True`` when the module requests ``self_attached_bridge`` or marks
            itself with :data:`MARKER_NAME` at module level.
    """
    return _requests_self_attach_fixture(tree) or _marked_for_isolation(tree)


def _is_test_file(path: Path) -> bool:
    """Report whether pytest's ``python_files`` patterns collect a file.

    Args:
        path: Candidate Python file.

    Returns:
        bool: ``True`` for ``test_*.py`` and ``*_test.py`` files.
    """
    return path.suffix == ".py" and (path.name.startswith(_TEST_FILE_PREFIX) or path.name.endswith(_TEST_FILE_SUFFIX))


def classify_self_attach_modules(tests_root: Path) -> dict[Path, bool]:
    """Map every Frida self-attach test module under a tree to whether it is isolated.

    Args:
        tests_root: Root of the test tree to scan.

    Returns:
        dict[Path, bool]: Each self-attaching test module mapped to ``True`` when
            it declares isolation and ``False`` when it would inject the Frida
            agent into the pytest process itself.
    """
    classified: dict[Path, bool] = {}
    for path in sorted(tests_root.rglob("*.py")):
        if not _is_test_file(path):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if self_attaches_frida(tree):
            classified[path] = declares_isolation(tree)
    return classified


def pytest_runtest_logreport(report: TestReport) -> None:
    """Record one phase result when running inside an isolation child.

    Appends (and flushes) each phase as it happens so that a child which dies
    part-way through still leaves usable results for the tests it completed.
    A skipped phase also records its location and reason, which the parent
    needs to rebuild the skipped report.

    Args:
        report: The phase report pytest just produced.
    """
    if not in_isolated_child():
        return
    result_path = os.environ.get(_RESULT_FILE_ENV)
    if not result_path:
        return
    fields = [report.nodeid, report.when, report.outcome]
    if report.skipped and isinstance(report.longrepr, tuple):
        path, lineno, reason = report.longrepr
        fields.extend((_escape_field(path), str(lineno), _escape_field(reason)))
    with Path(result_path).open("a", encoding="utf-8") as handle:
        _ = handle.write("\t".join(fields) + "\n")


def _escape_field(value: str) -> str:
    """Escape ``value`` so it holds no tab or line break.

    Args:
        value: Free text such as a skip reason.

    Returns:
        str: ASCII text that :func:`_unescape_field` turns back into ``value``.
    """
    return value.encode("unicode_escape").decode("ascii")


def _unescape_field(value: str) -> str:
    """Reverse :func:`_escape_field`.

    Args:
        value: Text produced by :func:`_escape_field`.

    Returns:
        str: The original text.
    """
    return value.encode("ascii").decode("unicode_escape")


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_protocol(item: pytest.Item, nextitem: pytest.Item | None) -> bool | None:
    """Serve a marked item from its module's isolated child run.

    The first marked item of a module triggers the child run; every later item
    of that module is answered from the cached results.

    Args:
        item: The test item about to run.
        nextitem: The next scheduled item, which this process's own setup
            state is unwound toward once the item has been served.

    Returns:
        bool | None: ``True`` when this hook handled a marked item, ``None`` to
            let pytest run the item normally (unmarked tests, and every test
            inside the isolation child itself).
    """
    if in_isolated_child() or item.get_closest_marker(MARKER_NAME) is None:
        return None
    module_key = str(item.location[0])
    result = _MODULE_RESULTS.get(module_key)
    if result is None:
        result = run_module_isolated(module_key, str(item.config.rootpath))
        _MODULE_RESULTS[module_key] = result
    _emit_reports(item, nextitem, result)
    return True


def run_target_isolated(
    target: str,
    rootpath: str,
    *,
    timeout_seconds: float = _CHILD_TIMEOUT_SECONDS,
    stall_seconds: float | None = None,
    result_path: str | None = None,
) -> tuple[_Outcome, str | None]:
    """Run one pytest ``target`` in a child process and classify the result.

    This is the containment seam: because the target runs in a separate process,
    a hard abort inside it (a native access violation, or any other abnormal
    termination) ends only the child. The parent observes a non-zero exit code
    and turns it into an ordinary failure instead of dying with the child.

    The child addresses ``target`` by import path. Inside the Windows test
    container a filesystem path makes pytest build the package chain twice, and
    one of the two copies then fails to resolve fixtures from its package's
    ``conftest.py`` -- turning every such test in an isolated module into a
    spurious setup error.

    Args:
        target: A pytest target such as ``tests/.../test_x.py`` or one node id.
        rootpath: Directory to run the child from (the session's rootdir).
        timeout_seconds: Wall-clock ceiling for the child run.
        stall_seconds: Longest the child may go without flushing a new result to
            ``result_path`` before it is killed as hung, or ``None`` to enforce
            only ``timeout_seconds``. Ignored when there is no ``result_path``.
        result_path: Optional file the child appends per-test results to.

    Returns:
        tuple[_Outcome, str | None]: ``("passed", None)`` when the child exited 0,
            otherwise ``("failed", <diagnostic>)`` carrying the child's tail
            output. A native crash surfaces as a non-zero child exit code and is
            therefore reported as a failure rather than aborting the whole run,
            and a child that hangs is killed and reported with the all-thread
            traceback it dumped.
    """
    command = [
        sys.executable,
        "-m",
        "pytest",
        *to_pyargs_argv([
            target,
            "-p",
            "no:randomly",
            "-p",
            "no:cacheprovider",
            "-o",
            "addopts=",
            "-o",
            f"faulthandler_timeout={_CHILD_FAULTHANDLER_SECONDS}",
            "-q",
            "--no-header",
        ]),
    ]
    child_env = dict(os.environ)
    child_env[_CHILD_ENV_FLAG] = "1"
    if result_path is not None:
        child_env[_RESULT_FILE_ENV] = result_path
    run = run_child_with_progress_watch(
        command,
        cwd=rootpath,
        env=child_env,
        timeout_seconds=timeout_seconds,
        stall_seconds=stall_seconds,
        result_path=result_path,
    )
    hang_detail = f"{run.stdout[-_STDOUT_TAIL:]}\n{clip_output(run.stderr, _STDERR_LIMIT)}"
    if run.stop_reason == "timeout":
        return "failed", f"isolated subprocess for {target} timed out after {run.limit_seconds:g}s\n{hang_detail}"
    if run.stop_reason == "stalled":
        return "failed", (
            f"isolated subprocess for {target} flushed no new test result for {run.limit_seconds:g}s and was killed as hung "
            f"(a deadlock, since a healthy module finishes in minutes). Its all-thread traceback from "
            f"faulthandler, dumped after {_CHILD_FAULTHANDLER_SECONDS}s on one test, shows where it was stuck.\n{hang_detail}"
        )
    if run.returncode == 0:
        return "passed", None
    detail = f"{run.stdout[-_STDOUT_TAIL:]}\n{clip_output(run.stderr, _STDERR_LIMIT)}"
    return "failed", (
        f"isolated subprocess for {target} exited {run.returncode}; a native crash "
        f"(such as a frida-core access violation) surfaces here as a failure of only these tests rather "
        f"than aborting the whole run.\n{detail}"
    )


def _read_child_results(result_path: str) -> tuple[dict[str, _Outcome], dict[str, _SkipLocation]]:
    """Aggregate the per-phase lines a child wrote into one outcome per test.

    A test counts as failed when any phase failed, skipped when it was skipped
    and never failed, and passed otherwise.

    Args:
        result_path: File the child appended ``nodeid<TAB>phase<TAB>outcome``
            lines to, a skipped phase followed by ``<TAB>path<TAB>lineno<TAB>reason``.

    Returns:
        tuple[dict[str, _Outcome], dict[str, _SkipLocation]]: Node key mapped to
            its aggregated outcome, and node key mapped to the location and
            reason of its skip.
    """
    outcomes: dict[str, _Outcome] = {}
    skips: dict[str, _SkipLocation] = {}
    raw = Path(result_path)
    if not raw.is_file():
        return outcomes, skips
    outcome_parts = 3
    skip_parts = 6
    for line in raw.read_text(encoding="utf-8").splitlines():
        parts = line.split("\t")
        if len(parts) not in {outcome_parts, skip_parts}:
            continue
        key = _node_key(parts[0])
        reported = parts[2]
        if len(parts) == skip_parts and reported == "skipped" and parts[4].isdigit():
            _ = skips.setdefault(key, (_unescape_field(parts[3]), int(parts[4]), _unescape_field(parts[5])))
        current = outcomes.get(key)
        if reported == "failed" or current is None:
            outcomes[key] = "failed" if reported == "failed" else _as_outcome(reported)
        elif current != "failed" and reported == "skipped":
            outcomes[key] = "skipped"
    return outcomes, skips


def _as_outcome(reported: str) -> _Outcome:
    """Narrow a child-reported outcome string to a known outcome.

    Args:
        reported: The outcome text the child wrote.

    Returns:
        _Outcome: The matching outcome, defaulting to ``"passed"``.
    """
    if reported == "failed":
        return "failed"
    return "skipped" if reported == "skipped" else "passed"


def run_module_isolated(module_file: str, rootpath: str) -> ModuleResult:
    """Run one whole module in a child process and collect its per-test results.

    Args:
        module_file: The module's rootdir-relative path.
        rootpath: Directory to run the child from (the session's rootdir).

    Returns:
        ModuleResult: The outcomes the child reported, plus the child's tail
            output and whether it finished cleanly.
    """
    handle, result_path = tempfile.mkstemp(prefix="ic_frida_isolation_", suffix=".tsv")
    os.close(handle)
    try:
        outcome, detail = run_target_isolated(
            module_file,
            rootpath,
            stall_seconds=_CHILD_STALL_SECONDS,
            result_path=result_path,
        )
        outcomes, skips = _read_child_results(result_path)
    finally:
        Path(result_path).unlink(missing_ok=True)
    return ModuleResult(outcomes=outcomes, skips=skips, detail=detail, complete=outcome == "passed")


def _synthetic_report(
    item: pytest.Item,
    when: _Phase,
    outcome: _Outcome,
    longrepr: str | _SkipLocation | None,
    start: float,
    stop: float,
) -> TestReport:
    """Build a :class:`TestReport` describing one phase of an isolated run.

    Args:
        item: The isolated test item.
        when: The run phase (``"setup"``, ``"call"`` or ``"teardown"``).
        outcome: The outcome to record for the phase.
        longrepr: Failure text for a failed phase, the skip's location and
            reason for a skipped one, else ``None``.
        start: Phase start time (``time.time()``).
        stop: Phase stop time (``time.time()``).

    Returns:
        TestReport: A report pytest's terminal and junit reporters consume.
    """
    keywords: Mapping[str, int] = dict.fromkeys(item.keywords, 1)
    return pytest.TestReport(
        nodeid=item.nodeid,
        location=item.location,
        keywords=keywords,
        outcome=outcome,
        longrepr=longrepr,
        when=when,
        sections=[],
        duration=stop - start,
        start=start,
        stop=stop,
        user_properties=list(item.user_properties),
    )


def _unwind_session_setup(item: pytest.Item, nextitem: pytest.Item | None) -> TestReport:
    """Tear this process's own setup state down to what the next item needs, and report how that went.

    The child sets up and tears down an isolated test's own fixtures, but an
    ordinary test that ran here just before it was torn down toward the
    isolated item, which leaves every collector the two share -- their package,
    say -- on pytest's setup stack. Nothing isolated ever sets up in this
    process, so unless the stack is unwound here those collectors are still on
    it when the next ordinary test starts, and pytest fails that test's setup
    with "previous item was not torn down properly". A finalizer that fails
    while unwinding is reported as this item's teardown failure, as pytest
    reports it for any other test.

    Args:
        item: The isolated item that has just been served.
        nextitem: The next scheduled item, or ``None`` when this is the last.

    Returns:
        TestReport: The item's teardown report.
    """
    setup_state = cast("SetupState", getattr(item.session, "_setupstate"))

    def _teardown() -> None:
        """Unwind the setup stack toward the next item."""
        setup_state.teardown_exact(nextitem)

    call = cast(
        "pytest.CallInfo[None]",
        pytest.CallInfo.from_call(_teardown, when="teardown", reraise=(pytest.exit.Exception, KeyboardInterrupt)),
    )
    return pytest.TestReport.from_item_and_call(item, call)


def _emit_reports(item: pytest.Item, nextitem: pytest.Item | None, result: ModuleResult) -> None:
    """Emit this item's reports from its module's isolated child results.

    A test the child never reported -- because the child crashed before reaching
    it -- is failed with the child's diagnostic rather than silently vanishing.

    Args:
        item: The self-attach Frida test being served from cached results.
        nextitem: The next scheduled item, or ``None`` when this is the last.
        result: The cached result of its module's child run.
    """
    key = _node_key(item.nodeid)
    outcome = result.outcomes.get(key)
    longrepr: str | _SkipLocation | None
    if outcome is None:
        outcome = "failed"
        longrepr = result.detail or f"the isolated child running {item.location[0]} never reported a result for this test"
    elif outcome == "skipped":
        path, lineno, _ = item.location
        longrepr = result.skips.get(key, (path, (lineno or 0) + 1, "Skipped: the isolated child reported no reason"))
    else:
        longrepr = result.detail if outcome == "failed" else None

    ihook = item.ihook
    ihook.pytest_runtest_logstart(nodeid=item.nodeid, location=item.location)
    at = time.time()
    ihook.pytest_runtest_logreport(report=_synthetic_report(item, "setup", "passed", None, at, at))
    ihook.pytest_runtest_logreport(report=_synthetic_report(item, "call", outcome, longrepr, at, at))
    ihook.pytest_runtest_logreport(report=_unwind_session_setup(item, nextitem))
    ihook.pytest_runtest_logfinish(nodeid=item.nodeid, location=item.location)
