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

The plugin is registered from ``tests/conftest.py`` so it loads for the whole
session regardless of optional native modules; its hooks are no-ops for every
test that is not in a Frida self-attach module.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

import pytest


if TYPE_CHECKING:
    from collections.abc import Mapping

    from _pytest.reports import TestReport


_Phase = Literal["setup", "call", "teardown"]
"""The three pytest run phases a synthesized report can describe."""

_Outcome = Literal["passed", "failed", "skipped"]
"""The outcomes pytest accepts on a :class:`TestReport`."""

MARKER_NAME = "frida_selfattach"
_MARKER_DESCRIPTION = (
    "run this test in an isolated child pytest process so a native Frida self-attach crash "
    "(access violation) fails only these tests instead of aborting the whole run; auto-applied "
    "to every test in a module that uses the self_attached_bridge fixture"
)
_SELF_ATTACH_FIXTURE = "self_attached_bridge"
_CHILD_ENV_FLAG = "IC_FRIDA_SELFATTACH_ISOLATED_CHILD"
_RESULT_FILE_ENV = "IC_FRIDA_SELFATTACH_RESULT_FILE"
_CHILD_TIMEOUT_SECONDS = 1800.0
_STDOUT_TAIL = 6000
_STDERR_TAIL = 2000

_MODULE_RESULTS: dict[str, ModuleResult] = {}
"""Per-module child results, keyed by the module's rootdir-relative path."""


@dataclass(frozen=True)
class ModuleResult:
    """Outcomes recovered from one isolated module run.

    Attributes:
        outcomes: Node key (the part of a node id after ``::``) mapped to the
            outcome the child reported for it.
        detail: The child's tail output, present when the child exited non-zero.
        complete: ``True`` when the child exited cleanly; ``False`` when it
            crashed or timed out, so unreported tests must be failed.
    """

    outcomes: Mapping[str, _Outcome]
    detail: str | None
    complete: bool


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


def pytest_runtest_logreport(report: TestReport) -> None:
    """Record one phase result when running inside an isolation child.

    Appends (and flushes) each phase as it happens so that a child which dies
    part-way through still leaves usable results for the tests it completed.

    Args:
        report: The phase report pytest just produced.
    """
    if not in_isolated_child():
        return
    result_path = os.environ.get(_RESULT_FILE_ENV)
    if not result_path:
        return
    with Path(result_path).open("a", encoding="utf-8") as handle:
        _ = handle.write(f"{report.nodeid}\t{report.when}\t{report.outcome}\n")


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_protocol(item: pytest.Item, nextitem: pytest.Item | None) -> bool | None:
    """Serve a marked item from its module's isolated child run.

    The first marked item of a module triggers the child run; every later item
    of that module is answered from the cached results.

    Args:
        item: The test item about to run.
        nextitem: The next scheduled item (unused; the child owns teardown).

    Returns:
        bool | None: ``True`` when this hook handled a marked item, ``None`` to
            let pytest run the item normally (unmarked tests, and every test
            inside the isolation child itself).
    """
    _ = nextitem
    if in_isolated_child() or item.get_closest_marker(MARKER_NAME) is None:
        return None
    module_key = str(item.location[0])
    result = _MODULE_RESULTS.get(module_key)
    if result is None:
        result = run_module_isolated(module_key, str(item.config.rootpath))
        _MODULE_RESULTS[module_key] = result
    _emit_reports(item, result)
    return True


def run_target_isolated(
    target: str,
    rootpath: str,
    *,
    timeout_seconds: float = _CHILD_TIMEOUT_SECONDS,
    result_path: str | None = None,
) -> tuple[_Outcome, str | None]:
    """Run one pytest ``target`` in a child process and classify the result.

    This is the containment seam: because the target runs in a separate process,
    a hard abort inside it (a native access violation, or any other abnormal
    termination) ends only the child. The parent observes a non-zero exit code
    and turns it into an ordinary failure instead of dying with the child.

    Args:
        target: A pytest target such as ``tests/.../test_x.py`` or one node id.
        rootpath: Directory to run the child from (the session's rootdir).
        timeout_seconds: Wall-clock ceiling for the child run.
        result_path: Optional file the child appends per-test results to.

    Returns:
        tuple[_Outcome, str | None]: ``("passed", None)`` when the child exited 0,
            otherwise ``("failed", <diagnostic>)`` carrying the child's tail
            output. A native crash surfaces as a non-zero child exit code and is
            therefore reported as a failure rather than aborting the whole run.
    """
    command = [
        sys.executable,
        "-m",
        "pytest",
        target,
        "-p",
        "no:randomly",
        "-p",
        "no:cacheprovider",
        "-o",
        "addopts=",
        "-q",
        "--no-header",
    ]
    child_env = dict(os.environ)
    child_env[_CHILD_ENV_FLAG] = "1"
    if result_path is not None:
        child_env[_RESULT_FILE_ENV] = result_path
    try:
        completed = subprocess.run(
            command,
            cwd=rootpath,
            env=child_env,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        stdout_tail = exc.stdout[-_STDOUT_TAIL:] if isinstance(exc.stdout, str) else ""
        return "failed", f"isolated subprocess for {target} timed out after {timeout_seconds:g}s\n{stdout_tail}"
    if completed.returncode == 0:
        return "passed", None
    detail = f"{completed.stdout[-_STDOUT_TAIL:]}\n{completed.stderr[-_STDERR_TAIL:]}"
    return "failed", (
        f"isolated subprocess for {target} exited {completed.returncode}; a native crash "
        f"(such as a frida-core access violation) surfaces here as a failure of only these tests rather "
        f"than aborting the whole run.\n{detail}"
    )


def _read_child_results(result_path: str) -> dict[str, _Outcome]:
    """Aggregate the per-phase lines a child wrote into one outcome per test.

    A test counts as failed when any phase failed, skipped when it was skipped
    and never failed, and passed otherwise.

    Args:
        result_path: File the child appended ``nodeid<TAB>phase<TAB>outcome`` to.

    Returns:
        dict[str, _Outcome]: Node key mapped to its aggregated outcome.
    """
    outcomes: dict[str, _Outcome] = {}
    raw = Path(result_path)
    if not raw.is_file():
        return outcomes
    for line in raw.read_text(encoding="utf-8").splitlines():
        parts = line.split("\t")
        expected_parts = 3
        if len(parts) != expected_parts:
            continue
        key = _node_key(parts[0])
        reported = parts[2]
        current = outcomes.get(key)
        if reported == "failed" or current is None:
            outcomes[key] = "failed" if reported == "failed" else _as_outcome(reported)
        elif current != "failed" and reported == "skipped":
            outcomes[key] = "skipped"
    return outcomes


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
        outcome, detail = run_target_isolated(module_file, rootpath, result_path=result_path)
        outcomes = _read_child_results(result_path)
    finally:
        Path(result_path).unlink(missing_ok=True)
    return ModuleResult(outcomes=outcomes, detail=detail, complete=outcome == "passed")


def _synthetic_report(item: pytest.Item, when: _Phase, outcome: _Outcome, longrepr: str | None, start: float, stop: float) -> TestReport:
    """Build a :class:`TestReport` describing one phase of an isolated run.

    Args:
        item: The isolated test item.
        when: The run phase (``"setup"``, ``"call"`` or ``"teardown"``).
        outcome: The outcome to record for the phase.
        longrepr: Failure text for a failed phase, else ``None``.
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


def _emit_reports(item: pytest.Item, result: ModuleResult) -> None:
    """Emit this item's reports from its module's isolated child results.

    A test the child never reported -- because the child crashed before reaching
    it -- is failed with the child's diagnostic rather than silently vanishing.

    Args:
        item: The self-attach Frida test being served from cached results.
        result: The cached result of its module's child run.
    """
    outcome = result.outcomes.get(_node_key(item.nodeid))
    if outcome is None:
        outcome = "failed"
        longrepr = result.detail or f"the isolated child running {item.location[0]} never reported a result for this test"
    else:
        longrepr = result.detail if outcome == "failed" else None

    ihook = item.ihook
    ihook.pytest_runtest_logstart(nodeid=item.nodeid, location=item.location)
    at = time.time()
    ihook.pytest_runtest_logreport(report=_synthetic_report(item, "setup", "passed", None, at, at))
    ihook.pytest_runtest_logreport(report=_synthetic_report(item, "call", outcome, longrepr, at, at))
    ihook.pytest_runtest_logreport(report=_synthetic_report(item, "teardown", "passed", None, at, at))
    ihook.pytest_runtest_logfinish(nodeid=item.nodeid, location=item.location)
