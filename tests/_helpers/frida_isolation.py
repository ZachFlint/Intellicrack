# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Subprocess isolation for the real self-attach Frida bridge tests.

Every test that self-attaches Frida into the pytest process (the ones that
request the ``self_attached_bridge`` fixture) is run in a dedicated child
``pytest`` process. Frida self-attach exercises native frida-core/Gum code that,
rarely and non-deterministically, raises a ``Windows fatal exception: access
violation`` deep in a full-suite run -- a native abort that terminates the whole
pytest process (exit 255, no junit) rather than failing a single test, which is
why the ``python-test`` CI job never reports.

Because a child process that faults returns its exit code to the parent instead
of taking the parent down with it, running each self-attach test in a child
contains such a crash: the parent records that one test as failed (with the
child's output) and the rest of the suite completes. Isolation is keyed on the
``self_attached_bridge`` fixture -- the only real ``attach(os.getpid())`` surface
-- so the fake-backed Frida tests keep running in-process at full speed.

The plugin is registered from ``tests/conftest.py`` so it loads for the whole
session regardless of optional native modules; its hooks are no-ops for every
test that is not a Frida self-attach test.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
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
    "(access violation) fails only this test instead of aborting the whole run; auto-applied "
    "to every test that requests the self_attached_bridge fixture"
)
_SELF_ATTACH_FIXTURE = "self_attached_bridge"
_CHILD_ENV_FLAG = "IC_FRIDA_SELFATTACH_ISOLATED_CHILD"
_CHILD_TIMEOUT_SECONDS = 240.0
_STDOUT_TAIL = 6000
_STDERR_TAIL = 2000


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


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Mark every self-attach Frida test for subprocess isolation.

    Args:
        items: The collected test items, modified in place.
    """
    for item in items:
        if _SELF_ATTACH_FIXTURE in getattr(item, "fixturenames", ()):
            item.add_marker(MARKER_NAME)


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_protocol(item: pytest.Item, nextitem: pytest.Item | None) -> bool | None:
    """Run a marked self-attach Frida test in an isolated child process.

    Args:
        item: The test item about to run.
        nextitem: The next scheduled item (unused; the child owns teardown).

    Returns:
        bool | None: ``True`` when this hook fully handled a marked item in a
            child process (short-circuiting the default protocol); ``None`` to let
            pytest run the item normally (unmarked tests, and every test inside the
            isolation child itself).
    """
    _ = nextitem
    if in_isolated_child() or item.get_closest_marker(MARKER_NAME) is None:
        return None
    _run_item_isolated(item)
    return True


def _child_target(item: pytest.Item) -> str:
    """Return the collectable ``file::node`` target for ``item``'s own file.

    Uses ``item.location`` (the file path relative to the rootdir) rather than the
    node id's path component so the child collects the real file regardless of how
    the parent addressed it (``--pyargs`` rewrites the path component to a dotted
    module).

    Args:
        item: The test item to address in the child.

    Returns:
        str: A pytest target such as ``tests/bridges/.../test_x.py::TestC::test_y``.
    """
    file_rel = str(item.location[0])
    _, separator, node_part = item.nodeid.partition("::")
    return f"{file_rel}::{node_part}" if separator else file_rel


def _run_child(item: pytest.Item) -> tuple[_Outcome, str | None]:
    """Run ``item`` in a child pytest process and classify the result.

    Args:
        item: The self-attach Frida test to run in isolation.

    Returns:
        tuple[_Outcome, str | None]: The outcome reported by
            :func:`run_target_isolated` for this item's own target.
    """
    return run_target_isolated(_child_target(item), str(item.config.rootpath))


def run_target_isolated(
    target: str,
    rootpath: str,
    *,
    timeout_seconds: float = _CHILD_TIMEOUT_SECONDS,
) -> tuple[_Outcome, str | None]:
    """Run one pytest ``target`` in a child process and classify the result.

    This is the containment seam: because the target runs in a separate process,
    a hard abort inside it (a native access violation, or any other abnormal
    termination) ends only the child. The parent observes a non-zero exit code
    and turns it into an ordinary failure instead of dying with the child.

    Args:
        target: A pytest target such as ``tests/.../test_x.py::TestC::test_y``.
        rootpath: Directory to run the child from (the session's rootdir).
        timeout_seconds: Wall-clock ceiling for the child run.

    Returns:
        tuple[_Outcome, str | None]: ``("passed", None)`` when the child exited 0,
            otherwise ``("failed", <diagnostic>)`` carrying the child's tail
            output. A native crash surfaces as a non-zero child exit code and is
            therefore reported as a normal failure of this one test.
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
        f"(such as a frida-core access violation) surfaces here as a failure of only this test rather than "
        f"aborting the whole run.\n{detail}"
    )


def _synthetic_report(item: pytest.Item, when: _Phase, outcome: _Outcome, longrepr: str | None, start: float, stop: float) -> TestReport:
    """Build a :class:`TestReport` describing one phase of an isolated run.

    Args:
        item: The isolated test item.
        when: The run phase (``"setup"``, ``"call"`` or ``"teardown"``).
        outcome: ``"passed"`` or ``"failed"``.
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


def _run_item_isolated(item: pytest.Item) -> None:
    """Drive one item through an isolated child run and emit its reports.

    Emits a passed ``setup`` and ``teardown`` (the child owns real setup and
    teardown) around a ``call`` report whose outcome is the child's result, so
    pytest counts the test and writes it to junit exactly as an in-process run.

    Args:
        item: The self-attach Frida test to run in isolation.
    """
    ihook = item.ihook
    ihook.pytest_runtest_logstart(nodeid=item.nodeid, location=item.location)
    setup_at = time.time()
    ihook.pytest_runtest_logreport(report=_synthetic_report(item, "setup", "passed", None, setup_at, setup_at))
    call_start = time.time()
    outcome, longrepr = _run_child(item)
    call_stop = time.time()
    ihook.pytest_runtest_logreport(report=_synthetic_report(item, "call", outcome, longrepr, call_start, call_stop))
    ihook.pytest_runtest_logreport(report=_synthetic_report(item, "teardown", "passed", None, call_stop, call_stop))
    ihook.pytest_runtest_logfinish(nodeid=item.nodeid, location=item.location)
