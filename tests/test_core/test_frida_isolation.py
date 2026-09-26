# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gate for the Frida self-attach subprocess isolation.

The real self-attach Frida tests are run in a child process by
:mod:`tests._helpers.frida_isolation` so that a native frida-core access
violation -- which aborts the whole pytest process (exit 255, no junit) and is
why the ``python-test`` CI job can fail to report -- fails only the offending
test. This module proves that containment with a real child process that really
dies abnormally, rather than asserting on a simulated result.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import defusedxml.ElementTree as DefusedET
import pytest

from tests._helpers.frida_isolation import run_module_isolated, run_target_isolated
from tests.test_core.frida_isolation_skip_probe import CALL_SKIP_REASON, SETUP_SKIP_REASON


if TYPE_CHECKING:
    from _pytest.monkeypatch import MonkeyPatch


_CRASH_PROBE_ENV = "IC_FRIDA_ISOLATION_CRASH_PROBE"
_GATE_TIMEOUT_SECONDS = 180.0
_PROBE_NAME = "test_isolation_crash_probe"


def test_isolation_crash_probe() -> None:
    """Abort this process on purpose, but only when the containment gate arms it.

    Left unarmed this skips, which makes it the gate's positive control (a child
    that exits cleanly must be classified ``passed``). Armed through
    :data:`_CRASH_PROBE_ENV` it calls :func:`os.abort`, killing its process
    without Python-level cleanup -- exactly the kind of abnormal death that would
    take the whole run down if it happened in the parent.
    """
    if os.environ.get(_CRASH_PROBE_ENV) != "1":
        pytest.skip("crash probe runs only inside the containment gate's child process")
    os.abort()


def test_isolation_contains_a_hard_child_crash(pytestconfig: pytest.Config, monkeypatch: MonkeyPatch) -> None:
    """A target whose process dies abnormally is reported failed, not propagated.

    Runs the same probe target twice through the real isolation seam: unarmed it
    must come back ``passed``, then armed -- where the child genuinely calls
    :func:`os.abort` -- it must come back ``failed`` with the child's exit code.

    Falsifiable three ways. If ``run_target_isolated`` stopped using a child
    process and ran the target in-process, the armed probe would abort *this*
    process and the run would die before reaching the final assertions. If it
    misclassified a crashed child as success, the ``failed`` assertion fails. If
    it reported every child as a failure, the unarmed ``passed`` assertion fails.

    Args:
        pytestconfig: Session config, used for the rootdir the child runs from.
        monkeypatch: Fixture used to arm the crash probe for the child only.
    """
    rootpath = pytestconfig.rootpath
    target = f"{Path(__file__).resolve().relative_to(rootpath).as_posix()}::{_PROBE_NAME}"

    clean_outcome, clean_detail = run_target_isolated(target, str(rootpath), timeout_seconds=_GATE_TIMEOUT_SECONDS)
    assert clean_outcome == "passed", f"an unarmed probe child exits cleanly and must be classified passed: {clean_detail}"

    monkeypatch.setenv(_CRASH_PROBE_ENV, "1")
    crash_outcome, crash_detail = run_target_isolated(target, str(rootpath), timeout_seconds=_GATE_TIMEOUT_SECONDS)

    assert crash_outcome == "failed", "a child process that aborts must be reported as a failed test"
    assert crash_detail is not None
    assert "exited" in crash_detail, f"the crash must be observed as a non-zero child exit, got: {crash_detail}"


def test_run_module_isolated_recovers_per_test_outcomes(pytestconfig: pytest.Config) -> None:
    """A whole module run in one child still yields an outcome for each of its tests.

    Per-module isolation only pays for itself if the parent can still report each
    test individually, which depends on the child streaming its results out to the
    result file. This runs a real sibling module in a real child and checks the
    outcomes come back per test.

    Falsifiable: if the child stopped writing results, or the parent parsed or
    keyed them wrongly, the recovered mapping would be empty (or miss the known
    test names) and this fails -- which is exactly the regression that would make
    every isolated test report as a spurious failure.

    Args:
        pytestconfig: Session config, used for the rootdir the child runs from.
    """
    rootpath = pytestconfig.rootpath
    sibling = Path(__file__).resolve().parent / "test_thread_leak_guard.py"
    module_rel = sibling.relative_to(rootpath).as_posix()

    result = run_module_isolated(module_rel, str(rootpath))

    assert result.complete, f"the sibling module must run cleanly in a child: {result.detail}"
    assert result.outcomes, "the child must report per-test outcomes back to the parent"
    assert "test_find_leaked_ignores_idle_thread_pool_worker" in result.outcomes
    assert all(outcome == "passed" for outcome in result.outcomes.values()), f"unexpected outcomes: {result.outcomes}"


def test_skipped_isolated_tests_are_reported_with_their_reasons(pytestconfig: pytest.Config, tmp_path: Path) -> None:
    """A self-attach module whose tests skip is reported as skipped, with the child's reasons.

    Runs a real pytest session over a probe module that uses the
    ``self_attached_bridge`` fixture, so its tests are served from an isolated
    child. One test skips in its fixture, one in its body, one passes. The
    session must finish cleanly with each skip reason in the terminal summary
    and in the JUnit report.

    Falsifiable: when the parent rebuilt a skipped report without the
    ``(path, lineno, reason)`` tuple pytest requires, the terminal reporter
    raised an INTERNALERROR and the session ended without its JUnit report.

    Args:
        pytestconfig: Session config, used for the rootdir the session runs from.
        tmp_path: Per-test temporary directory for the JUnit report.
    """
    rootpath = pytestconfig.rootpath
    probe = (Path(__file__).resolve().parent / "frida_isolation_skip_probe.py").relative_to(rootpath).as_posix()
    junit = tmp_path / "junit.xml"
    command = [
        sys.executable,
        "-m",
        "pytest",
        probe,
        "-p",
        "no:randomly",
        "-p",
        "no:cacheprovider",
        "-o",
        "addopts=",
        "-v",
        "-rA",
        "--no-header",
        f"--junitxml={junit}",
    ]
    completed = subprocess.run(command, cwd=rootpath, capture_output=True, text=True, check=False, timeout=_GATE_TIMEOUT_SECONDS)
    output = f"{completed.stdout}\n{completed.stderr}"

    assert "INTERNALERROR" not in output, output
    assert completed.returncode == 0, output
    assert "1 passed, 2 skipped" in output, output
    assert f"{probe}:29: {SETUP_SKIP_REASON}" in output, output
    assert f"{probe}:40: {CALL_SKIP_REASON}" in output, output

    report = DefusedET.fromstring(junit.read_text(encoding="utf-8"))
    cases = {case.get("name"): case for case in report.iter("testcase")}
    setup_skip = cases["test_skips_in_setup"].find("skipped")
    call_skip = cases["test_skips_in_call"].find("skipped")
    assert setup_skip is not None
    assert call_skip is not None
    assert setup_skip.get("message") == SETUP_SKIP_REASON
    assert call_skip.get("message") == CALL_SKIP_REASON
    assert cases["test_passes"].find("skipped") is None
