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
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from tests._helpers.frida_isolation import run_target_isolated


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
