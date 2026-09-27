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

It also gates coverage of that containment. Three modules once self-attached
through a fixture not named ``self_attached_bridge``, so they injected the Frida
agent into the pytest process itself; the access violation that agent left
behind surfaced later in unrelated tests (a LIEF section walk, a Qt paint event)
and killed the CI run. The classifier gate below fails the moment any test
module self-attaches without declaring isolation.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import TYPE_CHECKING

import defusedxml.ElementTree as DefusedET
import pytest

from scripts.sandbox.test_types import to_pyargs_argv
from tests._helpers.frida_isolation import (
    classify_self_attach_modules,
    declares_isolation,
    run_module_isolated,
    run_target_isolated,
    self_attaches_frida,
)
from tests.test_core.frida_isolation_marker_probe import PROCESS_REPORT_ENV
from tests.test_core.frida_isolation_skip_probe import CALL_SKIP_REASON, SETUP_SKIP_REASON


if TYPE_CHECKING:
    from _pytest.monkeypatch import MonkeyPatch


_CRASH_PROBE_ENV = "IC_FRIDA_ISOLATION_CRASH_PROBE"
_GATE_TIMEOUT_SECONDS = 180.0
_PROBE_NAME = "test_isolation_crash_probe"
_TESTS_ROOT = Path(__file__).resolve().parents[1]
_ISOLATED_CHILD_REPORT = "True"

_FORMERLY_UNISOLATED_MODULES = (
    "tests/bridges/completeness/frida/test_frida_lifecycle_scripting.py",
    "tests/bridges/completeness/frida/test_frida_panel_wiring.py",
    "tests/ui/test_frida_instruction_disassemble_control.py",
)
"""Modules that self-attached in-process until isolation covered module-level marking."""

_SELF_ATTACH_SOURCE = """
    import os
    from intellicrack.bridges.frida_bridge import FridaBridge

    def attached():
        bridge = FridaBridge()
        run(bridge.initialize())
        run(bridge.attach(os.getpid()))
        return bridge
"""
_REGISTRY_SELF_ATTACH_SOURCE = """
    import os
    import frida

    def test_dispatch(registry):
        run(registry.initialize())
        run(registry.execute_tool_call("frida", "frida.attach", {"pid": str(os.getpid())}))
"""
_FAKE_DEVICE_SOURCE = """
    import os
    from intellicrack.bridges.frida_bridge import FridaBridge

    _SPAWN_PID = os.getpid()

    def test_spawn_uses_fake_device():
        bridge = FridaBridge()
        bridge.set_device(_FakeDevice(spawn_pid=_SPAWN_PID))
"""
_NO_FRIDA_SOURCE = """
    import os

    def test_attach_process_bridge(panel):
        run(panel.initialize())
        panel.attach(os.getpid())
"""
_MODULE_MARK_LIST_SUFFIX = """
    pytestmark = [pytest.mark.usefixtures("qapp"), pytest.mark.frida_selfattach]
"""
_MODULE_MARK_ANNOTATED_SUFFIX = """
    pytestmark: object = pytest.mark.frida_selfattach
"""
_FIXTURE_REQUEST_SUFFIX = """
    def test_uses_fixture(self_attached_bridge):
        del self_attached_bridge
"""
_USEFIXTURES_SUFFIX = """
    @pytest.mark.usefixtures("self_attached_bridge")
    def test_uses_fixture_by_name():
        pass
"""
_CLASS_MARK_SUFFIX = """
    class TestOnlyThisClass:
        pytestmark = pytest.mark.frida_selfattach
"""
_OTHER_MARK_SUFFIX = """
    pytestmark = pytest.mark.usefixtures("qapp")
"""
_UNRELATED_ATTRIBUTE_SUFFIX = """
    pytestmark = config.frida_selfattach
"""


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
    location = Path(probe)
    junit = tmp_path / "junit.xml"
    command = [
        sys.executable,
        "-m",
        "pytest",
        *to_pyargs_argv([
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
            "--color=no",
            f"--junitxml={junit}",
        ]),
    ]
    completed = subprocess.run(command, cwd=rootpath, capture_output=True, text=True, check=False, timeout=_GATE_TIMEOUT_SECONDS)
    output = f"{completed.stdout}\n{completed.stderr}"

    assert "INTERNALERROR" not in output, output
    assert completed.returncode == 0, output
    assert "1 passed, 2 skipped" in output, output
    assert f"{location}:29: {SETUP_SKIP_REASON}" in output, output
    assert f"{location}:40: {CALL_SKIP_REASON}" in output, output

    report = DefusedET.fromstring(junit.read_text(encoding="utf-8"))
    cases = {case.get("name"): case for case in report.iter("testcase")}
    setup_skip = cases["test_skips_in_setup"].find("skipped")
    call_skip = cases["test_skips_in_call"].find("skipped")
    assert setup_skip is not None
    assert call_skip is not None
    assert setup_skip.get("message") == SETUP_SKIP_REASON
    assert call_skip.get("message") == CALL_SKIP_REASON
    assert cases["test_passes"].find("skipped") is None


def _parse(source: str) -> ast.Module:
    """Parse indented test-module source.

    Args:
        source: Module source indented like the constants in this module.

    Returns:
        ast.Module: The parsed module.
    """
    return ast.parse(textwrap.dedent(source))


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        pytest.param(_SELF_ATTACH_SOURCE, True, id="direct-bridge-attach"),
        pytest.param(_REGISTRY_SELF_ATTACH_SOURCE, True, id="registry-dispatch"),
        pytest.param(_FAKE_DEVICE_SOURCE, False, id="fake-device-only"),
        pytest.param(_NO_FRIDA_SOURCE, False, id="non-frida-attach"),
    ],
)
def test_classifier_recognises_real_self_attach(source: str, *, expected: bool) -> None:
    """Only a real Frida device aimed at the current process counts as self-attach.

    Falsifiable: dropping the device requirement flags the fake-device module
    (which only hands ``os.getpid()`` to a test double), dropping the Frida import
    requirement flags the process-bridge module, and matching only the literal
    ``bridge.attach(os.getpid())`` form misses the registry dispatch that
    ``test_frida_lifecycle_scripting`` uses.

    Args:
        source: Test-module source to classify.
        expected: Whether that source performs a real Frida self-attach.
    """
    assert self_attaches_frida(_parse(source)) is expected


@pytest.mark.parametrize(
    ("suffix", "expected"),
    [
        pytest.param("", False, id="undeclared"),
        pytest.param(_MODULE_MARK_LIST_SUFFIX, True, id="module-mark-list"),
        pytest.param(_MODULE_MARK_ANNOTATED_SUFFIX, True, id="module-mark-annotated"),
        pytest.param(_FIXTURE_REQUEST_SUFFIX, True, id="fixture-parameter"),
        pytest.param(_USEFIXTURES_SUFFIX, True, id="usefixtures-by-name"),
        pytest.param(_CLASS_MARK_SUFFIX, False, id="class-level-mark-only"),
        pytest.param(_OTHER_MARK_SUFFIX, False, id="unrelated-mark"),
        pytest.param(_UNRELATED_ATTRIBUTE_SUFFIX, False, id="attribute-not-on-mark"),
    ],
)
def test_isolation_declarations_are_recognised(suffix: str, *, expected: bool) -> None:
    """Exactly the declarations the plugin honours count as isolation.

    Falsifiable: accepting a class-level ``pytestmark`` would pass a module whose
    other tests still self-attach in the parent, and failing to accept the list
    form would reject the declaration ``test_frida_instruction_disassemble_control``
    actually uses.

    Args:
        suffix: Declaration appended to a self-attaching module.
        expected: Whether the plugin will isolate the resulting module.
    """
    tree = _parse(_SELF_ATTACH_SOURCE + suffix)

    assert self_attaches_frida(tree)
    assert declares_isolation(tree) is expected


def test_every_frida_self_attach_module_runs_isolated() -> None:
    """No test module may inject the Frida agent into the pytest process itself.

    Falsifiable: removing the ``frida_selfattach`` ``pytestmark`` from any of the
    three formerly unisolated modules lists that module here, and a classifier
    that stopped recognising them fails the coverage assertion before the
    isolation assertion could pass vacuously.
    """
    classified = {
        path.relative_to(_TESTS_ROOT.parent).as_posix(): isolated for path, isolated in classify_self_attach_modules(_TESTS_ROOT).items()
    }

    unrecognised = [module for module in _FORMERLY_UNISOLATED_MODULES if module not in classified]
    assert not unrecognised, f"the classifier no longer recognises these Frida self-attach modules: {unrecognised}"

    unisolated = sorted(module for module, isolated in classified.items() if not isolated)
    assert not unisolated, (
        f"these modules self-attach Frida to the pytest process without isolation: {unisolated}. An in-process "
        f"Frida agent can leave a native fault that aborts the whole run later, in an unrelated test. Request the "
        f"self_attached_bridge fixture or declare a module-level pytestmark = pytest.mark.frida_selfattach."
    )


def test_module_level_marker_runs_the_module_in_a_child(pytestconfig: pytest.Config, tmp_path: Path) -> None:
    """A module isolated only by its ``pytestmark`` really runs in a child process.

    Runs a real pytest session over a probe module that declares the marker but
    requests no ``self_attached_bridge`` fixture. The probe records whether it ran
    in the isolation child and which process started it.

    Falsifiable: if the plugin served only fixture-detected modules and ignored
    an explicit module-level marker, the probe would run inside the session this
    gate starts, report that it is not an isolation child, and name this gate's
    process as its parent.

    Args:
        pytestconfig: Session config, used for the rootdir the session runs from.
        tmp_path: Per-test temporary directory for the probe's process report.
    """
    rootpath = pytestconfig.rootpath
    probe = (Path(__file__).resolve().parent / "frida_isolation_marker_probe.py").relative_to(rootpath).as_posix()
    report = tmp_path / "process.txt"
    command = [
        sys.executable,
        "-m",
        "pytest",
        *to_pyargs_argv([probe, "-p", "no:randomly", "-p", "no:cacheprovider", "-o", "addopts=", "-q", "--no-header"]),
    ]
    env = {**os.environ, PROCESS_REPORT_ENV: str(report)}
    completed = subprocess.run(
        command,
        cwd=rootpath,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=_GATE_TIMEOUT_SECONDS,
    )
    output = f"{completed.stdout}\n{completed.stderr}"

    assert completed.returncode == 0, output
    assert "1 passed" in output, output
    assert report.is_file(), f"the probe never reported the process it ran in:\n{output}"
    in_child, parent_pid = report.read_text(encoding="utf-8").split("\t")
    assert in_child == _ISOLATED_CHILD_REPORT, "the marked probe ran without the isolation child's environment"
    assert int(parent_pid) != os.getpid(), "the marked probe ran inside the session process, not an isolation child"
