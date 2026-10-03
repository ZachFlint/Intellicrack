# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Gate for the record a pytest-xdist worker leaves when Qt kills it.

A Qt fatal message ends a worker without a trace: the message is held in
pytest-qt's capture, which dies with the process, and Qt's fast-fail gives
:mod:`faulthandler` nothing to dump. These gates kill real workers with real Qt
fatal messages, from a test body and from a fixture's teardown, and require the
session's output to carry the message and the stack of the test that raised it.

They also hold the recorder to leaving everything else alone. Its first form
was installed and restored around each test phase, which is not how pytest-qt's
own handler lives: that one is installed during setup and removed when the call
phase is reported. The mismatch left one recorder behind per test, each
forwarding to the last, and took pytest-qt's capture away from the test body.
A session of more tests than the recursion limit has frames must therefore
still pass, with a warning raised at its end landing in pytest-qt's capture.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtCore import QtMsgType, qInstallMessageHandler, qWarning

from scripts.sandbox.test_types import to_pyargs_argv
from tests._helpers.worker_crash_report import (
    FAULT_REPORT_HEADING,
    NO_RECORD_MESSAGE,
    fatal_report,
    fault_file,
    qt_fatal_messages_recorded,
)
from tests.test_core.worker_crash_probe import FATAL_MESSAGE, MANY_TESTS


if TYPE_CHECKING:
    from PyQt6.QtCore import QMessageLogContext


_GATE_TIMEOUT_SECONDS: Final[float] = 300.0
_SESSION_PID: Final[int] = 4242
_WORKER_ID: Final[str] = "gw7"
_WARNING_TEXT: Final[str] = "worker crash report gate: an ordinary warning"
_SURVIVORS: Final[int] = MANY_TESTS + 1


def _run_probes(rootpath: Path, keyword: str, *extra: str) -> subprocess.CompletedProcess[str]:
    """Run the probes a keyword selects in a real pytest session.

    Args:
        rootpath: The rootdir the session runs from.
        keyword: The ``-k`` expression choosing the probes.
        *extra: Further pytest arguments.

    Returns:
        subprocess.CompletedProcess[str]: The finished session.
    """
    probe = (Path(__file__).resolve().parent / "worker_crash_probe.py").relative_to(rootpath).as_posix()
    arguments = [probe, "-k", keyword, "-p", "no:randomly", "-p", "no:cacheprovider", "-o", "addopts=", "--no-header", *extra]
    command = [sys.executable, "-m", "pytest", *to_pyargs_argv(arguments)]
    return subprocess.run(command, cwd=rootpath, capture_output=True, text=True, check=False, timeout=_GATE_TIMEOUT_SECONDS)


@pytest.mark.parametrize("phase", ["call", "teardown"])
def test_a_worker_killed_by_a_qt_fatal_message_is_reported_with_the_message_and_its_stack(pytestconfig: pytest.Config, phase: str) -> None:
    """The session prints the fatal message that ended the worker and the stack of the test that raised it.

    Runs a real pytest session with one xdist worker over a probe that raises
    a Qt fatal message, from the test body or from a fixture's teardown.

    Falsifiable: with no handler recording fatal messages, the message dies
    with the worker and the output holds only "node down: Not properly
    terminated".

    Args:
        pytestconfig: Session config, used for the rootdir the session runs from.
        phase: The test phase the probe raises its fatal message in.
    """
    completed = _run_probes(pytestconfig.rootpath, f"test_fatal_in_{phase}_phase", "-n", "1", "-v")
    output = f"{completed.stdout}\n{completed.stderr}"

    assert "Not properly terminated" in output, f"the probe never took its worker down:\n{output}"
    assert FAULT_REPORT_HEADING in output, f"the session did not report the dead worker:\n{output}"
    assert NO_RECORD_MESSAGE not in output, f"the dead worker left no record of the fatal message:\n{output}"
    assert FATAL_MESSAGE in output, f"the fatal message that ended the worker is not in the session's output:\n{output}"
    assert "worker_crash_probe.py" in output.split(FATAL_MESSAGE, 1)[1], f"the report holds no stack for the probe:\n{output}"


def test_a_long_session_keeps_one_recorder_and_pytest_qts_capture(pytestconfig: pytest.Config) -> None:
    """More tests than the recursion limit has frames all pass, and a warning at the end still reaches pytest-qt's capture.

    Falsifiable: a recorder installed and restored around each phase leaves
    one behind per test, so the warning at the end overflows the stack on its
    way down the chain; and it replaces pytest-qt's handler before the test
    body runs, so the capture the last probe reads is empty.

    Args:
        pytestconfig: Session config, used for the rootdir the session runs from.
    """
    completed = _run_probes(pytestconfig.rootpath, "test_survivor", "-q")
    output = f"{completed.stdout}\n{completed.stderr}"

    assert completed.returncode == 0, output
    assert f"{_SURVIVORS} passed" in output, output


def test_recording_leaves_other_qt_messages_with_the_handler_that_was_installed() -> None:
    """A message that is not fatal still reaches the handler installed before the recording, and that handler is restored after."""
    seen: list[tuple[QtMsgType, str | None]] = []

    def _collect(mode: QtMsgType, _context: QMessageLogContext, message: str | None) -> None:
        """Keep each message handed to the handler under test.

        Args:
            mode: The message's severity.
            _context: Where Qt raised it.
            message: Its text.
        """
        seen.append((mode, message))

    outer = qInstallMessageHandler(_collect)
    try:
        with qt_fatal_messages_recorded():
            qWarning(_WARNING_TEXT)
        restored = qInstallMessageHandler(_collect)
    finally:
        _ = qInstallMessageHandler(outer)

    assert (QtMsgType.QtWarningMsg, _WARNING_TEXT) in seen
    assert restored is _collect, "leaving the recording did not put the earlier handler back"


def test_a_worker_that_left_no_record_reads_back_empty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A worker with no record file reads back as an empty report rather than an error.

    Args:
        tmp_path: Per-test directory standing in for the temporary directory.
        monkeypatch: Points the temporary directory at ``tmp_path``.
    """
    monkeypatch.setattr("tempfile.tempdir", str(tmp_path))

    assert not fatal_report(_SESSION_PID, _WORKER_ID)
    assert fault_file(_SESSION_PID, _WORKER_ID).is_relative_to(tmp_path)
