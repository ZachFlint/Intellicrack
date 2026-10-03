# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Gate for the record a pytest-xdist worker leaves when Qt kills it.

A Qt fatal message ends a worker without a trace: the message is held in
pytest-qt's capture, which dies with the process, and Qt's fast-fail gives
:mod:`faulthandler` nothing to dump. This gate kills a real worker with a real
Qt fatal message and requires the session's output to carry that message and
the stack of the test that raised it.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final

from PyQt6.QtCore import QtMsgType, qInstallMessageHandler, qWarning

from scripts.sandbox.test_types import to_pyargs_argv
from tests._helpers.worker_crash_report import (
    FAULT_REPORT_HEADING,
    NO_RECORD_MESSAGE,
    fatal_report,
    fault_file,
    qt_fatal_messages_recorded,
)
from tests.test_core.worker_crash_probe import FATAL_MESSAGE


if TYPE_CHECKING:
    import pytest
    from PyQt6.QtCore import QMessageLogContext


_GATE_TIMEOUT_SECONDS: Final[float] = 180.0
_PROBE_FRAME: Final[str] = " in test_dies_of_a_qt_fatal_message"
"""How :mod:`faulthandler` names the probe's frame in a stack dump: ``File "...", line N in test_dies_of_a_qt_fatal_message``.

The session's own crash summary names the probe too, but as a node id ending ``::test_dies_of_a_qt_fatal_message``, so only a real
stack dump carries this form.
"""
_SESSION_PID: Final[int] = 4242
_WORKER_ID: Final[str] = "gw7"
_WARNING_TEXT: Final[str] = "worker crash report gate: an ordinary warning"


def test_a_worker_killed_by_a_qt_fatal_message_is_reported_with_the_message_and_its_stack(pytestconfig: pytest.Config) -> None:
    """The session prints the fatal message that ended the worker and the stack of the test that raised it.

    Runs a real pytest session with one xdist worker over a probe that raises
    a Qt fatal message.

    Falsifiable: with no handler recording fatal messages, pytest-qt's capture
    takes the message to the grave and the output holds only "node down: Not
    properly terminated".

    Args:
        pytestconfig: Session config, used for the rootdir the session runs from.
    """
    rootpath = pytestconfig.rootpath
    probe = (Path(__file__).resolve().parent / "worker_crash_probe.py").relative_to(rootpath).as_posix()
    command = [
        sys.executable,
        "-m",
        "pytest",
        *to_pyargs_argv([probe, "-n", "1", "-p", "no:randomly", "-p", "no:cacheprovider", "-o", "addopts=", "-v", "--no-header"]),
    ]
    completed = subprocess.run(command, cwd=rootpath, capture_output=True, text=True, check=False, timeout=_GATE_TIMEOUT_SECONDS)
    output = f"{completed.stdout}\n{completed.stderr}"

    assert "Not properly terminated" in output, f"the probe never took its worker down:\n{output}"
    assert FAULT_REPORT_HEADING in output, f"the session did not report the dead worker:\n{output}"
    assert NO_RECORD_MESSAGE not in output, f"the dead worker left no record of the fatal message:\n{output}"
    assert FATAL_MESSAGE in output, f"the fatal message that ended the worker is not in the session's output:\n{output}"
    assert _PROBE_FRAME in output, f"the report holds no stack frame for the test that raised the fatal message:\n{output}"


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
