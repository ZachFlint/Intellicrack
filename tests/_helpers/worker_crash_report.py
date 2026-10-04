# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Say why a pytest-xdist worker died when Qt killed it.

A worker that hits an access violation or an ``abort`` leaves a
:mod:`faulthandler` dump on standard error, which reaches the session's output.
A Qt fatal message leaves nothing: Qt ends the process on Windows with a
fast-fail that raises no signal and no structured exception, so
:mod:`faulthandler` never runs, and pytest-qt's log capture has taken the
message itself into memory that dies with the process. All the session reports
is ``node down: Not properly terminated`` and the name of whichever test xdist
had last handed the worker, which is how the same death appeared in one CI run
after another under a different test's name and with no cause.

A recording handler writes every fatal message, and the Python stack of every
thread at that moment, to a file belonging to the worker, then passes the
message to the handler it stands in front of. When a worker goes down with an
error the session prints that file.

The recorder has to fit around pytest-qt's capture, whose handler is not
nested with the test phases: it is installed partway through setup and removed
when the call phase is reported. So the recorder is put in front of it once
setup has finished (:func:`record_fatal_messages_in_front_of_capture`) and is
never taken down by this module: pytest-qt removes it together with its own
handler by reinstalling whatever preceded both. Installing and restoring
around each phase instead left one recorder behind per test, each forwarding
to the last, until a message overflowed the stack. Teardown runs after
pytest-qt's handler is gone, so there the recorder is installed and restored
around the phase (:func:`qt_fatal_messages_recorded`). A fatal message raised
while fixtures are still being set up is the one case not recorded.
"""

from __future__ import annotations

import faulthandler
import os
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol

from PyQt6.QtCore import QtMsgType, qInstallMessageHandler


if TYPE_CHECKING:
    from collections.abc import Callable, Generator

    import pytest
    from PyQt6.QtCore import QMessageLogContext

    type _MessageHandler = Callable[[QtMsgType, QMessageLogContext, str | None], None]


FAULT_REPORT_HEADING: Final[str] = "Qt fatal message in worker"
"""How the section the session prints for a dead worker opens."""

NO_RECORD_MESSAGE: Final[str] = "the worker recorded no Qt fatal message: something other than Qt ended it"
"""What the section says when the dead worker left no record."""

XDIST_WORKER_ENV: Final[str] = "PYTEST_XDIST_WORKER"
"""Variable pytest-xdist sets in each worker to its id, such as ``gw0``."""

QT_LOG_CAPTURE_ATTRIBUTE: Final[str] = "qt_log_capture"
"""Attribute pytest-qt sets on a test item once its message capture has started."""

_FAULT_DIRECTORY_NAME: Final[str] = "intellicrack-worker-faults"


class WorkerGateway(Protocol):
    """The part of an execnet gateway the report needs.

    Attributes:
        id: The worker's xdist id, such as ``gw0``.
    """

    id: str


class DownedWorker(Protocol):
    """The part of a pytest-xdist worker controller the report needs.

    Attributes:
        config: The session's pytest configuration.
        gateway: The gateway the session reached the worker through.
    """

    config: pytest.Config
    gateway: WorkerGateway


def fault_file(session_pid: int, worker_id: str) -> Path:
    """Locate the file one worker of one session records Qt fatal messages in.

    Args:
        session_pid: Process id of the session that started the worker.
        worker_id: The worker's xdist id, such as ``gw0``.

    Returns:
        Path: The file. Nothing is created.
    """
    return Path(tempfile.gettempdir(), _FAULT_DIRECTORY_NAME, str(session_pid), f"{worker_id}.log")


def _record_fatal(message: str) -> None:
    """Write a Qt fatal message and every thread's Python stack where the session can find them.

    An xdist worker writes to its own file; any other process writes to the
    standard error it started with.

    Args:
        message: The message Qt is about to end the process over.
    """
    worker_id = os.environ.get(XDIST_WORKER_ENV)
    if worker_id is None:
        stream = sys.__stderr__
        if stream is None:
            return
        _ = stream.write(f"Qt fatal: {message}\n")
        stream.flush()
        faulthandler.dump_traceback(file=stream, all_threads=True)
        return
    path = fault_file(os.getppid(), worker_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        _ = stream.write(f"Qt fatal: {message}\n")
        stream.flush()
        faulthandler.dump_traceback(file=stream, all_threads=True)


def _install_recorder() -> _MessageHandler | None:
    """Put a recording handler in front of whichever handler is installed now.

    A message the recorder has no handler to pass on to is written to standard
    error, where Qt's own default handler would have put it.

    Returns:
        _MessageHandler | None: The handler the recorder now stands in front
        of, or ``None`` when Qt's default one was in place.
    """

    def _handle(mode: QtMsgType, context: QMessageLogContext, message: str | None) -> None:
        """Record a fatal message, then hand the message to the handler this one stands in front of.

        Args:
            mode: The message's severity.
            context: Where Qt raised it.
            message: Its text.
        """
        if mode == QtMsgType.QtFatalMsg:
            _record_fatal(message or "")
        if previous is not None:
            previous(mode, context, message)
        else:
            _ = sys.stderr.write(f"{message or ''}\n")

    previous = qInstallMessageHandler(_handle)
    return previous


def record_fatal_messages_in_front_of_capture(item: pytest.Item) -> None:
    """Record Qt fatal messages for the rest of a test whose pytest-qt capture is running.

    The recorder is left for pytest-qt to remove: when its capture stops it
    reinstalls the handler that preceded its own, which drops the recorder
    with it. A test pytest-qt is not capturing is left alone, since nothing
    would ever remove a recorder installed for it.

    Args:
        item: The test whose setup has just finished.
    """
    if hasattr(item, QT_LOG_CAPTURE_ATTRIBUTE):
        _ = _install_recorder()


@contextmanager
def qt_fatal_messages_recorded() -> Generator[None]:
    """Record every Qt fatal message raised inside the block and put the earlier handler back afterwards.

    For code that runs while nothing else installs or removes a handler, which
    is true of a test's teardown.

    Yields:
        None: While the recording handler is installed.
    """
    previous = _install_recorder()
    try:
        yield
    finally:
        _ = qInstallMessageHandler(previous)


def fatal_report(session_pid: int, worker_id: str) -> str:
    """Read what a worker recorded before it died.

    Args:
        session_pid: Process id of the session that started the worker.
        worker_id: The worker's xdist id.

    Returns:
        str: The record, or an empty string when the worker left none.
    """
    path = fault_file(session_pid, worker_id)
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace").strip()


def report_dead_worker(config: pytest.Config, worker_id: str) -> None:
    """Print a dead worker's Qt fatal record in the session's terminal output.

    Args:
        config: The session's pytest configuration.
        worker_id: The xdist id of the worker that went down with an error.
    """
    reporter = config.pluginmanager.get_plugin("terminalreporter")
    if reporter is None:
        return
    reporter.ensure_newline()
    reporter.write_sep("=", f"{FAULT_REPORT_HEADING} {worker_id}")
    reporter.write_line(fatal_report(os.getpid(), worker_id) or NO_RECORD_MESSAGE)
