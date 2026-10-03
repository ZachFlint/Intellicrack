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

While a test phase runs, a Qt message handler installed inside pytest-qt's own
writes every fatal message, and the Python stack of every thread at that
moment, to a file belonging to the worker, then passes the message on so
pytest-qt's capture is unchanged. When a worker goes down with an error the
session prints that file.
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
    from collections.abc import Generator

    import pytest
    from PyQt6.QtCore import QMessageLogContext


FAULT_REPORT_HEADING: Final[str] = "Qt fatal message in worker"
"""How the section the session prints for a dead worker opens."""

NO_RECORD_MESSAGE: Final[str] = "the worker recorded no Qt fatal message: something other than Qt ended it"
"""What the section says when the dead worker left no record."""

XDIST_WORKER_ENV: Final[str] = "PYTEST_XDIST_WORKER"
"""Variable pytest-xdist sets in each worker to its id, such as ``gw0``."""

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


@contextmanager
def qt_fatal_messages_recorded() -> Generator[None]:
    """Record every Qt fatal message raised inside the block, leaving other handling as it was.

    The handler that was installed before the block still receives every
    message, so pytest-qt's capture sees exactly what it saw before.

    Yields:
        None: While the recording handler is installed.
    """

    def _handle(mode: QtMsgType, context: QMessageLogContext, message: str | None) -> None:
        """Record a fatal message, then hand the message to the handler this one replaced.

        Args:
            mode: The message's severity.
            context: Where Qt raised it.
            message: Its text.
        """
        if mode == QtMsgType.QtFatalMsg:
            _record_fatal(message or "")
        if previous is not None:
            previous(mode, context, message)

    previous = qInstallMessageHandler(_handle)
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
