# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Probes for the worker crash report gate, run only by that gate.

The file name does not match ``python_files``, so the normal suite never
collects it. :mod:`tests.test_core.test_worker_crash_report` passes it to real
pytest runs and picks the probes it wants by keyword.

Two of them die of a Qt fatal message, one while the test body runs and one
while a fixture tears down, which ends the worker the way a ``QThread``
destroyed while running does: Qt ends the process without raising anything
:mod:`faulthandler` can see. The rest stay alive and check that the recorder
neither piles up across many tests nor takes pytest-qt's own message capture
away from the test.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, Protocol

import pytest
from PyQt6.QtCore import qFatal, qWarning


if TYPE_CHECKING:
    from collections.abc import Generator, Sequence


FATAL_MESSAGE: Final[str] = "intellicrack worker crash probe: this fatal message is deliberate"
WARNING_MESSAGE: Final[str] = "intellicrack worker crash probe: an ordinary warning"
MANY_TESTS: Final[int] = 1200
"""More tests than Python's recursion limit has frames, so a recorder left behind per test overflows the stack."""


class CapturedMessage(Protocol):
    """The part of a pytest-qt message record the probe reads.

    Attributes:
        message: The message's text.
    """

    message: str


class MessageCapture(Protocol):
    """The part of pytest-qt's ``qtlog`` fixture the probe reads.

    Attributes:
        records: The messages captured for the running test, oldest first.
    """

    records: Sequence[CapturedMessage]


@pytest.fixture
def fatal_teardown() -> Generator[None]:
    """Raise a Qt fatal message while tearing down.

    Yields:
        None: While the test body runs.
    """
    yield
    qFatal(FATAL_MESSAGE)


def test_fatal_in_call_phase() -> None:
    """End the worker process through Qt's fatal message path from the test body."""
    qFatal(FATAL_MESSAGE)


@pytest.mark.usefixtures("fatal_teardown")
def test_fatal_in_teardown_phase() -> None:
    """Pass, then end the worker process from a fixture's teardown."""


@pytest.mark.parametrize("index", range(MANY_TESTS))
def test_survivor_filler(index: int) -> None:
    """Do nothing, many times over, so any per-test residue has room to accumulate.

    Args:
        index: Which of the many repetitions this is.
    """
    assert index >= 0


@pytest.mark.qt_log_level_fail("NO")
def test_survivor_warning_reaches_the_capture(qtlog: MessageCapture) -> None:
    """After all the filler tests, an ordinary Qt warning still lands in pytest-qt's capture and nothing overflows.

    Args:
        qtlog: pytest-qt's view of the messages captured for this test.
    """
    qWarning(WARNING_MESSAGE)

    assert WARNING_MESSAGE in [record.message.strip() for record in qtlog.records]
