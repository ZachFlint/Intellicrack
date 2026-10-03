# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Probe that dies of a Qt fatal message, run only by the worker crash report gate.

The file name does not match ``python_files``, so the normal suite never
collects it. :mod:`tests.test_core.test_worker_crash_report` passes it to a real
pytest run under xdist, where the fatal message below ends the worker the way a
``QThread`` destroyed while running does: Qt ends the process without raising
anything :mod:`faulthandler` can see.
"""

from __future__ import annotations

from typing import Final

from PyQt6.QtCore import qFatal


FATAL_MESSAGE: Final[str] = "intellicrack worker crash probe: this fatal message is deliberate"


def test_dies_of_a_qt_fatal_message() -> None:
    """End the worker process through Qt's fatal message path."""
    qFatal(FATAL_MESSAGE)
