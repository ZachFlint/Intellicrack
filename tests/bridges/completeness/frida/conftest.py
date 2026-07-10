# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Pytest fixtures shared by the Frida bridge-completeness gate tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QApplication


if TYPE_CHECKING:
    from collections.abc import Generator


@pytest.fixture(scope="session")
def qapp() -> Generator[QApplication]:
    """Provide a QApplication instance for the test session.

    Qt requires exactly one QApplication instance per process; this
    fixture creates one for the entire session and yields it so every
    widget-construction test in this package can run without re-creating
    (or conflicting on) the singleton application instance.

    Yields:
        Generator[QApplication]: The application instance.
    """
    existing = QApplication.instance()
    if existing is not None and isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])
