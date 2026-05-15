# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Shared fixtures for ``tests/ui`` Qt-backed regression tests."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QApplication


if TYPE_CHECKING:
    from collections.abc import Iterator


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="session")
def qapp() -> Iterator[QApplication]:
    """Provide a single ``QApplication`` instance for the test session.

    Qt requires exactly one ``QApplication`` per process. The fixture
    yields any pre-existing instance to avoid double construction when
    a higher-scope conftest already created one.

    Yields:
        QApplication: Live ``QApplication`` for widget construction.
    """
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])
