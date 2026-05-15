# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Shared fixtures for audit7 F-0021 wire_sandbox_backend tests."""

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
    """Provide a QApplication instance for the test session.

    Qt requires exactly one QApplication instance per process. This fixture
    creates one for the entire test session and yields any pre-existing
    instance if present.

    Yields:
        QApplication: A live QApplication for widget construction.
    """
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        yield existing
        return

    yield QApplication([])
