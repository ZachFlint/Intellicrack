# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Shared fixtures for audit4 b6 SystemTab tests.

Prevents blocking ``QMessageBox`` dialogs from being shown by tests that exercise
the user-visible warning paths introduced for F-0022 and F-0023.
"""

from __future__ import annotations

import pytest
from PyQt6.QtWidgets import QMessageBox


@pytest.fixture(autouse=True)
def silence_qmessagebox(monkeypatch: pytest.MonkeyPatch) -> list[tuple[object, ...]]:
    """Replace ``QMessageBox.warning`` with a non-blocking capturer for every test.

    Args:
        monkeypatch: pytest monkeypatch fixture.

    Returns:
        list[tuple[object, ...]]: A list that receives each warning invocation's positional args.
    """
    calls: list[tuple[object, ...]] = []

    def _fake_warning(*args: object, **_kwargs: object) -> QMessageBox.StandardButton:
        """Record a warning invocation and return the default button.

        Args:
            *args: Positional arguments passed to ``QMessageBox.warning``.
            **_kwargs: Ignored keyword arguments.

        Returns:
            QMessageBox.StandardButton: ``Ok`` so callers that inspect the return value continue normally.
        """
        calls.append(args)
        return QMessageBox.StandardButton.Ok

    monkeypatch.setattr(QMessageBox, "warning", staticmethod(_fake_warning))
    return calls
