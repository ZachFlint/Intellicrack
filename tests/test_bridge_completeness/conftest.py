# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tree-wide fixtures for the bridge-completeness gate suite.

Every tool panel exercised by these L3 gates surfaces user feedback and input
requests through Qt's blocking modal dialogs -- directly via ``QMessageBox``
and ``QInputDialog``/``QFileDialog``, and indirectly via the
``intellicrack.ui.dialogs_helpers`` wrappers (``show_info``/``show_warning``/
``show_error``), each of which delegates to a ``QMessageBox`` static method.
Under the headless ``offscreen`` Qt platform used inside the Docker test
sandbox a modal dialog can never be dismissed, so any handler that reaches one
blocks its test forever and -- because the whole module runs in a single
process -- stalls the entire gate suite.

This package-root ``conftest`` installs an autouse guard that replaces every
blocking modal entry point with a non-blocking stand-in: ``QMessageBox``
prompts return ``Yes`` (so confirmation-gated handlers proceed), and the input
and file pickers return a cancelled/empty selection (so handlers take their
"user cancelled" branch). The production handler logic under test still runs
in full; only the operating system's modal render is bypassed. Individual
tests that assert on a specific dialog invocation, or that need a concrete
picker result, override the relevant entry point with their own
``monkeypatch.setattr`` inside the test body, which takes precedence over this
fixture.
"""

from __future__ import annotations

import os

import pytest
from PyQt6.QtWidgets import QFileDialog, QInputDialog, QMessageBox


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def _accept_messagebox(*_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
    """Return ``Yes`` without displaying a ``QMessageBox`` modal.

    Args:
        *_args: Positional arguments passed by the caller (ignored).
        **_kwargs: Keyword arguments passed by the caller (ignored).

    Returns:
        QMessageBox.StandardButton: The ``Yes`` button constant, so a handler
        guarding on an affirmative confirmation proceeds as it would if the
        user had accepted the dialog.
    """
    return QMessageBox.StandardButton.Yes


def _cancel_text_dialog(*_args: object, **_kwargs: object) -> tuple[str, bool]:
    """Return a cancelled empty-text result for a ``QInputDialog`` text prompt.

    Args:
        *_args: Positional arguments passed by the caller (ignored).
        **_kwargs: Keyword arguments passed by the caller (ignored).

    Returns:
        tuple[str, bool]: An empty string paired with ``False`` to signal the
        user dismissed the prompt without entering a value.
    """
    return ("", False)


def _cancel_int_dialog(*_args: object, **_kwargs: object) -> tuple[int, bool]:
    """Return a cancelled result for a ``QInputDialog.getInt`` prompt.

    Args:
        *_args: Positional arguments passed by the caller (ignored).
        **_kwargs: Keyword arguments passed by the caller (ignored).

    Returns:
        tuple[int, bool]: Zero paired with ``False`` to signal cancellation.
    """
    return (0, False)


def _cancel_double_dialog(*_args: object, **_kwargs: object) -> tuple[float, bool]:
    """Return a cancelled result for a ``QInputDialog.getDouble`` prompt.

    Args:
        *_args: Positional arguments passed by the caller (ignored).
        **_kwargs: Keyword arguments passed by the caller (ignored).

    Returns:
        tuple[float, bool]: Zero paired with ``False`` to signal cancellation.
    """
    return (0.0, False)


def _no_single_file(*_args: object, **_kwargs: object) -> tuple[str, str]:
    """Return an empty single-file selection for a ``QFileDialog`` picker.

    Args:
        *_args: Positional arguments passed by the caller (ignored).
        **_kwargs: Keyword arguments passed by the caller (ignored).

    Returns:
        tuple[str, str]: An empty path and empty selected-filter pair,
        matching the shape returned by ``getOpenFileName``/``getSaveFileName``
        when the user cancels.
    """
    return ("", "")


def _no_multiple_files(*_args: object, **_kwargs: object) -> tuple[list[str], str]:
    """Return an empty multi-file selection for ``QFileDialog.getOpenFileNames``.

    Args:
        *_args: Positional arguments passed by the caller (ignored).
        **_kwargs: Keyword arguments passed by the caller (ignored).

    Returns:
        tuple[list[str], str]: An empty path list and empty selected-filter,
        matching the shape returned when the user cancels.
    """
    return ([], "")


def _no_directory(*_args: object, **_kwargs: object) -> str:
    """Return an empty directory selection for ``QFileDialog.getExistingDirectory``.

    Args:
        *_args: Positional arguments passed by the caller (ignored).
        **_kwargs: Keyword arguments passed by the caller (ignored).

    Returns:
        str: An empty string, signalling the user cancelled the picker.
    """
    return ""


@pytest.fixture(autouse=True)
def guard_modal_dialogs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace every blocking Qt modal entry point with a non-blocking default.

    Args:
        monkeypatch: pytest monkeypatch fixture used to install the guards.
    """
    for name in ("warning", "information", "question", "critical"):
        monkeypatch.setattr(QMessageBox, name, _accept_messagebox)
    monkeypatch.setattr(QInputDialog, "getText", _cancel_text_dialog)
    monkeypatch.setattr(QInputDialog, "getMultiLineText", _cancel_text_dialog)
    monkeypatch.setattr(QInputDialog, "getItem", _cancel_text_dialog)
    monkeypatch.setattr(QInputDialog, "getInt", _cancel_int_dialog)
    monkeypatch.setattr(QInputDialog, "getDouble", _cancel_double_dialog)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _no_single_file)
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _no_single_file)
    monkeypatch.setattr(QFileDialog, "getOpenFileNames", _no_multiple_files)
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", _no_directory)
