# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Shared QMessageBox dialog helpers for Intellicrack UI panels.

Provides a single canonical implementation of the error / warning / information popup pattern used across the configuration dialogs and hex
editor panel mixins. Centralising these calls gives every UI surface consistent structured logging and a single seam for future theming or
accessibility tweaks.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtWidgets import QMessageBox

from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QWidget


_logger = get_logger(__name__)


def show_error(
    parent: QWidget | None,
    title: str,
    message: str,
    *,
    exc: BaseException | None = None,
) -> QMessageBox.StandardButton:
    """Display a critical error message and emit a structured log entry.

    Args:
        parent: Widget that owns the dialog. ``None`` produces an
            application-modal dialog with no parent.
        title: Window title shown at the top of the message box.
        message: Error message body. Multi-line text is preserved.
        exc: Optional exception that triggered the error. When provided
            the traceback is captured in the log entry via
            ``exc_info=True``.

    Returns:
        QMessageBox.StandardButton: The standard button selected by the
            user when they dismiss the dialog. Mirrors the return value
            of :meth:`QMessageBox.critical`.
    """
    if exc is not None:
        _logger.error(
            "dialog_error",
            title=title,
            dialog_message=message,
            error_type=type(exc).__name__,
            error=str(exc),
            exc_info=exc,
        )
    else:
        _logger.warning("dialog_error", title=title, dialog_message=message)
    return QMessageBox.critical(parent, title, message)


def show_warning(
    parent: QWidget | None,
    title: str,
    message: str,
    *,
    exc: BaseException | None = None,
) -> QMessageBox.StandardButton:
    """Display a warning message and emit a structured log entry.

    Args:
        parent: Widget that owns the dialog. ``None`` produces an
            application-modal dialog with no parent.
        title: Window title shown at the top of the message box.
        message: Warning message body. Multi-line text is preserved.
        exc: Optional exception that triggered the warning. When
            provided the traceback is captured in the log entry via
            ``exc_info=True``.

    Returns:
        QMessageBox.StandardButton: The standard button selected by the
            user when they dismiss the dialog. Mirrors the return value
            of :meth:`QMessageBox.warning`.
    """
    if exc is not None:
        _logger.warning(
            "dialog_warning",
            title=title,
            dialog_message=message,
            error_type=type(exc).__name__,
            error=str(exc),
            exc_info=exc,
        )
    else:
        _logger.warning("dialog_warning", title=title, dialog_message=message)
    return QMessageBox.warning(parent, title, message)


def show_info(
    parent: QWidget | None,
    title: str,
    message: str,
) -> QMessageBox.StandardButton:
    """Display an informational message and emit a structured log entry.

    Args:
        parent: Widget that owns the dialog. ``None`` produces an
            application-modal dialog with no parent.
        title: Window title shown at the top of the message box.
        message: Informational message body. Multi-line text is preserved.

    Returns:
        QMessageBox.StandardButton: The standard button selected by the
            user when they dismiss the dialog. Mirrors the return value
            of :meth:`QMessageBox.information`.
    """
    _logger.info("dialog_info", title=title, dialog_message=message)
    return QMessageBox.information(parent, title, message)
