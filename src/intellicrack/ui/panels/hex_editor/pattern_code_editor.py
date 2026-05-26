# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Pattern DSL editor widget with an in-line identifier completer.

Provides :class:`PatternCodeEditor`, a ``QPlainTextEdit`` subclass that hosts
a ``QCompleter`` backed by :class:`HexPatCompleter`. The popup triggers on
``Ctrl+Space`` and after the user types two or more identifier characters,
matching Qt's recommended custom-completer pattern. Tab, Enter, Esc and
Backtab are forwarded to the popup while it is visible so the user can
accept or dismiss suggestions without leaving the keyboard.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, override

from PyQt6.QtCore import QStringListModel, Qt
from PyQt6.QtGui import QKeyEvent, QTextCursor
from PyQt6.QtWidgets import QCompleter, QPlainTextEdit

from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from collections.abc import Iterable

    from PyQt6.QtCore import QModelIndex
    from PyQt6.QtWidgets import QAbstractItemView, QWidget


_logger = get_logger(__name__)


_AUTO_POPUP_PREFIX_LEN: Final[int] = 2
_POPUP_MIN_WIDTH_FUDGE: Final[int] = 20


class PatternCodeEditor(QPlainTextEdit):
    """QPlainTextEdit subclass with a HexPat identifier completer popup.

    The completer popup activates on ``Ctrl+Space`` regardless of the
    cursor's current word, and automatically when the user has typed at
    least :data:`_AUTO_POPUP_PREFIX_LEN` identifier characters. Selection
    inserts the remainder of the chosen completion into the cursor word.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the editor and attach a default completer model.

        Args:
            parent: Optional parent widget.
        """
        super().__init__(parent)
        self._model: QStringListModel = QStringListModel(self)
        self._completer: QCompleter = QCompleter(self._model, self)
        self._completer.setWidget(self)
        self._completer.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
        self._completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._completer.setWrapAround(False)
        self._completer.activated.connect(self._insert_completion)

    def update_type_names(self, names: Iterable[str]) -> None:
        """Replace the completer's string list with ``names``.

        Args:
            names: Identifier strings offered by the completer popup.
                Duplicates are removed and the list is sorted for
                deterministic ordering.
        """
        self._model.setStringList(sorted(set(names)))

    def _text_under_cursor(self) -> str:
        """Return the identifier word at the current cursor position.

        Returns:
            str: The identifier characters immediately before the cursor.
        """
        cursor = self.textCursor()
        cursor.select(QTextCursor.SelectionType.WordUnderCursor)
        return cursor.selectedText()

    def _insert_completion(self, completion: object) -> None:
        """Insert the chosen completion into the current cursor word.

        Args:
            completion: Selected completion string from the popup. Passed
                through ``str`` to accept the ``QVariant`` payload emitted
                by ``QCompleter.activated``.
        """
        if self._completer.widget() is not self:
            return
        completion_text = str(completion)
        prefix_len = len(self._completer.completionPrefix())
        cursor = self.textCursor()
        extra = completion_text[prefix_len:]
        cursor.insertText(extra)
        self.setTextCursor(cursor)

    def _is_popup_visible(self) -> bool:
        """Return whether the completer popup is currently shown.

        Returns:
            bool: ``True`` when the popup widget is visible.
        """
        popup: QAbstractItemView | None = self._completer.popup()
        return popup is not None and popup.isVisible()

    @override
    def keyPressEvent(self, e: QKeyEvent | None) -> None:
        """Handle key events, routing completion-relevant keys to the popup.

        Args:
            e: The incoming key event from Qt. ``None`` is handled by
                delegating to the base class for safety.
        """
        if e is None:
            super().keyPressEvent(e)
            return

        if self._is_popup_visible() and e.key() in {
            int(Qt.Key.Key_Enter),
            int(Qt.Key.Key_Return),
            int(Qt.Key.Key_Escape),
            int(Qt.Key.Key_Tab),
            int(Qt.Key.Key_Backtab),
        }:
            e.ignore()
            return

        is_shortcut = (
            (e.modifiers() & Qt.KeyboardModifier.ControlModifier) == Qt.KeyboardModifier.ControlModifier
            and e.key() == int(Qt.Key.Key_Space)
        )
        if not is_shortcut:
            super().keyPressEvent(e)

        ctrl_or_shift = (
            (e.modifiers() & Qt.KeyboardModifier.ControlModifier) == Qt.KeyboardModifier.ControlModifier
            or (e.modifiers() & Qt.KeyboardModifier.ShiftModifier) == Qt.KeyboardModifier.ShiftModifier
        )
        if not is_shortcut and (ctrl_or_shift and not e.text()):
            return

        prefix = self._text_under_cursor()

        if not is_shortcut and (not e.text() or len(prefix) < _AUTO_POPUP_PREFIX_LEN):
            popup = self._completer.popup()
            if popup is not None:
                popup.hide()
            return

        if prefix != self._completer.completionPrefix():
            self._completer.setCompletionPrefix(prefix)
            popup = self._completer.popup()
            if popup is not None:
                model = self._completer.completionModel()
                index: QModelIndex | None = model.index(0, 0) if model is not None else None
                if index is not None:
                    popup.setCurrentIndex(index)

        popup = self._completer.popup()
        if popup is None:
            return
        rect = self.cursorRect()
        scrollbar = popup.verticalScrollBar()
        scrollbar_width = scrollbar.sizeHint().width() if scrollbar is not None else 0
        rect.setWidth(
            popup.sizeHintForColumn(0)
            + scrollbar_width
            + _POPUP_MIN_WIDTH_FUDGE,
        )
        self._completer.complete(rect)
