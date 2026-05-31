# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-data coverage for ``hex_editor.pattern_code_editor.PatternCodeEditor``.

The audit (shard 13) flagged ``pattern_code_editor.py`` as entirely untested:
the HexPat identifier completer popup, completion matching, and insertion were
unexercised. These tests feed the editor the REAL HexPat built-in type names
sourced from :class:`intellicrack.core.hexpat.completer.HexPatCompleter` and
assert the completer offers the correct real completions for a type prefix and
that accepting a completion inserts exactly the missing suffix into the buffer.
The pattern DSL completion is pure widget logic with no external dependency, so
real type-name data drives the behaviour under test directly.
"""

from __future__ import annotations

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QTextCursor
from PyQt6.QtWidgets import QApplication

from intellicrack.core.hexpat.completer import HexPatCompleter
from intellicrack.ui.panels.hex_editor.pattern_code_editor import PatternCodeEditor


pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Provide a shared QApplication for the pattern editor tests.

    Returns:
        QApplication: The Qt application instance.
    """
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        return existing
    return QApplication([])


class _ProbeEditor(PatternCodeEditor):
    """PatternCodeEditor subclass exposing typed accessors for assertions.

    Subclassing keeps access to the editor's completer internals inside the
    class hierarchy, so tests can inspect completion results without reaching
    into private members from outside the module.
    """

    def completions_for(self, prefix: str) -> list[str]:
        """Return the completer's completions for ``prefix``.

        Args:
            prefix: Identifier prefix to match against the type names.

        Returns:
            list[str]: The completion strings the popup would offer.
        """
        self._completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._completer.setCompletionPrefix(prefix)
        model = self._completer.completionModel()
        if model is None:
            return []
        count = self._completer.completionCount()
        results: list[str] = []
        for row in range(count):
            index = model.index(row, 0)
            value = index.data()
            if value is not None:
                results.append(str(value))
        return results

    def accept_completion(self, typed: str, chosen: str) -> str:
        """Type ``typed``, accept ``chosen``, and return the resulting buffer.

        Args:
            typed: The prefix the user typed into the editor.
            chosen: The completion the user selected from the popup.

        Returns:
            str: The full editor text after the completion is inserted.
        """
        self.setPlainText(typed)
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.setTextCursor(cursor)
        self._completer.setCompletionPrefix(typed)
        self._insert_completion(chosen)
        return self.toPlainText()


class TestRealHexPatCompletions:
    """The completer must offer the real HexPat type names."""

    def test_offers_real_unsigned_types(self, qapp: QApplication) -> None:
        """Verify a ``u`` prefix offers the real unsigned HexPat types.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        type_names = HexPatCompleter().all_type_names()
        editor = _ProbeEditor()
        editor.update_type_names(type_names)

        expected = sorted(n for n in type_names if n.startswith("u"))
        assert expected, "real HexPat type set has no unsigned types"
        completions = sorted(editor.completions_for("u"))
        assert completions == expected

    def test_signed_prefix_excludes_unsigned(self, qapp: QApplication) -> None:
        """Verify an ``s`` prefix offers signed types and not unsigned ones.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        type_names = HexPatCompleter().all_type_names()
        editor = _ProbeEditor()
        editor.update_type_names(type_names)

        completions = editor.completions_for("s")
        assert "s32" in completions
        assert all(not c.startswith("u") for c in completions)

    def test_type_names_are_deduplicated_and_sorted(self, qapp: QApplication) -> None:
        """Verify duplicate input names collapse to a single sorted entry.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        editor = _ProbeEditor()
        editor.update_type_names(["u32", "u32", "u16", "u8", "u16"])
        completions = editor.completions_for("u")
        assert completions == ["u16", "u32", "u8"]


class TestCompletionInsertion:
    """Accepting a completion must insert only the missing suffix."""

    def test_accept_inserts_remaining_suffix(self, qapp: QApplication) -> None:
        """Verify typing ``u3`` and accepting ``u32`` yields ``u32`` once.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        editor = _ProbeEditor()
        editor.update_type_names(HexPatCompleter().all_type_names())
        assert editor.accept_completion("u3", "u32") == "u32"

    def test_accept_full_word_does_not_duplicate(self, qapp: QApplication) -> None:
        """Verify accepting a completion equal to the typed text is idempotent.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        editor = _ProbeEditor()
        editor.update_type_names(HexPatCompleter().all_type_names())
        assert editor.accept_completion("char", "char") == "char"
