# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for S16-D13: the Analysis panel Notes tab is real, editable, persisted notes.

Pre-fix, the Notes tab was a single ``QTextEdit`` with ``setReadOnly(True)``
that only ever displayed ``BridgeAnalysisSummary.analysis_notes`` (bridge-
generated diagnostics); the user could not type into it at all, and even a
writable box would have had nothing wired to keep its text across a panel
refresh. These tests drive the real
:class:`~intellicrack.ui.panels.analysis_panel.BridgeAnalysisPanel` under an
offscreen ``QApplication``, type real keystrokes into the notes editor with
:class:`~PyQt6.QtTest.QTest`, and prove the typed text survives a panel
refresh/reload -- both against the same analysis object and against a freshly
constructed one for the same binary, simulating a genuine re-analysis round
trip. No mocks or stubs stand in for the panel or the analysis model.
"""

from __future__ import annotations

from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QTextEdit

from intellicrack.core.types import (
    BridgeAnalysisSummary,
    ExportInfo,
    FunctionInfo,
    ImportInfo,
    SectionInfo,
    StringInfo,
)
from intellicrack.ui.panels.analysis_panel import BridgeAnalysisPanel


def _make_analysis(
    binary_name: str = "license_check.exe",
    diagnostic: str = "Detected anti-debug check at 0x404050",
) -> BridgeAnalysisSummary:
    """Build a real, structurally complete analysis summary for panel population.

    Args:
        binary_name: Name of the binary the summary represents.
        diagnostic: Single bridge-generated diagnostic note to attach.

    Returns:
        BridgeAnalysisSummary: A summary with one entry per data category and
        the given diagnostic note.
    """
    return BridgeAnalysisSummary(
        binary_name=binary_name,
        strings=[StringInfo(address=0x401000, value="license key invalid", encoding="ascii", section=".rdata")],
        imports=[ImportInfo(dll="KERNEL32.DLL", function="CreateFileW", ordinal=None, address=0x402000)],
        exports=[ExportInfo(name="ValidateLicense", ordinal=1, address=0x403000)],
        sections=[
            SectionInfo(
                name=".text",
                virtual_address=0x1000,
                virtual_size=0x2000,
                raw_size=0x1800,
                characteristics=0x60000020,
                entropy=6.5,
            ),
        ],
        functions=[
            FunctionInfo(
                name="ValidateLicense",
                address=0x404000,
                size=256,
                calling_convention="stdcall",
                return_type="int",
                parameters=[],
                local_variables=[],
            ),
        ],
        format_info="Portable Executable (PE32+) for x86-64",
        architecture="x86_64",
        source_bridges=["ghidra"],
        analysis_notes=[diagnostic],
        complete=True,
    )


def _type_into(widget_edit: QTextEdit, text: str) -> None:
    """Simulate a user typing real keystrokes into a text-edit widget.

    Args:
        widget_edit: The ``QTextEdit`` to type into.
        text: The text to type, one keystroke per character.
    """
    QTest.keyClicks(widget_edit, text)


def test_notes_editor_is_not_read_only(qapp: QApplication) -> None:
    """The user-notes editor must accept typed input, unlike the diagnostics box.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    panel = BridgeAnalysisPanel()
    try:
        assert panel._user_notes_edit.isReadOnly() is False, "notes editor must be editable, not read-only"
    finally:
        panel.deleteLater()
        QApplication.processEvents()


def test_generated_diagnostics_stay_visible_and_read_only(qapp: QApplication) -> None:
    """Bridge-generated diagnostics must remain visible and non-editable alongside user notes.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    panel = BridgeAnalysisPanel()
    try:
        analysis = _make_analysis()
        panel.set_analysis(analysis)
        assert panel._notes_edit.isReadOnly() is True
        assert panel._notes_edit.toPlainText() == "Detected anti-debug check at 0x404050"
    finally:
        panel.deleteLater()
        QApplication.processEvents()


def test_typed_notes_survive_refresh_on_same_analysis_object(qapp: QApplication) -> None:
    """Notes typed by the user must survive :meth:`set_analysis` being called again.

    Pre-fix, the notes widget was fully re-populated from
    ``analysis.analysis_notes`` on every call and had no independent editable
    state at all, so there was nothing to lose -- and no way to type
    anything in the first place. This asserts the user's text is still there
    after the panel is refreshed against the very same analysis object,
    which is exactly what a live re-render of the current binary does.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    panel = BridgeAnalysisPanel()
    try:
        analysis = _make_analysis()
        panel.set_analysis(analysis)

        panel._user_notes_edit.setFocus()
        typed = "Bypass found in ValidateLicense; check RSA signature path next."
        _type_into(panel._user_notes_edit, typed)
        assert panel._user_notes_edit.toPlainText() == typed

        panel.set_analysis(analysis)

        assert panel._user_notes_edit.toPlainText() == typed, "user notes were discarded by a same-object refresh"
        assert panel._user_notes_edit.isReadOnly() is False
    finally:
        panel.deleteLater()
        QApplication.processEvents()


def test_typed_notes_survive_reload_with_a_new_analysis_object(qapp: QApplication) -> None:
    """Notes must survive a reload that produces a brand-new analysis object for the same binary.

    This simulates a real re-analysis: the bridges run again and hand back a
    freshly constructed ``BridgeAnalysisSummary`` for the same binary name,
    with different diagnostics. The user's notes must still be there, and
    the diagnostics box must show the new diagnostics, proving the two are
    tracked independently rather than one clobbering the other.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    panel = BridgeAnalysisPanel()
    try:
        first = _make_analysis(diagnostic="First pass: anti-debug check at 0x404050")
        panel.set_analysis(first)

        typed = "Need to re-check the trial-expiry comparison at 0x404120."
        panel._user_notes_edit.setFocus()
        _type_into(panel._user_notes_edit, typed)
        assert panel._user_notes_edit.toPlainText() == typed

        second = _make_analysis(diagnostic="Second pass: found RSA signature check at 0x404200")
        panel.set_analysis(second)

        assert panel._user_notes_edit.toPlainText() == typed, "user notes were lost on reload with a new analysis object"
        assert panel._notes_edit.toPlainText() == "Second pass: found RSA signature check at 0x404200", (
            "diagnostics must reflect the freshly reloaded analysis, not the stale one"
        )
    finally:
        panel.deleteLater()
        QApplication.processEvents()


def test_notes_are_scoped_per_binary(qapp: QApplication) -> None:
    """Notes for one binary must not bleed into another binary's notes.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    panel = BridgeAnalysisPanel()
    try:
        binary_a = _make_analysis(binary_name="a.exe", diagnostic="a diagnostic")
        binary_b = _make_analysis(binary_name="b.exe", diagnostic="b diagnostic")

        panel.set_analysis(binary_a)
        panel._user_notes_edit.setFocus()
        _type_into(panel._user_notes_edit, "notes about a.exe")

        panel.set_analysis(binary_b)
        assert not panel._user_notes_edit.toPlainText(), "switching binaries must not show the previous binary's notes"
        panel._user_notes_edit.setFocus()
        _type_into(panel._user_notes_edit, "notes about b.exe")

        panel.set_analysis(binary_a)
        assert panel._user_notes_edit.toPlainText() == "notes about a.exe", "a.exe notes were lost or overwritten by b.exe notes"

        panel.set_analysis(binary_b)
        assert panel._user_notes_edit.toPlainText() == "notes about b.exe", "b.exe notes were lost or overwritten by a.exe notes"
    finally:
        panel.deleteLater()
        QApplication.processEvents()


def test_typed_notes_survive_mark_loaded_before_analysis_completes(qapp: QApplication) -> None:
    """Notes typed while a binary is loaded but not yet analyzed must survive analysis completing.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    panel = BridgeAnalysisPanel()
    try:
        panel.mark_loaded("target.exe")
        assert panel._user_notes_edit.isReadOnly() is False

        panel._user_notes_edit.setFocus()
        _type_into(panel._user_notes_edit, "remember to check the packer first")

        analysis = _make_analysis(binary_name="target.exe")
        panel.set_analysis(analysis)

        assert panel._user_notes_edit.toPlainText() == "remember to check the packer first", (
            "notes typed before analysis completed were discarded once set_analysis populated the panel"
        )
    finally:
        panel.deleteLater()
        QApplication.processEvents()
