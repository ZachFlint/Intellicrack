# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit5 U9 ToolConfirmationDialog fix (F-0020).

F-0020: ``ToolConfirmationDialog.remember_similar`` was captured but never
read by callers. The dialog had no observable side effect for the
"Remember for similar operations this session" checkbox, leaving the
state effectively dead.

The remediation:

1. Adds a Qt ``decision_made(approved: bool, remember_similar: bool)``
   signal so the captured preference is exposed as part of the decision
   event rather than only via post-``exec()`` property polling.

2. Maintains a class-level remembered-decisions cache keyed by
   ``(tool_name, function_name)`` and overrides ``exec()`` to short-circuit
   when a cached decision exists. This makes the captured preference
   functionally observable inside the dialog's own scope.

Each test below would fail against the unfixed code: the signal did not
exist and ``exec()`` was inherited unchanged so cached decisions had no
effect.
"""

from __future__ import annotations

import os


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QApplication, QDialog

from intellicrack.core.types import ToolCall
from intellicrack.ui.confirmation_dialog import ToolConfirmationDialog


if TYPE_CHECKING:
    from collections.abc import Iterator

    from PyQt6.QtCore import QCoreApplication


@pytest.fixture(scope="module")
def qapp() -> QCoreApplication:
    """Ensure exactly one QApplication exists for these widget tests.

    Returns:
        QCoreApplication: The running application instance.
    """
    existing = QApplication.instance()
    if existing is not None:
        return existing
    return QApplication([])


@pytest.fixture(autouse=True)
def reset_remembered_decisions() -> Iterator[None]:
    """Clear class-level remembered decisions before and after each test.

    Yields:
        None: Pytest setup-yield-teardown idiom.
    """
    ToolConfirmationDialog.clear_remembered_decisions()
    try:
        yield
    finally:
        ToolConfirmationDialog.clear_remembered_decisions()


class _DecisionRecorder:
    """Recording slot that captures ``decision_made`` signal payloads.

    Replaces ``unittest.mock.Mock`` to comply with the audit test policy of
    avoiding mock objects in regression tests.
    """

    events: list[tuple[bool, bool]]

    def __init__(self) -> None:
        """Initialize with an empty event list."""
        self.events = []

    def record(self, *args: bool) -> None:
        """Record a decision event from the Qt signal.

        Args:
            *args: Positional ``(approved, remember)`` booleans delivered by Qt.
        """
        approved, remember = args
        self.events.append((approved, remember))


def _make_call(
    *,
    tool_name: str = "fs",
    function_name: str = "delete_file",
    call_id: str = "tc-1",
) -> ToolCall:
    """Build a ToolCall instance for tests.

    Args:
        tool_name: Tool namespace name.
        function_name: Function name within the tool.
        call_id: Unique identifier for this synthetic call.

    Returns:
        ToolCall: A populated ToolCall dataclass.
    """
    return ToolCall(
        id=call_id,
        tool_name=tool_name,
        function_name=function_name,
        arguments={"path": "C:/temp/example.bin"},
    )


def test_decision_made_signal_emitted_on_approve(
    qapp: QCoreApplication,
) -> None:
    """Approve emits decision_made(True, remember_similar=False) by default.

    Args:
        qapp: The shared QApplication fixture.
    """
    del qapp
    recorder = _DecisionRecorder()
    dialog = ToolConfirmationDialog(_make_call())
    dialog.decision_made.connect(recorder.record)
    try:
        dialog.make_decision(approved=True)
    finally:
        dialog.deleteLater()
    assert recorder.events == [(True, False)]
    assert dialog.approved is True
    assert dialog.remember_similar is False


def test_decision_made_signal_emitted_on_deny(
    qapp: QCoreApplication,
) -> None:
    """Deny emits decision_made(False, remember_similar=False) by default.

    Args:
        qapp: The shared QApplication fixture.
    """
    del qapp
    recorder = _DecisionRecorder()
    dialog = ToolConfirmationDialog(_make_call())
    dialog.decision_made.connect(recorder.record)
    try:
        dialog.make_decision(approved=False)
    finally:
        dialog.deleteLater()
    assert recorder.events == [(False, False)]
    assert dialog.approved is False
    assert dialog.remember_similar is False


def test_remember_checkbox_propagates_to_signal_and_cache(
    qapp: QCoreApplication,
) -> None:
    """Checking the remember box stores the decision in the class cache.

    Args:
        qapp: The shared QApplication fixture.
    """
    del qapp
    recorder = _DecisionRecorder()
    call = _make_call(tool_name="patch", function_name="apply")
    dialog = ToolConfirmationDialog(call)
    dialog.decision_made.connect(recorder.record)
    try:
        dialog.set_remember_similar(value=True)
        dialog.make_decision(approved=True)
    finally:
        dialog.deleteLater()
    assert recorder.events == [(True, True)]
    assert dialog.remember_similar is True
    assert ToolConfirmationDialog.remembered_decision(call) is True


def test_remember_deny_caches_negative_decision(qapp: QCoreApplication) -> None:
    """Denying with remember caches False for the (tool, function) pair.

    Args:
        qapp: The shared QApplication fixture.
    """
    del qapp
    call = _make_call(tool_name="exec", function_name="run_shell")
    dialog = ToolConfirmationDialog(call)
    try:
        dialog.set_remember_similar(value=True)
        dialog.make_decision(approved=False)
    finally:
        dialog.deleteLater()
    assert ToolConfirmationDialog.remembered_decision(call) is False


def test_unchecked_remember_does_not_populate_cache(
    qapp: QCoreApplication,
) -> None:
    """Approving without remember leaves the class cache untouched.

    Args:
        qapp: The shared QApplication fixture.
    """
    del qapp
    call = _make_call(tool_name="hex", function_name="search_strings")
    dialog = ToolConfirmationDialog(call)
    try:
        dialog.make_decision(approved=True)
    finally:
        dialog.deleteLater()
    assert ToolConfirmationDialog.remembered_decision(call) is None


def test_exec_short_circuits_when_decision_remembered_approve(
    qapp: QCoreApplication,
) -> None:
    """A second dialog auto-accepts when prior approval was remembered.

    Args:
        qapp: The shared QApplication fixture.
    """
    del qapp
    call = _make_call(tool_name="patch", function_name="apply")
    first = ToolConfirmationDialog(call)
    try:
        first.set_remember_similar(value=True)
        first.make_decision(approved=True)
    finally:
        first.deleteLater()

    recorder = _DecisionRecorder()
    second = ToolConfirmationDialog(call)
    second.decision_made.connect(recorder.record)
    try:
        result = second.exec()
    finally:
        second.deleteLater()

    assert result == QDialog.DialogCode.Accepted.value
    assert second.approved is True
    assert second.remember_similar is True
    assert recorder.events == [(True, True)]


def test_exec_short_circuits_when_decision_remembered_deny(
    qapp: QCoreApplication,
) -> None:
    """A second dialog auto-rejects when prior denial was remembered.

    Args:
        qapp: The shared QApplication fixture.
    """
    del qapp
    call = _make_call(tool_name="exec", function_name="run_shell")
    first = ToolConfirmationDialog(call)
    try:
        first.set_remember_similar(value=True)
        first.make_decision(approved=False)
    finally:
        first.deleteLater()

    recorder = _DecisionRecorder()
    second = ToolConfirmationDialog(call)
    second.decision_made.connect(recorder.record)
    try:
        result = second.exec()
    finally:
        second.deleteLater()

    assert result == QDialog.DialogCode.Rejected.value
    assert second.approved is False
    assert recorder.events == [(False, True)]


def test_exec_does_not_short_circuit_for_different_function(
    qapp: QCoreApplication,
) -> None:
    """Cached approval for one function does not leak to a different function.

    Args:
        qapp: The shared QApplication fixture.
    """
    del qapp
    cached_call = _make_call(tool_name="fs", function_name="delete_file")
    cached = ToolConfirmationDialog(cached_call)
    try:
        cached.set_remember_similar(value=True)
        cached.make_decision(approved=True)
    finally:
        cached.deleteLater()

    other_call = _make_call(tool_name="fs", function_name="rename_file")
    assert ToolConfirmationDialog.remembered_decision(other_call) is None


def test_clear_remembered_decisions_removes_cached_state(
    qapp: QCoreApplication,
) -> None:
    """clear_remembered_decisions() empties the class cache.

    Args:
        qapp: The shared QApplication fixture.
    """
    del qapp
    call = _make_call(tool_name="patch", function_name="apply")
    dialog = ToolConfirmationDialog(call)
    try:
        dialog.set_remember_similar(value=True)
        dialog.make_decision(approved=True)
    finally:
        dialog.deleteLater()
    assert ToolConfirmationDialog.remembered_decision(call) is True

    ToolConfirmationDialog.clear_remembered_decisions()
    assert ToolConfirmationDialog.remembered_decision(call) is None
