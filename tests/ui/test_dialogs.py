# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for the shared QMessageBox dialog helpers.

Exercises ``intellicrack.ui.dialogs_helpers`` against real ``QApplication`` and
``QMessageBox`` instances. Each test patches the underlying
``QMessageBox.warning`` / ``critical`` / ``information`` static methods
with a recording shim so assertions can be made on the parent, title,
message arguments and the return value plumbing without a real modal
dialog appearing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtWidgets import QMessageBox, QWidget

from intellicrack.ui.dialogs_helpers import show_error, show_info, show_warning


if TYPE_CHECKING:
    import pytest
    from PyQt6.QtWidgets import QApplication


class _Recorder:
    """Static-method shim recording QMessageBox calls and returning a value.

    Args:
        return_value: Standard button enum returned by every recorded
            invocation. Defaults to ``QMessageBox.StandardButton.Ok``.
    """

    def __init__(
        self,
        return_value: QMessageBox.StandardButton = QMessageBox.StandardButton.Ok,
    ) -> None:
        self.calls: list[tuple[QWidget | None, str, str]] = []
        self._return_value: QMessageBox.StandardButton = return_value

    def __call__(
        self,
        parent: QWidget | None,
        title: str,
        message: str,
    ) -> QMessageBox.StandardButton:
        """Record a call and return the configured standard button.

        Args:
            parent: Dialog parent forwarded by the helper.
            title: Window title forwarded by the helper.
            message: Body text forwarded by the helper.

        Returns:
            QMessageBox.StandardButton: The configured return value.
        """
        self.calls.append((parent, title, message))
        return self._return_value


class TestShowError:
    """Cover ``show_error`` argument forwarding and exception handling."""

    @staticmethod
    def test_forwards_parent_title_message_to_qmessagebox(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``show_error`` calls ``QMessageBox.critical`` with the same args.

        Args:
            qapp: QApplication fixture from conftest.
            monkeypatch: Pytest monkeypatch fixture for replacing static methods.
        """
        del qapp
        recorder = _Recorder()
        monkeypatch.setattr(QMessageBox, "critical", staticmethod(recorder))
        parent = QWidget()
        try:
            result = show_error(parent, "Boom", "It exploded")
        finally:
            parent.deleteLater()
        assert recorder.calls == [(parent, "Boom", "It exploded")]
        assert result == QMessageBox.StandardButton.Ok

    @staticmethod
    def test_accepts_none_parent(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``show_error`` accepts a ``None`` parent and forwards it intact.

        Args:
            qapp: QApplication fixture from conftest.
            monkeypatch: Pytest monkeypatch fixture for replacing static methods.
        """
        del qapp
        recorder = _Recorder()
        monkeypatch.setattr(QMessageBox, "critical", staticmethod(recorder))
        show_error(None, "T", "M")
        assert recorder.calls[0][0] is None

    @staticmethod
    def test_logs_exception_when_exc_provided(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When ``exc`` is provided the dialog is still shown.

        Args:
            qapp: QApplication fixture from conftest.
            monkeypatch: Pytest monkeypatch fixture for replacing static methods.
        """
        del qapp
        recorder = _Recorder()
        monkeypatch.setattr(QMessageBox, "critical", staticmethod(recorder))
        exc = ValueError("bad input")
        show_error(None, "Bad", "Something failed", exc=exc)
        assert recorder.calls == [(None, "Bad", "Something failed")]

    @staticmethod
    def test_returns_qmessagebox_button(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The helper returns whatever the underlying QMessageBox returned.

        Args:
            qapp: QApplication fixture from conftest.
            monkeypatch: Pytest monkeypatch fixture for replacing static methods.
        """
        del qapp
        recorder = _Recorder(return_value=QMessageBox.StandardButton.Cancel)
        monkeypatch.setattr(QMessageBox, "critical", staticmethod(recorder))
        result = show_error(None, "T", "M")
        assert result == QMessageBox.StandardButton.Cancel


class TestShowWarning:
    """Cover ``show_warning`` argument forwarding and exception handling."""

    @staticmethod
    def test_forwards_parent_title_message_to_qmessagebox(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``show_warning`` calls ``QMessageBox.warning`` with the same args.

        Args:
            qapp: QApplication fixture from conftest.
            monkeypatch: Pytest monkeypatch fixture for replacing static methods.
        """
        del qapp
        recorder = _Recorder()
        monkeypatch.setattr(QMessageBox, "warning", staticmethod(recorder))
        parent = QWidget()
        try:
            result = show_warning(parent, "Heads up", "Watch out")
        finally:
            parent.deleteLater()
        assert recorder.calls == [(parent, "Heads up", "Watch out")]
        assert result == QMessageBox.StandardButton.Ok

    @staticmethod
    def test_logs_exception_when_exc_provided(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``exc`` is consumed without affecting the dialog forwarding.

        Args:
            qapp: QApplication fixture from conftest.
            monkeypatch: Pytest monkeypatch fixture for replacing static methods.
        """
        del qapp
        recorder = _Recorder()
        monkeypatch.setattr(QMessageBox, "warning", staticmethod(recorder))
        exc = OSError("disk gone")
        show_warning(None, "Disk", "Save failed", exc=exc)
        assert recorder.calls == [(None, "Disk", "Save failed")]

    @staticmethod
    def test_handles_multiline_message(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Newlines in the message body are preserved verbatim.

        Args:
            qapp: QApplication fixture from conftest.
            monkeypatch: Pytest monkeypatch fixture for replacing static methods.
        """
        del qapp
        recorder = _Recorder()
        monkeypatch.setattr(QMessageBox, "warning", staticmethod(recorder))
        body = "line one\nline two\nline three"
        show_warning(None, "T", body)
        assert recorder.calls[0][2] == body


class TestShowInfo:
    """Cover ``show_info`` argument forwarding."""

    @staticmethod
    def test_forwards_parent_title_message_to_qmessagebox(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``show_info`` calls ``QMessageBox.information`` with the same args.

        Args:
            qapp: QApplication fixture from conftest.
            monkeypatch: Pytest monkeypatch fixture for replacing static methods.
        """
        del qapp
        recorder = _Recorder()
        monkeypatch.setattr(QMessageBox, "information", staticmethod(recorder))
        parent = QWidget()
        try:
            result = show_info(parent, "Done", "All good")
        finally:
            parent.deleteLater()
        assert recorder.calls == [(parent, "Done", "All good")]
        assert result == QMessageBox.StandardButton.Ok

    @staticmethod
    def test_accepts_none_parent(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``show_info`` accepts a ``None`` parent.

        Args:
            qapp: QApplication fixture from conftest.
            monkeypatch: Pytest monkeypatch fixture for replacing static methods.
        """
        del qapp
        recorder = _Recorder()
        monkeypatch.setattr(QMessageBox, "information", staticmethod(recorder))
        show_info(None, "T", "M")
        assert recorder.calls[0][0] is None

    @staticmethod
    def test_returns_qmessagebox_button(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The helper returns whatever the underlying QMessageBox returned.

        Args:
            qapp: QApplication fixture from conftest.
            monkeypatch: Pytest monkeypatch fixture for replacing static methods.
        """
        del qapp
        recorder = _Recorder(return_value=QMessageBox.StandardButton.Close)
        monkeypatch.setattr(QMessageBox, "information", staticmethod(recorder))
        result = show_info(None, "T", "M")
        assert result == QMessageBox.StandardButton.Close
