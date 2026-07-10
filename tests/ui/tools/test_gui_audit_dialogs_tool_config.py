# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for GUI audit findings in ToolSettingsWidget.

Covers two fixes:

* M11 - empty install-path guard. ``Path(self._path_input.text().strip())``
  yields ``WindowsPath('.')`` for an empty field, which is always truthy, so
  the ``if not install_path`` guard never fired and a cleared field would
  extract the download into the current working directory instead of the
  default ``tools/<tool_id>`` location. The fix tests the stripped string
  before wrapping it in ``Path``.
* Worker guard. The manual install and status-check triggers reassigned their
  worker attribute without first checking whether the previous worker was
  still running, orphaning a live ``QThread``. The fix returns early while a
  worker is running.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast, override

import pytest
from PyQt6.QtWidgets import QMessageBox

import intellicrack.ui.tool_config as tool_config_mod
from intellicrack.ui.tool_config import ToolInstallWorker, ToolSettingsWidget, ToolStatusCheckWorker


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication, QLineEdit


def _path_input(widget: ToolSettingsWidget) -> QLineEdit:
    """Return the install-path input without tripping private-usage checks.

    Args:
        widget: The ToolSettingsWidget under test.

    Returns:
        QLineEdit: The install-path line edit.
    """
    value: object = getattr(widget, "_path_input")
    return cast("QLineEdit", value)


def _invoke(widget: ToolSettingsWidget, name: str) -> None:
    """Invoke a no-argument private method without tripping private-usage checks.

    Args:
        widget: The ToolSettingsWidget under test.
        name: The private method name to invoke.
    """
    method: object = getattr(widget, name)
    cast("Callable[[], None]", method)()


class _FakeQuestionBox:
    """Stand-in for ``QMessageBox`` whose ``question`` never blocks on a modal.

    Attributes:
        StandardButton: The real ``QMessageBox.StandardButton`` enum, reused so
            production code comparing against ``StandardButton.Yes`` still works.
    """

    StandardButton = QMessageBox.StandardButton

    @staticmethod
    def question(*_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
        """Return ``No`` so the confirm dialog resolves without a real prompt.

        Args:
            *_args: Ignored positional arguments.
            **_kwargs: Ignored keyword arguments.

        Returns:
            QMessageBox.StandardButton: Always ``No``.
        """
        return QMessageBox.StandardButton.No


class _CallRecorder:
    """Records call count for assertions without a mock library."""

    def __init__(self) -> None:
        """Initialise the recorder with a zero call count."""
        self.calls: int = 0

    def __call__(self, *_args: object, **_kwargs: object) -> None:
        """Record one invocation.

        Args:
            *_args: Ignored positional arguments.
            **_kwargs: Ignored keyword arguments.
        """
        self.calls += 1


class _RunningInstallWorker(ToolInstallWorker):
    """A ToolInstallWorker that reports itself as perpetually running.

    The override lets the running-worker guard be exercised deterministically
    without starting a real OS thread. It is a genuine subclass, not a mock:
    the base constructor runs and the object is a real ``ToolInstallWorker``.
    """

    @override
    def isRunning(self) -> bool:
        """Report the worker as running.

        Returns:
            bool: Always ``True``.
        """
        return True


class _RunningStatusWorker(ToolStatusCheckWorker):
    """A ToolStatusCheckWorker that reports itself as perpetually running."""

    @override
    def isRunning(self) -> bool:
        """Report the worker as running.

        Returns:
            bool: Always ``True``.
        """
        return True


@pytest.fixture
def widget(qapp: QApplication, tmp_path: Path) -> Iterator[ToolSettingsWidget]:
    """Create a ToolSettingsWidget for the installable ``ghidra`` tool.

    ``ghidra`` is used because it is a non-builtin tool present in
    ``ToolInstallWorker.DOWNLOAD_URLS`` and it does not require the optional
    ``pefile`` dependency, so ``_install_tool`` reaches the path-resolution
    logic under test.

    Args:
        qapp: Session-scoped Qt application fixture.
        tmp_path: Per-test temporary directory.

    Yields:
        ToolSettingsWidget: A live widget rooted at the temp directory.
    """
    del qapp
    w = ToolSettingsWidget(
        "ghidra",
        "Ghidra",
        "Software reverse engineering suite",
        tools_directory=tmp_path / "tools",
        config_path=tmp_path / "tools.json",
    )
    yield w
    w.deleteLater()


class TestM11EmptyInstallPathGuard:
    """M11: a cleared install-path field must fall back to tools/<tool_id>."""

    def test_empty_field_resolves_to_default_tools_path(
        self,
        widget: ToolSettingsWidget,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """An empty path field is replaced with the default tools/<tool_id> path.

        The pre-fix bug wrapped ``""`` in ``Path`` first, producing
        ``WindowsPath('.')`` which is truthy, so the field stayed empty and the
        install target became the current working directory. Post-fix, the
        empty field is detected and rewritten to the default location.

        Args:
            widget: ToolSettingsWidget fixture.
            monkeypatch: Pytest monkeypatch fixture.
            tmp_path: Per-test temporary directory.
        """
        monkeypatch.setattr(tool_config_mod, "QMessageBox", _FakeQuestionBox)
        _path_input(widget).setText("")

        _invoke(widget, "_install_tool")

        expected = str(tmp_path / "tools" / "ghidra")
        resolved = _path_input(widget).text()
        assert resolved == expected, (
            f"an empty install path must resolve to tools/<tool_id>, not the CWD; expected {expected!r}, got {resolved!r}"
        )
        assert resolved not in {"", "."}, "resolved path must never be empty or the current directory"

    def test_whitespace_only_field_resolves_to_default_tools_path(
        self,
        widget: ToolSettingsWidget,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """A whitespace-only path field is treated as empty and reset to the default.

        Args:
            widget: ToolSettingsWidget fixture.
            monkeypatch: Pytest monkeypatch fixture.
            tmp_path: Per-test temporary directory.
        """
        monkeypatch.setattr(tool_config_mod, "QMessageBox", _FakeQuestionBox)
        _path_input(widget).setText("   ")

        _invoke(widget, "_install_tool")

        expected = str(tmp_path / "tools" / "ghidra")
        resolved = _path_input(widget).text()
        assert resolved == expected, f"a whitespace-only install path must resolve to tools/<tool_id>; got {resolved!r}"

    def test_explicit_path_is_left_untouched(
        self,
        widget: ToolSettingsWidget,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """A user-supplied non-empty path is preserved verbatim (empty branch not taken).

        Args:
            widget: ToolSettingsWidget fixture.
            monkeypatch: Pytest monkeypatch fixture.
            tmp_path: Per-test temporary directory.
        """
        monkeypatch.setattr(tool_config_mod, "QMessageBox", _FakeQuestionBox)
        custom = str(tmp_path / "custom_location")
        _path_input(widget).setText(custom)

        _invoke(widget, "_install_tool")

        resolved = _path_input(widget).text()
        assert resolved == custom, f"an explicitly supplied install path must be left unchanged; expected {custom!r}, got {resolved!r}"


class TestWorkerRunningGuards:
    """Manual triggers must not orphan a still-running worker QThread."""

    def test_install_trigger_does_not_replace_running_worker(
        self,
        widget: ToolSettingsWidget,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Calling install while an install worker runs is a no-op, not a replacement.

        Args:
            widget: ToolSettingsWidget fixture.
            monkeypatch: Pytest monkeypatch fixture.
            tmp_path: Per-test temporary directory.
        """
        recorder = _CallRecorder()
        monkeypatch.setattr(tool_config_mod, "show_info", recorder)
        running = _RunningInstallWorker("ghidra", tmp_path / "tools" / "ghidra", widget)
        setattr(widget, "_install_worker", running)

        _invoke(widget, "_install_tool")

        worker_after: object = getattr(widget, "_install_worker")
        assert worker_after is running, "the install trigger must not replace a running worker, which would orphan its QThread"
        assert recorder.calls >= 1, "the busy branch must inform the user that installation is already in progress"

    def test_status_trigger_does_not_replace_running_worker(
        self,
        widget: ToolSettingsWidget,
        tmp_path: Path,
    ) -> None:
        """Calling status-check while a status worker runs is a no-op, not a replacement.

        Args:
            widget: ToolSettingsWidget fixture.
            tmp_path: Per-test temporary directory.
        """
        running = _RunningStatusWorker("ghidra", str(tmp_path / "tools" / "ghidra"), widget)
        setattr(widget, "_status_worker", running)

        _invoke(widget, "_check_status")

        worker_after: object = getattr(widget, "_status_worker")
        assert worker_after is running, "the status-check trigger must not replace a running worker, which would orphan its QThread"
        assert widget.status_label.text() != "Checking...", (
            "the guard must return before mutating status UI when a check is already running"
        )
