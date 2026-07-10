# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for audit4 B5 — ModulesTab F-0004 (filter wiring) and F-0024 (error callbacks).

Validates that:

* The ``_mod_filter`` QLineEdit is connected to ``_on_filter_modules``, which
  hides tree rows that do not match the typed substring and reveals them all
  when the field is cleared.
* The handles, heaps, COM, and .NET refresh methods pass an ``on_error``
  callback to ``run_bridge_coroutine_logged`` so bridge errors are surfaced via
  ``QMessageBox.warning`` rather than swallowed silently.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtWidgets import QMessageBox, QTreeWidgetItem

from intellicrack.bridges.process import ProcessBridge
from intellicrack.ui.panels.process_panel.modules_tab import ModulesTab


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from PyQt6.QtWidgets import QApplication


_BRIDGE_MODULE_PATH: Final[str] = "intellicrack.ui.panels.process_panel.modules_tab.run_bridge_coroutine_logged"

_MODULE_NAMES: Final[tuple[str, ...]] = (
    "kernel32.dll",
    "ntdll.dll",
    "user32.dll",
    "KernelBase.dll",
    "ws2_32.dll",
)


@pytest.fixture
def tab(qapp: QApplication) -> ModulesTab:
    """Create a ModulesTab widget for testing.

    Args:
        qapp: QApplication fixture required by Qt widgets.

    Returns:
        ModulesTab: A freshly constructed ModulesTab instance.
    """
    _ = qapp
    widget = ModulesTab()
    for name in _MODULE_NAMES:
        QTreeWidgetItem(
            getattr(widget, "_mod_tree"),
            [name, "0x7FF800000000", "1,024 bytes", f"C:\\Windows\\System32\\{name}", "0x0"],
        )
    return widget


def _visible_names(tab: ModulesTab) -> list[str]:
    """Collect the text of all visible top-level tree items in the module list.

    Args:
        tab: ModulesTab instance to inspect.

    Returns:
        list[str]: Module names from visible (non-hidden) top-level items.
    """
    root = getattr(tab, "_mod_tree").invisibleRootItem()
    if root is None:
        return []
    names: list[str] = []
    for i in range(root.childCount()):
        child = root.child(i)
        if child is not None and not child.isHidden():
            names.append(child.text(0))
    return names


def _hidden_count(tab: ModulesTab) -> int:
    """Count the number of hidden top-level tree items in the module list.

    Args:
        tab: ModulesTab instance to inspect.

    Returns:
        int: Number of hidden top-level items.
    """
    root = getattr(tab, "_mod_tree").invisibleRootItem()
    if root is None:
        return 0
    count = 0
    for i in range(root.childCount()):
        child = root.child(i)
        if child is not None and child.isHidden():
            count += 1
    return count


class TestFilterWiring:
    """Verify F-0004 — _mod_filter is connected and filters the tree correctly."""

    def test_filter_hides_non_matching_rows(self, tab: ModulesTab) -> None:
        """Typing 'kernel' hides rows whose name does not contain 'kernel'.

        Args:
            tab: ModulesTab fixture with pre-populated module entries.
        """
        getattr(tab, "_mod_filter").setText("kernel")
        assert _visible_names(tab) == ["kernel32.dll", "KernelBase.dll"]

    def test_filter_case_insensitive(self, tab: ModulesTab) -> None:
        """The filter is case-insensitive ('NTDLL' matches 'ntdll.dll').

        Args:
            tab: ModulesTab fixture with pre-populated module entries.
        """
        getattr(tab, "_mod_filter").setText("NTDLL")
        assert _visible_names(tab) == ["ntdll.dll"]

    def test_clear_filter_shows_all_rows(self, tab: ModulesTab) -> None:
        """Clearing the filter after typing reveals all rows again.

        Args:
            tab: ModulesTab fixture with pre-populated module entries.
        """
        getattr(tab, "_mod_filter").setText("kernel")
        getattr(tab, "_mod_filter").setText("")
        assert _hidden_count(tab) == 0

    def test_filter_no_match_hides_all(self, tab: ModulesTab) -> None:
        """A filter string that matches nothing hides every row.

        Args:
            tab: ModulesTab fixture with pre-populated module entries.
        """
        getattr(tab, "_mod_filter").setText("zzz_no_match_zzz")
        assert len(_visible_names(tab)) == 0


class TestErrorCallbacks:
    """Verify F-0024 — refresh methods surface bridge errors via on_error callback."""

    @staticmethod
    def _make_error_capturer(
        monkeypatch: pytest.MonkeyPatch,
        tab: ModulesTab,
    ) -> list[tuple[object, Callable[[object], None] | None]]:
        """Monkeypatch run_bridge_coroutine_logged to capture the on_error argument.

        Args:
            monkeypatch: pytest monkeypatch fixture.
            tab: The ModulesTab under test.

        Returns:
            list[tuple[object, Callable[[object], None] | None]]: Captured (coro, on_error) pairs.
        """
        captured: list[tuple[object, Callable[[object], None] | None]] = []

        def fake_run(
            coro: Coroutine[object, object, object],
            on_success: Callable[[object], None] | None = None,
            on_error: Callable[[object], None] | None = None,
            parent: object = None,
            *,
            event: str = "",
            logger: object = None,
            **context: object,
        ) -> None:
            _ = (on_success, parent, event, logger, context)
            captured.append((coro, on_error))
            coro.close()

        monkeypatch.setattr(_BRIDGE_MODULE_PATH, fake_run)
        setattr(tab, "_attached_pid", 1234)
        return captured

    def test_refresh_handles_provides_on_error(self, tab: ModulesTab, monkeypatch: pytest.MonkeyPatch) -> None:
        """_refresh_handles passes a non-None on_error to run_bridge_coroutine_logged.

        Args:
            tab: ModulesTab fixture instance.
            monkeypatch: pytest monkeypatch fixture.
        """
        tab.set_bridge(ProcessBridge())
        captured = self._make_error_capturer(monkeypatch, tab)
        getattr(tab, "_refresh_handles")()
        assert len(captured) == 1
        assert captured[0][1] is not None

    def test_refresh_heaps_provides_on_error(self, tab: ModulesTab, monkeypatch: pytest.MonkeyPatch) -> None:
        """_refresh_heaps passes a non-None on_error to run_bridge_coroutine_logged.

        Args:
            tab: ModulesTab fixture instance.
            monkeypatch: pytest monkeypatch fixture.
        """
        tab.set_bridge(ProcessBridge())
        captured = self._make_error_capturer(monkeypatch, tab)
        getattr(tab, "_refresh_heaps")()
        assert len(captured) == 1
        assert captured[0][1] is not None

    def test_refresh_com_provides_on_error(self, tab: ModulesTab, monkeypatch: pytest.MonkeyPatch) -> None:
        """_refresh_com passes a non-None on_error to run_bridge_coroutine_logged.

        Args:
            tab: ModulesTab fixture instance.
            monkeypatch: pytest monkeypatch fixture.
        """
        tab.set_bridge(ProcessBridge())
        captured = self._make_error_capturer(monkeypatch, tab)
        getattr(tab, "_refresh_com")()
        assert len(captured) == 1
        assert captured[0][1] is not None

    def test_refresh_dotnet_provides_on_error(self, tab: ModulesTab, monkeypatch: pytest.MonkeyPatch) -> None:
        """_refresh_dotnet passes a non-None on_error to run_bridge_coroutine_logged.

        Args:
            tab: ModulesTab fixture instance.
            monkeypatch: pytest monkeypatch fixture.
        """
        tab.set_bridge(ProcessBridge())
        captured = self._make_error_capturer(monkeypatch, tab)
        getattr(tab, "_refresh_dotnet")()
        assert len(captured) == 1
        assert captured[0][1] is not None

    def test_on_error_callback_shows_qmessagebox(
        self,
        tab: ModulesTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Invoking the on_error callback triggers QMessageBox.warning.

        Args:
            tab: ModulesTab fixture instance.
            monkeypatch: pytest monkeypatch fixture.
        """
        tab.set_bridge(ProcessBridge())
        captured = self._make_error_capturer(monkeypatch, tab)
        getattr(tab, "_refresh_handles")()

        warning_calls: list[tuple[object, ...]] = []

        def fake_warning(*args: object, **_kwargs: object) -> QMessageBox.StandardButton:
            warning_calls.append(args)
            return QMessageBox.StandardButton.Ok

        monkeypatch.setattr(QMessageBox, "warning", staticmethod(fake_warning))

        on_error = captured[0][1]
        assert on_error is not None
        on_error(RuntimeError("bridge exploded"))

        assert len(warning_calls) == 1
        title_arg = warning_calls[0][1]
        message_arg = warning_calls[0][2]
        assert isinstance(title_arg, str)
        assert "Handle" in title_arg
        assert "bridge exploded" in str(message_arg)
