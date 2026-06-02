# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for audit4 B5 — ModulesTab F-0004 (filter wiring) and F-0024 (error callbacks).

Validates that:

* The ``_mod_filter`` QLineEdit is connected to ``_on_filter_modules``, which
  hides tree rows that do not match the typed substring and reveals them all
  when the field is cleared.
* The handles, heaps, COM, and .NET refresh methods drive a real
  ``ProcessBridge`` coroutine that genuinely fails (its backing Win32 library
  is unavailable) end to end through ``run_bridge_coroutine_logged`` and the
  background worker, surfacing the bridge ``ToolError`` via
  ``QMessageBox.warning`` rather than swallowing it silently.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtCore import QCoreApplication, QEventLoop, QTimer
from PyQt6.QtWidgets import QMessageBox, QTreeWidgetItem

from intellicrack.bridges.process import ProcessBridge
from intellicrack.core.types import ToolError
from intellicrack.ui.panels.process_panel.modules_tab import ModulesTab


if TYPE_CHECKING:
    from collections.abc import Callable

    from PyQt6.QtWidgets import QApplication


_MODULE_NAMES: Final[tuple[str, ...]] = (
    "kernel32.dll",
    "ntdll.dll",
    "user32.dll",
    "KernelBase.dll",
    "ws2_32.dll",
)


class _HarnessModulesTab(ModulesTab):
    """ModulesTab subclass exposing public hooks for the tests.

    Reaching into single-underscore attributes from outside the class
    hierarchy trips basedpyright's ``reportPrivateUsage`` under strict mode.
    Subclassing keeps every private access inside the class hierarchy while
    still exercising the real production widget, signals, and slots: the
    filter still flows through the genuine ``QLineEdit.textChanged`` wiring
    and the refresh hooks call the unmodified production methods.
    """

    def populate(self, names: tuple[str, ...]) -> None:
        """Insert one top-level module row per name into the real tree.

        Args:
            names: Module file names to add as rows.
        """
        for name in names:
            QTreeWidgetItem(
                self._mod_tree,
                [name, "0x7FF800000000", "1,024 bytes", f"C:\\Windows\\System32\\{name}", "0x0"],
            )

    def type_filter(self, text: str) -> None:
        """Drive the real filter ``QLineEdit`` via ``setText``.

        Args:
            text: Text to place in the filter field, triggering the wired
                ``textChanged`` -> ``_on_filter_modules`` slot.
        """
        self._mod_filter.setText(text)

    def visible_names(self) -> list[str]:
        """Return the names of currently visible top-level rows in order.

        Returns:
            list[str]: Module names from non-hidden top-level items.
        """
        root = self._mod_tree.invisibleRootItem()
        if root is None:
            return []
        names: list[str] = []
        for i in range(root.childCount()):
            child = root.child(i)
            if child is not None and not child.isHidden():
                names.append(child.text(0))
        return names

    def hidden_count(self) -> int:
        """Return the number of hidden top-level rows.

        Returns:
            int: Count of hidden top-level items.
        """
        root = self._mod_tree.invisibleRootItem()
        if root is None:
            return 0
        return sum(1 for i in range(root.childCount()) if (child := root.child(i)) is not None and child.isHidden())

    def configure(self, bridge: ProcessBridge, pid: int | None) -> None:
        """Attach a bridge and set the attached PID for refresh dispatch.

        Args:
            bridge: Process bridge to drive the refresh coroutines through.
            pid: Attached process id, or ``None`` to leave the tab detached.
        """
        self.set_bridge(bridge)
        self.set_attached_pid(pid)

    def invoke_refresh(self, which: str) -> None:
        """Call one of the production refresh slots by name.

        Args:
            which: One of ``"handles"``, ``"heaps"``, ``"com"``, ``"dotnet"``.

        Raises:
            ValueError: If ``which`` is not a recognised refresh name.
        """
        dispatch = {
            "handles": self._refresh_handles,
            "heaps": self._refresh_heaps,
            "com": self._refresh_com,
            "dotnet": self._refresh_dotnet,
        }
        slot = dispatch.get(which)
        if slot is None:
            msg = f"unknown refresh: {which!r}"
            raise ValueError(msg)
        slot()


@pytest.fixture
def tab(qapp: QApplication) -> _HarnessModulesTab:
    """Create a populated ModulesTab harness for testing.

    Args:
        qapp: QApplication fixture required by Qt widgets.

    Returns:
        _HarnessModulesTab: A freshly constructed harness with the standard
        module rows already inserted.
    """
    _ = qapp
    widget = _HarnessModulesTab()
    widget.populate(_MODULE_NAMES)
    return widget


class TestFilterWiring:
    """Verify F-0004 — _mod_filter is connected and filters the tree correctly.

    Every test drives the real ``QLineEdit.textChanged`` signal wired to
    ``_on_filter_modules`` (no direct method call), so a regression that
    disconnects the signal, drops the ``.lower()`` case-fold, inverts the
    ``setHidden`` predicate, or fails to clear on empty input is caught.
    """

    def test_filter_partial_match_hides_non_matching_rows(self, tab: _HarnessModulesTab) -> None:
        """Typing 'kernel' shows exactly the two kernel rows, hides three.

        Args:
            tab: ModulesTab fixture with pre-populated module entries.
        """
        assert len(tab.visible_names()) == len(_MODULE_NAMES)
        tab.type_filter("kernel")
        assert tab.visible_names() == ["kernel32.dll", "KernelBase.dll"]
        assert tab.hidden_count() == 3

    def test_filter_exact_full_name_isolates_single_row(self, tab: _HarnessModulesTab) -> None:
        """An exact full module name shows only that one row.

        Args:
            tab: ModulesTab fixture with pre-populated module entries.
        """
        tab.type_filter("ws2_32.dll")
        assert tab.visible_names() == ["ws2_32.dll"]
        assert tab.hidden_count() == len(_MODULE_NAMES) - 1

    def test_filter_case_insensitive(self, tab: _HarnessModulesTab) -> None:
        """The filter is case-insensitive ('NTDLL' matches 'ntdll.dll').

        Args:
            tab: ModulesTab fixture with pre-populated module entries.
        """
        tab.type_filter("NTDLL")
        assert tab.visible_names() == ["ntdll.dll"]
        tab.type_filter("kernelbase")
        assert tab.visible_names() == ["KernelBase.dll"]

    def test_filter_no_match_hides_all(self, tab: _HarnessModulesTab) -> None:
        """A filter string that matches nothing hides every row.

        Args:
            tab: ModulesTab fixture with pre-populated module entries.
        """
        tab.type_filter("zzz_no_match_zzz")
        assert tab.visible_names() == []
        assert tab.hidden_count() == len(_MODULE_NAMES)

    def test_clearing_filter_restores_every_previously_hidden_row(self, tab: _HarnessModulesTab) -> None:
        """Narrowing then clearing the field re-reveals all rows in order.

        Drives the full hide/restore cycle: a narrow filter first hides
        four rows, then an empty string must un-hide every one of them.

        Args:
            tab: ModulesTab fixture with pre-populated module entries.
        """
        tab.type_filter("ntdll")
        assert tab.hidden_count() == len(_MODULE_NAMES) - 1
        tab.type_filter("")
        assert tab.hidden_count() == 0
        assert tab.visible_names() == list(_MODULE_NAMES)

    def test_whitespace_only_filter_is_treated_as_empty(self, tab: _HarnessModulesTab) -> None:
        """A whitespace-only filter strips to empty and hides nothing.

        Args:
            tab: ModulesTab fixture with pre-populated module entries.
        """
        tab.type_filter("kernel")
        assert tab.hidden_count() == 3
        tab.type_filter("   ")
        assert tab.hidden_count() == 0
        assert tab.visible_names() == list(_MODULE_NAMES)


def _pump_until(predicate: Callable[[], bool], qapp: QCoreApplication, timeout_ms: int = 8000) -> bool:
    """Spin the Qt event loop until ``predicate()`` is truthy or time runs out.

    Args:
        predicate: Zero-argument callable whose truth value is checked after
            each pump iteration.
        qapp: Running application instance used to drain queued cross-thread
            signal deliveries.
        timeout_ms: Maximum total milliseconds to wait.

    Returns:
        bool: True if the predicate became truthy within the timeout.
    """
    elapsed_ms = 0
    step_ms = 20
    while elapsed_ms < timeout_ms:
        if predicate():
            return True
        loop = QEventLoop()
        QTimer.singleShot(step_ms, loop.quit)
        loop.exec()
        qapp.processEvents()
        elapsed_ms += step_ms
    return predicate()


class _LibraryUnavailableBridge(ProcessBridge):
    """Real ProcessBridge forced into its Win32-library-unavailable state.

    After normal construction, every library handle the refresh coroutines
    depend on is cleared to ``None`` — the genuine "external tool
    misconfigured" condition the bridge already guards against. Each affected
    coroutine (``get_handles``, ``get_heaps``, ``enumerate_com_servers``,
    ``detect_dotnet``) then raises its documented :class:`ToolError` from
    real production code. Subclassing keeps the private-attribute writes
    inside the class hierarchy; the coroutines run unmodified, so this is the
    real failure path, not a stub.
    """

    def __init__(self) -> None:
        """Construct the bridge, then null out every backing library handle."""
        super().__init__()
        self._kernel32 = None
        self._ntdll = None
        self._advapi32 = None
        self._psapi = None


def _unavailable_bridge() -> ProcessBridge:
    """Return a real bridge whose enumeration coroutines raise ``ToolError``.

    Returns:
        ProcessBridge: A bridge in the library-unavailable error state.
    """
    return _LibraryUnavailableBridge()


class TestErrorCallbacks:
    """Verify F-0024 — refresh methods surface real bridge errors in the UI.

    Each test drives a real :class:`ProcessBridge` coroutine that genuinely
    fails (its backing Win32 library is unavailable) through the real
    ``run_bridge_coroutine_logged`` -> ``BridgeCallWorker`` -> ``call_error``
    -> ``_on_error`` path on the actual background event loop, then asserts
    the real ``QMessageBox.warning`` fired with the correct dialog title and
    the exact ``ToolError`` text. Nothing in the failure-propagation path is
    mocked; only the terminal modal sink is captured so the test stays
    non-interactive.
    """

    @staticmethod
    def _capture_warning(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
        """Record every ``QMessageBox.warning`` call as a ``(title, text)`` pair.

        Args:
            monkeypatch: pytest monkeypatch fixture.

        Returns:
            list[tuple[str, str]]: Mutable list appended to on each call.
        """
        calls: list[tuple[str, str]] = []

        def recorder(
            _parent: object,
            title: str,
            text: str,
            *_args: object,
            **_kwargs: object,
        ) -> QMessageBox.StandardButton:
            calls.append((title, text))
            return QMessageBox.StandardButton.Ok

        monkeypatch.setattr(QMessageBox, "warning", staticmethod(recorder))
        return calls

    def _drive_to_error(
        self,
        tab: _HarnessModulesTab,
        which: str,
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> tuple[str, str]:
        """Run a refresh against an unavailable bridge and return the warning.

        Args:
            tab: ModulesTab harness under test.
            which: Refresh selector (``"handles"``/``"heaps"``/``"com"``/``"dotnet"``).
            qapp: QApplication used to pump queued signal deliveries.
            monkeypatch: pytest monkeypatch fixture used to capture the modal.

        Returns:
            tuple[str, str]: The ``(title, text)`` of the single
            ``QMessageBox.warning`` raised by the real ``_on_error`` callback.
        """
        tab.configure(_unavailable_bridge(), 0x7FFFFFFE)
        calls = self._capture_warning(monkeypatch)

        tab.invoke_refresh(which)

        delivered = _pump_until(lambda: len(calls) >= 1, qapp)
        assert delivered, "bridge failure never surfaced a QMessageBox.warning within the timeout"
        assert len(calls) == 1, f"expected exactly one warning dialog, got {len(calls)}: {calls!r}"
        return calls[0]

    def test_refresh_handles_surfaces_ntdll_unavailable(
        self,
        tab: _HarnessModulesTab,
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A handle-enumeration failure raises the Handle error dialog.

        Args:
            tab: ModulesTab fixture instance.
            qapp: QApplication fixture for event pumping.
            monkeypatch: pytest monkeypatch fixture.
        """
        title, text = self._drive_to_error(tab, "handles", qapp, monkeypatch)
        assert title == "Handle Enumeration Error"
        assert text == "ntdll not available"

    def test_refresh_heaps_surfaces_kernel32_unavailable(
        self,
        tab: _HarnessModulesTab,
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A heap-enumeration failure raises the Heap error dialog.

        Args:
            tab: ModulesTab fixture instance.
            qapp: QApplication fixture for event pumping.
            monkeypatch: pytest monkeypatch fixture.
        """
        title, text = self._drive_to_error(tab, "heaps", qapp, monkeypatch)
        assert title == "Heap Enumeration Error"
        assert text == "kernel32 not available"

    def test_refresh_com_surfaces_advapi32_unavailable(
        self,
        tab: _HarnessModulesTab,
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A COM-enumeration failure raises the COM error dialog.

        Args:
            tab: ModulesTab fixture instance.
            qapp: QApplication fixture for event pumping.
            monkeypatch: pytest monkeypatch fixture.
        """
        title, text = self._drive_to_error(tab, "com", qapp, monkeypatch)
        assert title == "COM Enumeration Error"
        assert text == "advapi32 not available"

    def test_refresh_dotnet_surfaces_kernel32_unavailable(
        self,
        tab: _HarnessModulesTab,
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A .NET-detection failure raises the .NET error dialog.

        Args:
            tab: ModulesTab fixture instance.
            qapp: QApplication fixture for event pumping.
            monkeypatch: pytest monkeypatch fixture.
        """
        title, text = self._drive_to_error(tab, "dotnet", qapp, monkeypatch)
        assert title == ".NET Detection Error"
        assert text == "kernel32 not available"

    def test_refresh_handles_no_op_without_attached_pid(
        self,
        tab: _HarnessModulesTab,
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """With no attached PID the refresh is a no-op and shows no dialog.

        This guards the early-return guard in ``_refresh_handles``: when no
        process is attached the method must not dispatch a coroutine and must
        not raise an error dialog, distinguishing "nothing to do" from
        "operation failed".

        Args:
            tab: ModulesTab fixture instance.
            qapp: QApplication fixture for event pumping.
            monkeypatch: pytest monkeypatch fixture.
        """
        tab.configure(_unavailable_bridge(), None)
        calls = self._capture_warning(monkeypatch)

        tab.invoke_refresh("handles")

        appeared = _pump_until(lambda: len(calls) >= 1, qapp, timeout_ms=400)
        assert not appeared, f"no-op refresh must not raise a dialog; got {calls!r}"

    def test_real_tool_error_propagates_as_tool_error_type(self) -> None:
        """The bridge raises a typed ToolError, not a generic exception.

        Confirms the failure surfaced to the UI is the documented
        :class:`ToolError`, anchoring the exact error text used by the
        dialog tests above to the real production contract.
        """
        bridge = _unavailable_bridge()
        with pytest.raises(ToolError) as excinfo:
            asyncio.run(bridge.get_heaps(0x7FFFFFFE))
        assert str(excinfo.value) == "kernel32 not available"
