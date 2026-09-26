# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 gate tests for the x64dbg Advanced tab's resource / TLS-callback controls.

Finding T2-8a: ``X64DbgBridge.get_resources``, ``get_tls_callbacks``, and
``break_on_tls_callbacks`` were fully implemented and registered tool
functions with no reachable GUI control in either ``x64dbg_panel.py`` or
``x64dbg_advanced_tab.py``. This module gates the three controls added to
the Advanced tab's "Module Info" sub-tab.

``get_resources`` and ``get_tls_callbacks`` walk the module's in-memory PE
header through a sequence of ``read_memory`` RPCs (like ``get_entry_point``
in ``test_x64dbg_advanced_tab_l3.py``), so their button-dispatch gates use
the same coroutine-capture pattern established there rather than a
single-response pipe responder. The table/label rendering driven by their
results is gated separately by invoking the real, private ``_apply_*``
handlers through ``getattr`` (mirroring the ``priv`` helper's rationale in
``conftest.py``: precise, deliberate private access without tripping
``reportPrivateUsage``) with bridge-shaped payloads.
"""

from __future__ import annotations

import asyncio
import sys
from typing import TYPE_CHECKING, Any, TypeVar

import pytest
from PyQt6.QtWidgets import QApplication, QLabel, QLineEdit, QPushButton, QTableWidget

from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.ui.panels import x64dbg_advanced_tab as _advanced_mod
from intellicrack.ui.panels.x64dbg_advanced_tab import X64DbgAdvancedTab

from .conftest import priv


if TYPE_CHECKING:
    import types
    from collections.abc import Iterator


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="x64dbg is a Windows-only debugger bridge")


_T = TypeVar("_T")


async def _unreached_result[T](value: T) -> T:
    """Return ``value``; the coroutine wrapping it is captured, never awaited.

    Args:
        value: Placeholder result the coroutine would resolve to.

    Returns:
        T: ``value`` unchanged.
    """
    await asyncio.sleep(0)
    return value


class _CallRecordingX64DbgBridge(X64DbgBridge):
    """Real ``X64DbgBridge`` whose PE-walking / OS-query entry points only record calls.

    The overridden methods record the exact arguments they were called with
    and hand back a fresh, never-started coroutine so the test can assert the
    object passed to ``run_bridge_coroutine_logged`` is precisely that method's
    return value. :meth:`close_pending` closes every coroutine handed out so no
    "never awaited" warning leaks from the capture.
    """

    def __init__(self) -> None:
        """Initialize a pipe-less bridge with empty call/coroutine logs."""
        super().__init__()
        self.calls: list[tuple[str, tuple[object, ...]]] = []
        self.returned: dict[str, list[types.CoroutineType[Any, Any, Any]]] = {}

    def _record(self, name: str, args: tuple[object, ...], coro: types.CoroutineType[Any, Any, _T]) -> types.CoroutineType[Any, Any, _T]:
        """Log a call and remember the coroutine it returns.

        Args:
            name: Bridge method name that was called.
            args: Positional arguments the method received.
            coro: The coroutine being returned to the caller.

        Returns:
            types.CoroutineType[Any, Any, _T]: ``coro`` unchanged.
        """
        self.calls.append((name, args))
        self.returned.setdefault(name, []).append(coro)
        return coro

    def calls_to(self, name: str) -> list[tuple[object, ...]]:
        """Return the argument tuples of every recorded call to ``name``.

        Args:
            name: Bridge method name to filter on.

        Returns:
            list[tuple[object, ...]]: Recorded positional-argument tuples.
        """
        return [args for called, args in self.calls if called == name]

    def close_pending(self) -> None:
        """Close every captured coroutine so none is reported as never awaited."""
        for coros in self.returned.values():
            for coro in coros:
                coro.close()

    def get_resources(self, module_name: str) -> types.CoroutineType[Any, Any, list[dict[str, Any]]]:
        """Record the call and return an unstarted coroutine.

        Args:
            module_name: Module the handler read from the UI.

        Returns:
            types.CoroutineType[Any, Any, list[dict[str, Any]]]: Captured, never-awaited coroutine.
        """
        return self._record("get_resources", (module_name,), _unreached_result(list[dict[str, Any]]()))

    def get_tls_callbacks(self, module_name: str) -> types.CoroutineType[Any, Any, list[dict[str, Any]]]:
        """Record the call and return an unstarted coroutine.

        Args:
            module_name: Module the handler read from the UI.

        Returns:
            types.CoroutineType[Any, Any, list[dict[str, Any]]]: Captured, never-awaited coroutine.
        """
        return self._record("get_tls_callbacks", (module_name,), _unreached_result(list[dict[str, Any]]()))

    def break_on_tls_callbacks(self, module_name: str) -> types.CoroutineType[Any, Any, dict[str, Any]]:
        """Record the call and return an unstarted coroutine.

        Args:
            module_name: Module the handler read from the UI.

        Returns:
            types.CoroutineType[Any, Any, dict[str, Any]]: Captured, never-awaited coroutine.
        """
        return self._record("break_on_tls_callbacks", (module_name,), _unreached_result(dict[str, Any]()))


@pytest.fixture
def recording_bridge() -> Iterator[_CallRecordingX64DbgBridge]:
    """Provide a call-recording bridge and close its captured coroutines afterwards.

    Yields:
        _CallRecordingX64DbgBridge: The recording bridge.
    """
    bridge = _CallRecordingX64DbgBridge()
    yield bridge
    bridge.close_pending()


@pytest.fixture
def wired_tab(qapp: QApplication) -> Iterator[tuple[X64DbgAdvancedTab, X64DbgBridge]]:
    """Build a real Advanced tab wired to a real (pipe-less) ``X64DbgBridge``.

    Args:
        qapp: Session QApplication fixture (ensures Qt is initialised).

    Yields:
        tuple[X64DbgAdvancedTab, X64DbgBridge]: The tab and its bridge.
    """
    del qapp
    tab = X64DbgAdvancedTab()
    bridge = X64DbgBridge()
    tab.set_bridge(bridge)
    yield tab, bridge
    tab.deleteLater()


def _cell_text(table: QTableWidget, row: int, column: int) -> str:
    """Read a table cell's text, failing loudly when the cell is empty.

    Args:
        table: Table widget to read from.
        row: Row index.
        column: Column index.

    Returns:
        str: The cell's text.
    """
    item = table.item(row, column)
    assert item is not None, f"expected an item at ({row}, {column})"
    return item.text()


def _apply(tab: X64DbgAdvancedTab, handler_name: str, result: object) -> None:
    """Invoke a private ``_apply_*`` rendering handler on ``tab`` by name.

    Mirrors ``priv``'s ``getattr``-based access pattern (see
    ``conftest.py``) so calling a private rendering handler directly from
    a test does not trip ``reportPrivateUsage``.

    Args:
        tab: Advanced-tab widget whose handler to invoke.
        handler_name: Name of the private ``_apply_*`` method.
        result: The bridge-shaped payload to render.
    """
    handler = getattr(tab, handler_name)
    handler(result)


class _CoroutineCapture:
    """Records every call made to a monkeypatched ``run_bridge_coroutine_logged``.

    ``get_resources``/``get_tls_callbacks``/``break_on_tls_callbacks`` each
    walk the module's in-memory PE header through a sequence of
    ``read_memory`` RPCs (like ``get_entry_point`` in
    ``test_x64dbg_advanced_tab_l3.py``), so their button-dispatch gates
    replace ``run_bridge_coroutine_logged`` entirely and assert on the
    coroutine/arguments it was handed rather than scripting every
    intermediate pipe RPC.
    """

    def __init__(self) -> None:
        """Initialize with an empty call log."""
        self.calls: list[tuple[object, ...]] = []

    def __call__(self, *args: object, **kwargs: object) -> None:
        """Record a call's positional arguments.

        Args:
            *args: Positional arguments the handler passed through.
            **kwargs: Keyword arguments the handler passed through (unused).
        """
        del kwargs
        self.calls.append(args)


class TestResourcesButtonDispatch:
    """The Resources button must reach ``X64DbgBridge.get_resources``."""

    @staticmethod
    def test_resources_button_dispatches_get_resources_with_module(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        recording_bridge: _CallRecordingX64DbgBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The Resources button must call ``get_resources`` with the entered module.

        Falsifiable: before this fix nothing in either panel file called
        ``get_resources`` at all, so ``capture.calls`` would stay empty and
        this assertion would fail; rewiring the button to a different
        bridge method makes the captured coroutine no longer
        ``get_resources``'s return value.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            recording_bridge: Call-recording bridge swapped into the tab.
            monkeypatch: Pytest monkeypatch fixture.
        """
        tab, _bridge = wired_tab
        setattr(tab, "_bridge", recording_bridge)
        capture = _CoroutineCapture()

        monkeypatch.setattr(_advanced_mod, "run_bridge_coroutine_logged", capture)
        priv(tab, "_modinfo_name_input", QLineEdit).setText("kernel32.dll")

        priv(tab, "_modinfo_resources_btn", QPushButton).click()

        assert capture.calls, "Resources button must dispatch through run_bridge_coroutine_logged"
        assert capture.calls[0][0] is recording_bridge.returned["get_resources"][0]
        assert recording_bridge.calls == [("get_resources", ("kernel32.dll",))]

    @staticmethod
    def test_resources_button_blank_module_does_not_dispatch(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        recording_bridge: _CallRecordingX64DbgBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A blank module field must skip the ``get_resources`` dispatch entirely.

        Falsifiable: dropping the ``if module_name is None: return`` guard in
        ``_on_get_resources`` would let a blank field dispatch a bogus
        request, which this assertion forbids.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            recording_bridge: Call-recording bridge swapped into the tab.
            monkeypatch: Pytest monkeypatch fixture.
        """
        tab, _bridge = wired_tab
        setattr(tab, "_bridge", recording_bridge)
        capture = _CoroutineCapture()

        monkeypatch.setattr(_advanced_mod, "run_bridge_coroutine_logged", capture)
        priv(tab, "_modinfo_name_input", QLineEdit).setText("   ")

        priv(tab, "_modinfo_resources_btn", QPushButton).click()

        assert capture.calls == []
        assert recording_bridge.calls_to("get_resources") == []


class TestTlsCallbacksButtonDispatch:
    """The TLS Callbacks button must reach ``X64DbgBridge.get_tls_callbacks``."""

    @staticmethod
    def test_tls_callbacks_button_dispatches_get_tls_callbacks_with_module(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        recording_bridge: _CallRecordingX64DbgBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The TLS Callbacks button must call ``get_tls_callbacks`` with the entered module.

        Falsifiable: before this fix nothing in either panel file called
        ``get_tls_callbacks``; rewiring the button to a different bridge
        method makes the captured coroutine or call arguments wrong.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            recording_bridge: Call-recording bridge swapped into the tab.
            monkeypatch: Pytest monkeypatch fixture.
        """
        tab, _bridge = wired_tab
        setattr(tab, "_bridge", recording_bridge)
        capture = _CoroutineCapture()

        monkeypatch.setattr(_advanced_mod, "run_bridge_coroutine_logged", capture)
        priv(tab, "_modinfo_name_input", QLineEdit).setText("target.exe")

        priv(tab, "_modinfo_tls_btn", QPushButton).click()

        assert capture.calls, "TLS Callbacks button must dispatch through run_bridge_coroutine_logged"
        assert capture.calls[0][0] is recording_bridge.returned["get_tls_callbacks"][0]
        assert recording_bridge.calls == [("get_tls_callbacks", ("target.exe",))]

    @staticmethod
    def test_tls_callbacks_button_blank_module_does_not_dispatch(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        recording_bridge: _CallRecordingX64DbgBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A blank module field must skip the ``get_tls_callbacks`` dispatch entirely.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            recording_bridge: Call-recording bridge swapped into the tab.
            monkeypatch: Pytest monkeypatch fixture.
        """
        tab, _bridge = wired_tab
        setattr(tab, "_bridge", recording_bridge)
        capture = _CoroutineCapture()

        monkeypatch.setattr(_advanced_mod, "run_bridge_coroutine_logged", capture)
        priv(tab, "_modinfo_name_input", QLineEdit).setText("")

        priv(tab, "_modinfo_tls_btn", QPushButton).click()

        assert capture.calls == []
        assert recording_bridge.calls_to("get_tls_callbacks") == []


class TestBreakOnTlsCallbacksButtonDispatch:
    """The Break on TLS CBs button must reach ``X64DbgBridge.break_on_tls_callbacks``."""

    @staticmethod
    def test_break_button_dispatches_break_on_tls_callbacks_with_module(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        recording_bridge: _CallRecordingX64DbgBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The Break on TLS CBs button must call ``break_on_tls_callbacks`` with the entered module.

        Falsifiable: before this fix nothing in either panel file called
        ``break_on_tls_callbacks``; rewiring the button to a different
        bridge method makes the captured coroutine or call arguments wrong.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            recording_bridge: Call-recording bridge swapped into the tab.
            monkeypatch: Pytest monkeypatch fixture.
        """
        tab, _bridge = wired_tab
        setattr(tab, "_bridge", recording_bridge)
        capture = _CoroutineCapture()

        monkeypatch.setattr(_advanced_mod, "run_bridge_coroutine_logged", capture)
        priv(tab, "_modinfo_name_input", QLineEdit).setText("target.exe")

        priv(tab, "_modinfo_tls_break_btn", QPushButton).click()

        assert capture.calls, "Break on TLS CBs button must dispatch through run_bridge_coroutine_logged"
        assert capture.calls[0][0] is recording_bridge.returned["break_on_tls_callbacks"][0]
        assert recording_bridge.calls == [("break_on_tls_callbacks", ("target.exe",))]

    @staticmethod
    def test_break_button_blank_module_does_not_dispatch(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        recording_bridge: _CallRecordingX64DbgBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A blank module field must skip the ``break_on_tls_callbacks`` dispatch entirely.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
            recording_bridge: Call-recording bridge swapped into the tab.
            monkeypatch: Pytest monkeypatch fixture.
        """
        tab, _bridge = wired_tab
        setattr(tab, "_bridge", recording_bridge)
        capture = _CoroutineCapture()

        monkeypatch.setattr(_advanced_mod, "run_bridge_coroutine_logged", capture)
        priv(tab, "_modinfo_name_input", QLineEdit).setText("")

        priv(tab, "_modinfo_tls_break_btn", QPushButton).click()

        assert capture.calls == []
        assert recording_bridge.calls_to("break_on_tls_callbacks") == []


class TestApplyResourcesRendering:
    """``_apply_resources`` must render every documented field into its own column."""

    @staticmethod
    def test_apply_resources_populates_table_with_all_fields(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
    ) -> None:
        """Each resource-leaf field lands in the column matching its header.

        Falsifiable: swapping any column index in ``_apply_resources`` (for
        example writing ``id`` into the ``Name`` column) makes the
        corresponding cell assertion fail.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
        """
        tab, _bridge = wired_tab
        table = priv(tab, "_modinfo_table", QTableWidget)
        status_label = priv(tab, "_modinfo_status_label", QLabel)

        resources: list[dict[str, Any]] = [
            {
                "type_id": 3,
                "type_name": "RT_ICON",
                "id": 101,
                "name": "",
                "language": 1033,
                "rva": "0x3000",
                "size": 744,
                "code_page": 0,
            },
        ]

        _apply(tab, "_apply_resources", resources)

        assert table.columnCount() == 7
        assert table.rowCount() == 1
        assert _cell_text(table, 0, 0) == "RT_ICON"
        assert _cell_text(table, 0, 1) == "101"
        assert not _cell_text(table, 0, 2)
        assert _cell_text(table, 0, 3) == "1033"
        assert _cell_text(table, 0, 4) == "0x3000"
        assert _cell_text(table, 0, 5) == "744"
        assert _cell_text(table, 0, 6) == "0"
        assert status_label.text() == "1 resource(s) found"


class TestApplyTlsCallbacksRendering:
    """``_apply_tls_callbacks`` must render the index/address pairs."""

    @staticmethod
    def test_apply_tls_callbacks_populates_table(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
    ) -> None:
        """Each TLS callback's index and address land in their own columns.

        Falsifiable: swapping the ``index``/``address`` column assignment in
        ``_apply_tls_callbacks`` makes the corresponding cell assertion fail.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
        """
        tab, _bridge = wired_tab
        table = priv(tab, "_modinfo_table", QTableWidget)
        status_label = priv(tab, "_modinfo_status_label", QLabel)

        callbacks: list[dict[str, Any]] = [
            {"index": 0, "address": "0x140001000"},
            {"index": 1, "address": "0x140001050"},
        ]

        _apply(tab, "_apply_tls_callbacks", callbacks)

        assert table.columnCount() == 2
        assert table.rowCount() == 2
        assert _cell_text(table, 0, 0) == "0"
        assert _cell_text(table, 0, 1) == "0x140001000"
        assert _cell_text(table, 1, 0) == "1"
        assert _cell_text(table, 1, 1) == "0x140001050"
        assert status_label.text() == "2 TLS callback(s) found"


class TestApplyTlsBreakResultRendering:
    """``_apply_tls_break_result`` must report the actual breakpoint count."""

    @staticmethod
    def test_apply_tls_break_result_reports_breakpoints_set_count(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
    ) -> None:
        """The status label reflects the bridge's real ``breakpoints_set`` count.

        Falsifiable: hardcoding the label text or reading the wrong dict key
        in ``_apply_tls_break_result`` makes this assertion observe the
        wrong count.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
        """
        tab, _bridge = wired_tab
        status_label = priv(tab, "_modinfo_status_label", QLabel)

        _apply(tab, "_apply_tls_break_result", {"success": True, "breakpoints_set": 3})

        assert status_label.text() == "Set breakpoints on 3 TLS callback(s)"

    @staticmethod
    def test_apply_tls_break_result_defaults_to_zero_on_malformed_result(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
    ) -> None:
        """A non-dict or missing-count result renders as zero rather than raising.

        Args:
            wired_tab: Advanced-tab/bridge pair fixture.
        """
        tab, _bridge = wired_tab
        status_label = priv(tab, "_modinfo_status_label", QLabel)

        _apply(tab, "_apply_tls_break_result", None)

        assert status_label.text() == "Set breakpoints on 0 TLS callback(s)"
