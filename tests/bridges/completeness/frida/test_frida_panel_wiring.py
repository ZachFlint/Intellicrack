# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 gate tests for the Frida panel's lifecycle/scripting and instrumentation GUI wiring.

Covers the GUI column of ``audit/bridge-completeness/agent-07-frida-lifecycle-scripting.md``
and ``audit/bridge-completeness/agent-08-frida-instrumentation.md``: every widget/handler
under test must dispatch through ``run_bridge_coroutine_logged`` to a real
``FridaBridge`` coroutine method (never a repaint / local reimplementation), and the
resulting real Frida operation must actually take effect.

``run_bridge_coroutine_async`` (the low-level Qt-thread dispatch primitive in
``intellicrack.ui.panels.async_bridge``) is monkeypatched to drain the coroutine
synchronously on a private event loop instead of a background QThread -- this is
the same pattern used by ``tests/test_audit4/c12_hex_sandbox_route/test_sandbox_route.py``
and only replaces the *thread-dispatch mechanism*, never the bridge coroutine or the
widget's own click handler, both of which execute for real.

Each widget under test is driven through a thin test-only subclass exposing public
wrapper methods around its protected internals -- the same pattern already used by
``tests/test_audit4/b2_process_tab/test_process_tab.py`` -- so tests can reach
production-declared attributes without violating basedpyright's
``reportPrivateUsage`` check (subclass access to a base class's protected members is
permitted; only access from *outside* the class hierarchy is flagged).
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import sys
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QMessageBox, QTableWidget, QWidget

from intellicrack.core.types import IntellicrackError
from intellicrack.ui.panels import async_bridge as async_bridge_module
from intellicrack.ui.panels.frida_instrumentation_tab import (
    InterceptorLifecycleControls,
    MemoryPatchStringControls,
    StalkerCallProbeControls,
    SymbolLookupControls,
    SystemFunctionCallControls,
)
from intellicrack.ui.panels.frida_panel import FridaPanel


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator

    from intellicrack.bridges.frida_bridge import FridaBridge
    from intellicrack.core.subprocess_compat import Popen

try:
    from intellicrack.bridges.frida_bridge import FridaBridge

    _frida_available: bool = True
except ImportError:
    _frida_available = False


_DISPATCH_EXCEPTIONS: tuple[type[BaseException], ...] = (
    IntellicrackError,
    *async_bridge_module.WORKER_DEFAULT_EXCEPTIONS,
    asyncio.CancelledError,
)


def _run_async[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine synchronously for test use.

    Args:
        coro: Awaitable coroutine to execute.

    Returns:
        T: The coroutine's return value, preserving its type.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class _TestFridaPanel(FridaPanel):
    """FridaPanel subclass exposing toolbar internals via public wrappers for gate tests."""

    def set_attach_target_text(self, text: str) -> None:
        """Set the Attach target line edit's text as a user would type it.

        Args:
            text: PID or process-name text to enter.
        """
        self._target_input.setText(text)

    def invoke_on_attach(self) -> None:
        """Invoke the real Attach button handler."""
        self._on_attach()

    def invoke_on_stop_all_scripts(self) -> None:
        """Invoke the real "Stop All Scripts" button handler."""
        self._on_stop_all_scripts()


class _TestInterceptorLifecycleControls(InterceptorLifecycleControls):
    """InterceptorLifecycleControls subclass exposing internals via public wrappers."""

    def set_revert_target_text(self, text: str) -> None:
        """Set the Revert-target line edit's text.

        Args:
            text: Target address/name text to enter.
        """
        self._revert_target_input.setText(text)

    def invoke_on_revert_hook(self) -> None:
        """Invoke the real Revert button handler."""
        self._on_revert_hook()

    def invoke_on_flush_interceptor(self) -> None:
        """Invoke the real Flush button handler."""
        self._on_flush_interceptor()

    def get_status_text(self) -> str:
        """Return the widget's current status label text.

        Returns:
            str: Current status label text.
        """
        return self._status_label.text()


class _TestStalkerCallProbeControls(StalkerCallProbeControls):
    """StalkerCallProbeControls subclass exposing internals via public wrappers."""

    def set_probe_inputs(self, address_hex: str, callback_js: str) -> None:
        """Set the address and callback-JS fields for adding a probe.

        Args:
            address_hex: Hex address text to enter.
            callback_js: JavaScript callback body to enter.
        """
        self._probe_addr_input.setText(address_hex)
        self._probe_callback_input.setText(callback_js)

    def invoke_on_add_call_probe(self) -> None:
        """Invoke the real "Add Probe" button handler."""
        self._on_add_call_probe()

    def invoke_on_remove_call_probe(self) -> None:
        """Invoke the real "Remove Selected" button handler."""
        self._on_remove_call_probe()

    def select_probe_row(self, row: int) -> None:
        """Select a row in the probe table as a user click would.

        Args:
            row: Zero-based row index to select.
        """
        self._probe_table.selectRow(row)

    def probe_table_row_count(self) -> int:
        """Return the number of rows currently in the probe table.

        Returns:
            int: Current probe-table row count.
        """
        return self._probe_table.rowCount()

    def probe_table_id_at(self, row: int) -> str:
        """Return the probe-ID text displayed at a given table row.

        Args:
            row: Zero-based row index to read.

        Returns:
            str: Probe-ID text shown in the table's first column.

        Raises:
            AssertionError: If the requested cell has no item.
        """
        item = self._probe_table.item(row, 0)
        if item is None:
            msg = f"no probe-id item at row {row}"
            raise AssertionError(msg)
        return item.text()


class _TestMemoryPatchStringControls(MemoryPatchStringControls):
    """MemoryPatchStringControls subclass exposing internals via public wrappers."""

    def set_patch_inputs(self, address_hex: str, hex_bytes: str) -> None:
        """Set the patch-address and patch-bytes fields.

        Args:
            address_hex: Hex address text to enter.
            hex_bytes: Space-separated hex byte text to enter.
        """
        self._patch_addr_input.setText(address_hex)
        self._patch_data_input.setText(hex_bytes)

    def invoke_on_patch_code(self) -> None:
        """Invoke the real "Patch Code" button handler."""
        self._on_patch_code()

    def get_patch_status_text(self) -> str:
        """Return the patch-status label text.

        Returns:
            str: Current patch-status label text.
        """
        return self._patch_status_label.text()

    def set_allocate_string_inputs(self, value: str, encoding: str) -> None:
        """Set the string-allocation value and encoding fields.

        Args:
            value: String value to allocate.
            encoding: Encoding combo selection (``utf8``/``ansi``/``utf16``).
        """
        self._alloc_string_input.setText(value)
        self._alloc_encoding_combo.setCurrentText(encoding)

    def invoke_on_allocate_string(self) -> None:
        """Invoke the real "Allocate" button handler."""
        self._on_allocate_string()

    def get_allocate_string_result_text(self) -> str:
        """Return the string-allocation result label text.

        Returns:
            str: Current allocation-result label text.
        """
        return self._alloc_string_result.text()


class _TestSymbolLookupControls(SymbolLookupControls):
    """SymbolLookupControls subclass exposing internals via public wrappers."""

    def set_enumerate_module_text(self, module_name: str) -> None:
        """Set the module-name field for symbol enumeration.

        Args:
            module_name: Module name text to enter.
        """
        self._enum_module_input.setText(module_name)

    def invoke_on_enumerate_symbols(self) -> None:
        """Invoke the real "Enumerate Symbols" button handler."""
        self._on_enumerate_symbols()

    def set_reverse_lookup_address_text(self, address_hex: str) -> None:
        """Set the address field for reverse module lookup.

        Args:
            address_hex: Hex address text to enter.
        """
        self._reverse_addr_input.setText(address_hex)

    def invoke_on_find_module_by_address(self) -> None:
        """Invoke the real "Find Module by Address" button handler."""
        self._on_find_module_by_address()

    def get_reverse_result_text(self) -> str:
        """Return the reverse-lookup result label text.

        Returns:
            str: Current reverse-lookup result label text.
        """
        return self._reverse_result_label.text()

    def set_glob_pattern_text(self, pattern: str) -> None:
        """Set the glob-pattern field for function search.

        Args:
            pattern: Glob pattern text to enter.
        """
        self._glob_pattern_input.setText(pattern)

    def invoke_on_find_functions_matching(self) -> None:
        """Invoke the real "Find Functions Matching" button handler."""
        self._on_find_functions_matching()

    def symbols_table(self) -> QTableWidget:
        """Return the underlying symbols/results table widget.

        Returns:
            QTableWidget: The widget's results table.
        """
        return self._symbols_table


class _TestSystemFunctionCallControls(SystemFunctionCallControls):
    """SystemFunctionCallControls subclass exposing internals via public wrappers."""

    def set_call_inputs(
        self,
        address_hex: str,
        args_text: str,
        return_type: str,
        arg_types_text: str,
        calling_convention: str,
    ) -> None:
        """Set every input field required for a system-function call.

        Args:
            address_hex: Hex function-address text to enter.
            args_text: Comma-separated argument list text.
            return_type: Return-type combo selection.
            arg_types_text: Comma-separated argument-type list text.
            calling_convention: Calling-convention combo selection.
        """
        self._syscall_addr_input.setText(address_hex)
        self._syscall_args_input.setText(args_text)
        self._syscall_ret_type.setCurrentText(return_type)
        self._syscall_arg_types_input.setText(arg_types_text)
        self._syscall_cc.setCurrentText(calling_convention)

    def invoke_on_call_system_function(self) -> None:
        """Invoke the real "Call (capture errno)" button handler."""
        self._on_call_system_function()

    def get_status_text(self) -> str:
        """Return the widget's status label text.

        Returns:
            str: Current status label text.
        """
        return self._status_label.text()

    def get_last_error_text(self) -> str:
        """Return the captured GetLastError label text.

        Returns:
            str: Current GetLastError label text.
        """
        return self._syscall_last_error_label.text()


@pytest.fixture(autouse=True)
def require_frida() -> None:
    """Skip any test in this module when frida-python is not installed."""
    if not _frida_available:
        pytest.skip("frida-python required for bridge-completeness gate tests")


@pytest.fixture(autouse=True)
def block_message_boxes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace QMessageBox.warning with a raising stub to prevent test hangs.

    In a headless test environment, QMessageBox.warning blocks waiting for
    user input. This fixture patches it to raise immediately so a wiring
    regression that pops an unexpected dialog fails fast instead of hanging.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
    """

    def _raise_on_warning(
        parent: QWidget | None,
        title: str,
        text: str,
        *args: object,
        **kwargs: object,
    ) -> None:
        del parent, args, kwargs
        msg = f"QMessageBox.warning shown unexpectedly: [{title}] {text}"
        raise AssertionError(msg)

    monkeypatch.setattr(QMessageBox, "warning", staticmethod(_raise_on_warning))


@pytest.fixture
def synchronous_dispatch(monkeypatch: pytest.MonkeyPatch) -> list[Coroutine[object, object, object]]:
    """Replace ``run_bridge_coroutine_async`` with a synchronous, draining capture.

    Args:
        monkeypatch: Pytest monkeypatch fixture.

    Returns:
        list[Coroutine[object, object, object]]: List that records every
        coroutine the panel/widget tried to dispatch, in dispatch order.
    """
    captured: list[Coroutine[object, object, object]] = []
    drain_loop = asyncio.new_event_loop()

    def fake_dispatch(
        coro: Coroutine[object, object, object],
        on_success: Callable[[object], None] | None = None,
        on_error: Callable[[object], None] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        del parent
        captured.append(coro)
        try:
            result = drain_loop.run_until_complete(coro)
        except _DISPATCH_EXCEPTIONS as exc:
            if on_error is not None:
                on_error(exc)
            return
        if on_success is not None:
            on_success(result)

    monkeypatch.setattr(async_bridge_module, "run_bridge_coroutine_async", fake_dispatch)
    return captured


@pytest.fixture
def attached_bridge() -> Generator[FridaBridge]:
    """Create a FridaBridge attached to the current test process.

    Yields:
        FridaBridge: An initialized and self-attached bridge.
    """
    b = FridaBridge()
    _run_async(b.initialize())
    _run_async(b.attach(os.getpid()))
    yield b
    with contextlib.suppress(Exception):
        _run_async(b.shutdown())


@pytest.mark.usefixtures("qapp")
@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge/GUI integration tests")
class TestFridaPanelAttachDispatchesRealBridge:
    """L3 gates for the Attach toolbar button (G1 fix, PID and name branches)."""

    @staticmethod
    def test_attach_button_numeric_target_calls_bridge_attach(
        synchronous_dispatch: list[Coroutine[object, object, object]],
    ) -> None:
        """Clicking Attach with a numeric PID must invoke the real ``bridge.attach`` coroutine.

        Falsifiable: if ``_on_attach`` (frida_panel.py) stopped calling
        ``self._bridge.attach(pid)`` on the numeric branch -- e.g. reverted
        to always calling ``attach_by_name`` regardless of input shape -- the
        real self-attach would never happen and
        ``bridge.state.process_attached`` would remain ``False``.

        Args:
            synchronous_dispatch: Captures and drains dispatched coroutines.
        """
        panel = _TestFridaPanel()
        bridge = FridaBridge()
        _run_async(bridge.initialize())
        panel.set_bridge(bridge)
        panel.set_attach_target_text(str(os.getpid()))

        panel.invoke_on_attach()

        assert len(synchronous_dispatch) == 1
        assert bridge.state.process_attached is True
        assert bridge.state.target_pid == os.getpid()

        with contextlib.suppress(Exception):
            _run_async(bridge.shutdown())

    @staticmethod
    def test_attach_button_name_target_calls_bridge_attach_by_name(
        synchronous_dispatch: list[Coroutine[object, object, object]],
        notepad_process: Popen[bytes],
    ) -> None:
        """Clicking Attach with a non-numeric target must invoke ``bridge.attach_by_name``.

        Falsifiable: if ``_on_attach``'s ``except ValueError`` branch
        (frida_panel.py) were removed or miswired to call ``attach`` instead
        of ``attach_by_name``, the target would never be resolved by name
        and ``process_attached`` would remain ``False``.

        The target is a dedicated, freshly-spawned ``notepad.exe`` rather
        than the ambient test process (whose name -- ``python.exe``/
        ``pytest.exe`` -- commonly collides with other concurrently-running
        interpreters), so the asserted PID is the real, unambiguous PID of
        the process this test actually spawned -- a real gate that fails if
        ``attach_by_name`` resolves to the wrong process.

        Args:
            synchronous_dispatch: Captures and drains dispatched coroutines.
            notepad_process: Dedicated spawned notepad target.
        """
        panel = _TestFridaPanel()
        bridge = FridaBridge()
        _run_async(bridge.initialize())
        panel.set_bridge(bridge)
        panel.set_attach_target_text("notepad.exe")

        panel.invoke_on_attach()

        assert len(synchronous_dispatch) == 1
        assert bridge.state.process_attached is True
        assert bridge.state.target_pid == notepad_process.pid

        with contextlib.suppress(Exception):
            _run_async(bridge.shutdown())


@pytest.mark.usefixtures("qapp")
@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge/GUI integration tests")
class TestFridaPanelStopAllScripts:
    """L3 gate for the "Stop All Scripts" button (previously NO-CONTROL)."""

    @staticmethod
    def test_stop_all_scripts_button_calls_unload_all_scripts(
        synchronous_dispatch: list[Coroutine[object, object, object]],
        attached_bridge: FridaBridge,
    ) -> None:
        """Clicking "Stop All Scripts" must really unload every tracked script.

        Falsifiable: if ``_on_stop_all_scripts`` (frida_panel.py) stopped
        calling ``self._bridge.unload_all_scripts()``, the two persistent
        scripts loaded below would remain tracked by the bridge after the
        click.

        Args:
            synchronous_dispatch: Captures and drains dispatched coroutines.
            attached_bridge: Bridge fixture self-attached to this process.
        """
        panel = _TestFridaPanel()
        panel.set_bridge(attached_bridge)

        first_id = _run_async(attached_bridge.execute_persistent_script("// panel wiring script one"))
        second_id = _run_async(attached_bridge.execute_persistent_script("// panel wiring script two"))

        panel.invoke_on_stop_all_scripts()

        assert len(synchronous_dispatch) == 1
        unload_result = _run_async(attached_bridge.unload_script(first_id))
        assert unload_result is False, "script one should already be gone (double-unload must report not-found)"
        unload_result_two = _run_async(attached_bridge.unload_script(second_id))
        assert unload_result_two is False, "script two should already be gone (double-unload must report not-found)"


@pytest.mark.usefixtures("qapp")
@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge/GUI integration tests")
class TestInterceptorLifecycleControlsWiring:
    """L3 gates for the Revert/Flush controls (previously NO-CONTROL)."""

    @staticmethod
    def test_flush_button_calls_flush_interceptor(
        synchronous_dispatch: list[Coroutine[object, object, object]],
        attached_bridge: FridaBridge,
    ) -> None:
        """Clicking Flush must invoke the real ``flush_interceptor`` bridge coroutine.

        Falsifiable: if ``_on_flush_interceptor`` (frida_instrumentation_tab.py)
        were rewired to a local no-op instead of
        ``self._bridge.flush_interceptor()``, no coroutine would be captured
        and the status label would never read "Interceptor flushed".

        Args:
            synchronous_dispatch: Captures and drains dispatched coroutines.
            attached_bridge: Bridge fixture self-attached to this process.
        """
        widget = _TestInterceptorLifecycleControls()
        widget.set_bridge(attached_bridge)

        widget.invoke_on_flush_interceptor()

        assert len(synchronous_dispatch) == 1
        assert widget.get_status_text() == "Interceptor flushed"

    @staticmethod
    def test_revert_button_calls_revert_hook_with_typed_target(
        synchronous_dispatch: list[Coroutine[object, object, object]],
        attached_bridge: FridaBridge,
    ) -> None:
        """Clicking Revert must invoke ``revert_hook`` with the exact typed target string.

        Real Frida's ``Interceptor.revert(target)`` is a safe, idempotent
        no-op for a target address with no active interceptor -- it
        succeeds rather than raising. So reverting a never-hooked target
        must report success, and the status label must echo the *exact*
        target string the user typed.

        Falsifiable: if the click handler stopped forwarding the line
        edit's text to ``self._bridge.revert_hook(target)`` -- e.g.
        hardcoding a different string or silently dropping the call -- the
        status label would either omit "0x1" entirely or show a different
        target string than the one typed.

        Args:
            synchronous_dispatch: Captures and drains dispatched coroutines.
            attached_bridge: Bridge fixture self-attached to this process.
        """
        widget = _TestInterceptorLifecycleControls()
        widget.set_bridge(attached_bridge)
        widget.set_revert_target_text("0x1")

        widget.invoke_on_revert_hook()

        assert len(synchronous_dispatch) == 1
        assert widget.get_status_text() == "Reverted 0x1"


@pytest.mark.usefixtures("qapp")
@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge/GUI integration tests")
class TestStalkerCallProbeControlsWiring:
    """L3 gates for the Stalker call-probe add/remove controls (previously NO-CONTROL)."""

    @staticmethod
    def test_add_probe_button_calls_stalker_add_call_probe_and_populates_table(
        synchronous_dispatch: list[Coroutine[object, object, object]],
        attached_bridge: FridaBridge,
    ) -> None:
        """Clicking "Add Probe" must invoke ``stalker_add_call_probe`` and render its real probe ID.

        Falsifiable: if ``_on_add_call_probe`` (frida_instrumentation_tab.py)
        stopped calling the bridge and instead fabricated a row locally, the
        table's Probe-ID cell would not equal a real ID the bridge can later
        resolve through ``stalker_remove_call_probe`` -- a subsequent removal
        by that exact ID would report not-found instead of success.

        Args:
            synchronous_dispatch: Captures and drains dispatched coroutines.
            attached_bridge: Bridge fixture self-attached to this process.
        """
        widget = _TestStalkerCallProbeControls()
        widget.set_bridge(attached_bridge)
        widget.set_probe_inputs(hex(os.getpid()), "send({ type: 'probe_hit' });")

        widget.invoke_on_add_call_probe()

        assert len(synchronous_dispatch) == 1
        assert widget.probe_table_row_count() == 1
        probe_id = widget.probe_table_id_at(0)
        assert probe_id

        removed = _run_async(attached_bridge.stalker_remove_call_probe(probe_id))
        assert removed is True

    @staticmethod
    def test_remove_probe_button_calls_stalker_remove_call_probe(
        synchronous_dispatch: list[Coroutine[object, object, object]],
        attached_bridge: FridaBridge,
    ) -> None:
        """Clicking "Remove Selected" must invoke ``stalker_remove_call_probe`` for real.

        Falsifiable: if ``_on_remove_call_probe`` stopped calling
        ``self._bridge.stalker_remove_call_probe(probe_id)``, the probe added
        in the setup step would still be removable through the bridge after
        the click (this test proves it is not, by observing a second,
        direct bridge-level removal attempt report not-found).

        Args:
            synchronous_dispatch: Captures and drains dispatched coroutines.
            attached_bridge: Bridge fixture self-attached to this process.
        """
        widget = _TestStalkerCallProbeControls()
        widget.set_bridge(attached_bridge)
        widget.set_probe_inputs(hex(os.getpid()), "send({ type: 'probe_hit' });")
        widget.invoke_on_add_call_probe()
        assert widget.probe_table_row_count() == 1
        probe_id = widget.probe_table_id_at(0)
        widget.select_probe_row(0)

        widget.invoke_on_remove_call_probe()

        assert len(synchronous_dispatch) == 2
        assert widget.probe_table_row_count() == 0
        already_removed = _run_async(attached_bridge.stalker_remove_call_probe(probe_id))
        assert already_removed is False


@pytest.mark.usefixtures("qapp")
@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge/GUI integration tests")
class TestMemoryPatchStringControlsWiring:
    """L3 gates for the Patch Code / Allocate String controls (previously NO-CONTROL)."""

    @staticmethod
    def test_patch_button_calls_patch_code_and_writes_real_bytes(
        synchronous_dispatch: list[Coroutine[object, object, object]],
        attached_bridge: FridaBridge,
    ) -> None:
        """Clicking "Patch Code" must invoke ``patch_code`` and really write the typed bytes.

        Falsifiable: if ``_on_patch_code`` stopped forwarding to
        ``self._bridge.patch_code(addr, hex_data)`` -- e.g. only updating a
        local label without touching process memory -- the freshly allocated
        block would not contain the exact ``AA BB CC`` byte sequence when
        read back through the bridge's own real ``read_memory``.

        Args:
            synchronous_dispatch: Captures and drains dispatched coroutines.
            attached_bridge: Bridge fixture self-attached to this process.
        """
        widget = _TestMemoryPatchStringControls()
        widget.set_bridge(attached_bridge)

        target_addr = _run_async(attached_bridge.allocate_memory(16))

        widget.set_patch_inputs(hex(target_addr), "AA BB CC")

        widget.invoke_on_patch_code()

        assert len(synchronous_dispatch) == 1
        assert widget.get_patch_status_text() == f"Patched 0x{target_addr:X}"
        written = _run_async(attached_bridge.read_memory(target_addr, 3))
        assert written == b"\xaa\xbb\xcc"

    @staticmethod
    def test_allocate_string_button_calls_allocate_string_and_produces_readable_string(
        synchronous_dispatch: list[Coroutine[object, object, object]],
        attached_bridge: FridaBridge,
    ) -> None:
        """Clicking "Allocate" must invoke ``allocate_string`` and return a real, readable address.

        Falsifiable: if ``_on_allocate_string`` were rewired away from
        ``self._bridge.allocate_string(value, encoding=encoding)``, the
        result label would not contain a hex address whose target memory
        (read back via the bridge's real ``read_memory``) decodes to the
        exact UTF-8 string the user typed.

        Args:
            synchronous_dispatch: Captures and drains dispatched coroutines.
            attached_bridge: Bridge fixture self-attached to this process.
        """
        widget = _TestMemoryPatchStringControls()
        widget.set_bridge(attached_bridge)
        widget.set_allocate_string_inputs("gate-test-string", "utf8")

        widget.invoke_on_allocate_string()

        assert len(synchronous_dispatch) == 1
        result_text = widget.get_allocate_string_result_text()
        assert result_text.startswith("0x")
        addr = int(result_text, 16)
        raw = _run_async(attached_bridge.read_memory(addr, len(b"gate-test-string") + 1))
        assert raw[:-1] == b"gate-test-string"
        assert raw[-1] == 0


@pytest.mark.usefixtures("qapp")
@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge/GUI integration tests")
class TestSymbolLookupControlsWiring:
    """L3 gates for the module-symbols / reverse-lookup / glob-search controls (previously NO-CONTROL)."""

    @staticmethod
    def test_enumerate_symbols_button_calls_enumerate_symbols_with_real_module(
        synchronous_dispatch: list[Coroutine[object, object, object]],
        attached_bridge: FridaBridge,
    ) -> None:
        """Clicking "Enumerate Symbols" must invoke ``enumerate_symbols`` for a real system module.

        Falsifiable: if ``_on_enumerate_symbols`` stopped calling
        ``self._bridge.enumerate_symbols(module_name)``, the symbols table
        would remain empty instead of being populated with real exported
        names from ``kernel32.dll`` (every Windows process has this module
        loaded, and it always exports hundreds of symbols).

        Args:
            synchronous_dispatch: Captures and drains dispatched coroutines.
            attached_bridge: Bridge fixture self-attached to this process.
        """
        widget = _TestSymbolLookupControls()
        widget.set_bridge(attached_bridge)
        widget.set_enumerate_module_text("kernel32.dll")

        widget.invoke_on_enumerate_symbols()

        assert len(synchronous_dispatch) == 1
        table = widget.symbols_table()
        assert table.rowCount() > 0
        name_item = table.item(0, 0)
        assert name_item is not None
        assert name_item.text()

    @staticmethod
    def test_find_module_by_address_button_resolves_real_module(
        synchronous_dispatch: list[Coroutine[object, object, object]],
        attached_bridge: FridaBridge,
    ) -> None:
        """Clicking "Find Module by Address" must invoke ``find_module_by_address`` for a real base address.

        Falsifiable: if the click handler stopped calling
        ``self._bridge.find_module_by_address(addr)``, the result label
        would not contain "kernel32.dll" when queried with kernel32's own
        real, independently-resolved base address.

        Args:
            synchronous_dispatch: Captures and drains dispatched coroutines.
            attached_bridge: Bridge fixture self-attached to this process.
        """
        kernel32_base = _run_async(attached_bridge.find_base_address("kernel32.dll"))
        widget = _TestSymbolLookupControls()
        widget.set_bridge(attached_bridge)
        widget.set_reverse_lookup_address_text(hex(kernel32_base))

        widget.invoke_on_find_module_by_address()

        assert len(synchronous_dispatch) == 1
        assert "kernel32.dll" in widget.get_reverse_result_text().lower()

    @staticmethod
    def test_find_functions_matching_button_finds_real_export(
        synchronous_dispatch: list[Coroutine[object, object, object]],
        attached_bridge: FridaBridge,
    ) -> None:
        """Clicking "Find Functions Matching" must invoke ``find_functions_matching`` with the typed glob.

        Falsifiable: if the handler stopped calling
        ``self._bridge.find_functions_matching(pattern)``, the symbols table
        would not be populated with a real match for ``*CreateFileW*``,
        which every Windows process resolves to at least one function in
        ``kernel32.dll``.

        Args:
            synchronous_dispatch: Captures and drains dispatched coroutines.
            attached_bridge: Bridge fixture self-attached to this process.
        """
        widget = _TestSymbolLookupControls()
        widget.set_bridge(attached_bridge)
        widget.set_glob_pattern_text("*CreateFileW*")

        widget.invoke_on_find_functions_matching()

        assert len(synchronous_dispatch) == 1
        table = widget.symbols_table()
        assert table.rowCount() >= 1
        matched_names: list[str] = []
        for row in range(table.rowCount()):
            item = table.item(row, 0)
            if item is not None:
                matched_names.append(item.text())
        assert any("CreateFileW" in name for name in matched_names)


@pytest.mark.usefixtures("qapp")
@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge/GUI integration tests")
class TestSystemFunctionCallControlsWiring:
    """L3 gate for the errno/GetLastError call-path control (previously NO-CONTROL)."""

    @staticmethod
    def test_call_button_calls_call_system_function_and_captures_last_error(
        synchronous_dispatch: list[Coroutine[object, object, object]],
        attached_bridge: FridaBridge,
    ) -> None:
        """Clicking "Call (capture errno)" must invoke ``call_system_function`` and surface a real GetLastError.

        Calls ``kernel32.dll!CloseHandle`` with an intentionally invalid
        handle (``0``), which the real Win32 API rejects, setting
        ``GetLastError() == ERROR_INVALID_HANDLE`` (6) -- an
        independently-known Win32 constant, not derived from the
        implementation under test.

        Falsifiable: if ``_on_call_system_function`` stopped calling
        ``self._bridge.call_system_function(...)`` -- e.g. falling back to
        the plain ``call_function`` path which does not capture
        ``GetLastError`` -- the GetLastError label would never be populated
        with the real captured value.

        Args:
            synchronous_dispatch: Captures and drains dispatched coroutines.
            attached_bridge: Bridge fixture self-attached to this process.
        """
        symbols = _run_async(attached_bridge.enumerate_exports("kernel32.dll"))
        close_handle = next(s for s in symbols if s.name == "CloseHandle")

        widget = _TestSystemFunctionCallControls()
        widget.set_bridge(attached_bridge)
        widget.set_call_inputs(
            hex(close_handle.address),
            "0",
            "int",
            "pointer",
            "default",
        )

        widget.invoke_on_call_system_function()

        assert len(synchronous_dispatch) == 1
        assert widget.get_status_text() == "Call succeeded"
        error_invalid_handle = 6
        assert widget.get_last_error_text() == str(error_invalid_handle)
