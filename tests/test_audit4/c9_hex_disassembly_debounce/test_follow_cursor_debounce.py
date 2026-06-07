# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit4 C9 (F-0013): hex disassembly follow-cursor debounce.

The defect: ``DisassemblyMixin._on_cursor_moved_disasm`` previously called
``_on_disassemble`` synchronously on every cursor move. Holding an arrow
key streams hundreds of cursor events per second, each of which became a
bridge ``disassemble`` call - the bridge worker thread saturates and the
GUI freezes.

The fix introduces three production-grade safeguards:

1. **Debounce timer** — each cursor move re-arms a single-shot
   ``QTimer``; only the most recent offset survives the wait window.
2. **In-flight guard** — if a previous bridge call has not returned, no
   new dispatch happens. The completion handler re-flushes the latest
   pending offset so nothing is lost.
3. **Equality check** — if the pending offset matches the offset of the
   last successful dispatch, the dispatch is suppressed (the table is
   already correct).

These tests construct a ``DisassemblyMixin``-backed harness that records
every dispatch attempt, drives the public lifecycle exactly the way the
hex widget does, and asserts that:

- a burst of N cursor moves produces at most one dispatch,
- a duplicate offset never causes a second dispatch,
- a cursor move arriving while a bridge call is in flight is held until
  the call completes and then dispatched once.

The ``TestBridgeCallParameters`` class adds a genuine bridge-signature gate:
it supplies a recording bridge with a real async ``disassemble`` coroutine
and lets ``_on_disassemble`` run without override, asserting the exact offset,
count, architecture, and mode args that reach ``bridge.disassemble()``.
"""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, Any, Final

import pytest
from PyQt6.QtCore import QEventLoop, QTimer
from PyQt6.QtWidgets import QApplication, QCheckBox, QComboBox, QSpinBox, QTableWidget, QWidget

from intellicrack.ui.panels.hex_editor.disassembly import DisassemblyMixin


if TYPE_CHECKING:
    from collections.abc import Generator


_DOC_LEN: Final[int] = 4096
_INITIAL_OFFSET: Final[int] = 0
_DEBOUNCE_MS: Final[int] = 150
_BRIDGE_TIMEOUT_MS: Final[int] = 2000


@pytest.fixture(scope="module")
def qapp() -> Generator[QApplication]:
    """Provide a process-wide ``QApplication`` for Qt widget construction.

    Yields:
        Generator[QApplication]: Qt application instance shared across tests.
    """
    existing = QApplication.instance()
    if existing is not None and isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


class _StubDocument:
    """Minimal stand-in for ``HexDocument`` exposing the calls the mixin makes."""

    def __init__(self, length: int) -> None:
        """Initialise the stub with a fixed reported length.

        Args:
            length: Document length in bytes.
        """
        self._length = length

    def length(self) -> int:
        """Return the stub document's length.

        Returns:
            int: Stored byte length.
        """
        return self._length


class _StubHexWidget:
    """Minimal cursor-state holder mirroring the hex widget contract.

    The mixin reads ``_cursor_offset`` directly via ``getattr``; this stub
    exposes the same attribute name the production widget uses so the
    code path under test exercises the real attribute lookup.
    """

    def __init__(self, offset: int = _INITIAL_OFFSET) -> None:
        """Initialise the stub with a starting cursor offset.

        Args:
            offset: Initial cursor byte offset.
        """
        self._cursor_offset: int = offset

    def set_cursor_offset(self, offset: int) -> None:
        """Update the cursor offset the way the hex widget would.

        Args:
            offset: New cursor byte offset.
        """
        self._cursor_offset = offset


class _DebouncingHarness(DisassemblyMixin, QWidget):
    """Test harness that records every dispatch the mixin attempts.

    Wires real Qt widgets the mixin reads from, but overrides
    :meth:`_on_disassemble` to record offsets and keep the in-flight
    guard armed (so the test can drive completion explicitly).
    """

    def __init__(self) -> None:
        """Initialise the harness with realistic mixin state."""
        super().__init__()
        self._stub_document: _StubDocument = _StubDocument(_DOC_LEN)
        self.document: Any | None = self._stub_document
        self._document: Any | None = self._stub_document
        self._stub_hex_widget: _StubHexWidget = _StubHexWidget()
        self._hex_widget: Any | None = self._stub_hex_widget
        self._disasm_arch_combo: QComboBox | None = QComboBox(self)
        self._disasm_arch_combo.addItems(["Auto Detect", "x86"])
        self._disasm_mode_combo: QComboBox | None = QComboBox(self)
        self._disasm_mode_combo.addItems(["64-bit"])
        self._disasm_count_spin: QSpinBox | None = QSpinBox(self)
        self._disasm_count_spin.setRange(1, 100)
        self._disasm_count_spin.setValue(20)
        self._stub_follow_cursor: QCheckBox = QCheckBox(self)
        self._stub_follow_cursor.setChecked(True)
        self._disasm_follow_cursor: QCheckBox | None = self._stub_follow_cursor
        self._disasm_table: QTableWidget | None = QTableWidget(0, 4, self)
        self._bridge: Any | None = object()
        timer = QTimer(self)
        timer.setSingleShot(True)
        timer.setInterval(_DEBOUNCE_MS)
        timer.timeout.connect(self._on_follow_cursor_debounced)
        self._disasm_follow_timer: QTimer | None = timer
        self._disasm_pending_offset: int | None = None
        self._disasm_last_dispatched_offset: int | None = None
        self._disasm_in_flight: bool = False
        self.dispatched_offsets: list[int] = []

    def _on_disassemble(self) -> None:
        """Record the dispatch and arm the in-flight guard the way production does.

        Production hands the bridge call to ``run_bridge_coroutine_async``
        and unwinds in the success/error handler. The harness short-circuits
        the bridge call and records the cursor offset so tests can assert
        dispatch counts deterministically.
        """
        offset = int(getattr(self._stub_hex_widget, "_cursor_offset", 0))
        self._disasm_in_flight = True
        self._disasm_last_dispatched_offset = offset
        self.dispatched_offsets.append(offset)

    def move_cursor(self, offset: int) -> None:
        """Simulate the hex widget reporting a new cursor position.

        Args:
            offset: New cursor byte offset.
        """
        self._stub_hex_widget.set_cursor_offset(offset)
        self._on_cursor_moved_disasm(offset)

    def fire_debounce_now(self) -> None:
        """Bypass the wall-clock debounce wait and fire the timer slot directly.

        Equivalent to the ``QTimer.timeout`` signal firing on schedule;
        used so tests do not have to ``sleep`` for the configured debounce
        interval.
        """
        if self._disasm_follow_timer is not None:
            self._disasm_follow_timer.stop()
        self._on_follow_cursor_debounced()

    def complete_bridge_call(self) -> None:
        """Drive the success handler exactly as ``run_bridge_coroutine_async`` would.

        Releases the in-flight guard and re-flushes a pending offset if
        one arrived while the bridge call was outstanding.
        """
        self._on_disassemble_success([])

    def in_flight_for_test(self) -> bool:
        """Expose the in-flight guard state for assertions.

        Returns:
            bool: ``True`` while a bridge call is outstanding.
        """
        return self._disasm_in_flight

    def pending_offset_for_test(self) -> int | None:
        """Expose the parked pending offset for assertions.

        Returns:
            int | None: The offset queued for the next dispatch.
        """
        return self._disasm_pending_offset

    def disable_follow_cursor(self) -> None:
        """Programmatically uncheck Follow Cursor between phases of a test."""
        self._stub_follow_cursor.setChecked(False)


class _DisassembleCall:
    """Record of one ``bridge.disassemble`` invocation.

    Attributes:
        offset: Byte offset passed to disassemble.
        count: Instruction count requested.
        arch: Architecture string.
        mode: Mode string.
    """

    offset: int
    count: int
    arch: str
    mode: str

    def __init__(self, offset: int, count: int, arch: str, mode: str) -> None:
        """Initialise the record.

        Args:
            offset: Byte offset passed to disassemble.
            count: Instruction count requested.
            arch: Architecture string.
            mode: Mode string.
        """
        self.offset = offset
        self.count = count
        self.arch = arch
        self.mode = mode


class _RecordingBridge:
    """Recording bridge with a real async disassemble coroutine.

    Does NOT override ``_on_disassemble``; instead the production method runs
    in full and its call to ``bridge.disassemble(offset, count, arch, mode)``
    is intercepted here so the exact argument values can be asserted.
    """

    def __init__(self) -> None:
        """Initialise an empty call record and a threading event for synchronisation."""
        self.calls: list[_DisassembleCall] = []
        self._called: threading.Event = threading.Event()

    async def disassemble(self, offset: int, count: int, arch: str, mode: str) -> list[object]:
        """Record the call arguments and return an empty instruction list.

        Args:
            offset: Byte offset to start disassembly.
            count: Number of instructions to disassemble.
            arch: Target architecture string.
            mode: Target mode string.

        Returns:
            list[object]: Empty list (no real disassembly needed for signature tests).
        """
        self.calls.append(_DisassembleCall(offset=offset, count=count, arch=arch, mode=mode))
        self._called.set()
        return []

    def wait_for_call(self, timeout_sec: float = 3.0) -> bool:
        """Block until at least one ``disassemble`` call has been recorded.

        Args:
            timeout_sec: Maximum time to wait in seconds.

        Returns:
            bool: ``True`` if a call was recorded within the timeout.
        """
        return self._called.wait(timeout=timeout_sec)


class _RealDispatchHarness(DisassemblyMixin, QWidget):
    """Harness that lets ``_on_disassemble`` run without override.

    Wires the same Qt widgets as :class:`_DebouncingHarness` but attaches
    a :class:`_RecordingBridge` as ``_bridge`` so the production code path
    through ``_on_disassemble`` → ``bridge.disassemble(offset, count, arch, mode)``
    is exercised end-to-end and the exact arguments can be asserted.
    """

    def __init__(self, recording_bridge: _RecordingBridge) -> None:
        """Initialise the harness with a recording bridge.

        Args:
            recording_bridge: Bridge whose ``disassemble`` coroutine records args.
        """
        super().__init__()
        self._stub_document: _StubDocument = _StubDocument(_DOC_LEN)
        self.document: Any | None = self._stub_document
        self._document: Any | None = self._stub_document
        self._stub_hex_widget: _StubHexWidget = _StubHexWidget()
        self._hex_widget: Any | None = self._stub_hex_widget
        self._disasm_arch_combo: QComboBox | None = QComboBox(self)
        self._disasm_arch_combo.addItems(["Auto Detect", "x86", "ARM"])
        self._disasm_mode_combo: QComboBox | None = QComboBox(self)
        self._disasm_mode_combo.addItems(["64-bit", "32-bit"])
        self._disasm_count_spin: QSpinBox | None = QSpinBox(self)
        self._disasm_count_spin.setRange(1, 100)
        self._disasm_count_spin.setValue(15)
        self._stub_follow_cursor: QCheckBox = QCheckBox(self)
        self._stub_follow_cursor.setChecked(True)
        self._disasm_follow_cursor: QCheckBox | None = self._stub_follow_cursor
        self._disasm_table: QTableWidget | None = QTableWidget(0, 4, self)
        self._bridge: Any | None = recording_bridge
        self._disasm_follow_timer: QTimer | None = None
        self._disasm_pending_offset: int | None = None
        self._disasm_last_dispatched_offset: int | None = None
        self._disasm_in_flight: bool = False

    def set_cursor(self, offset: int) -> None:
        """Move the stub hex widget cursor to ``offset``.

        Args:
            offset: New cursor byte offset.
        """
        self._stub_hex_widget.set_cursor_offset(offset)


@pytest.mark.usefixtures("qapp")
class TestBurstCollapsesToSingleDispatch:
    """A burst of cursor moves must dispatch at most once after the debounce window."""

    @staticmethod
    def test_n_moves_yield_one_dispatch(qapp: QApplication) -> None:
        """Stream 50 distinct offsets, fire the debounce, expect one dispatch.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        harness = _DebouncingHarness()

        for offset in range(50):
            harness.move_cursor(offset * 4)

        assert harness.dispatched_offsets == [], "no dispatch should occur until the debounce timer fires"

        harness.fire_debounce_now()

        assert harness.dispatched_offsets == [49 * 4], "debounce must collapse the burst to one dispatch at the latest offset"


@pytest.mark.usefixtures("qapp")
class TestEqualityCheckSuppressesDuplicates:
    """A pending offset equal to the last dispatched offset must not re-dispatch."""

    @staticmethod
    def test_same_offset_after_completion_is_suppressed(qapp: QApplication) -> None:
        """Dispatch once, complete, then re-arm the debounce with the same offset.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        harness = _DebouncingHarness()

        harness.move_cursor(0x100)
        harness.fire_debounce_now()
        harness.complete_bridge_call()

        assert harness.dispatched_offsets == [0x100]

        harness.move_cursor(0x100)
        harness.fire_debounce_now()

        assert harness.dispatched_offsets == [0x100], "equality check must suppress dispatch when the pending offset is unchanged"


@pytest.mark.usefixtures("qapp")
class TestInFlightGuardHoldsThenFlushes:
    """Cursor moves arriving during a bridge call must be queued, not dropped."""

    @staticmethod
    def test_pending_offset_dispatches_after_completion(qapp: QApplication) -> None:
        """Dispatch, then move cursor twice while in flight, then complete.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        harness = _DebouncingHarness()

        harness.move_cursor(0x10)
        harness.fire_debounce_now()
        assert harness.dispatched_offsets == [0x10]
        assert harness.in_flight_for_test(), "first dispatch must arm the in-flight guard"

        harness.move_cursor(0x20)
        harness.fire_debounce_now()
        assert harness.dispatched_offsets == [0x10], "in-flight guard must hold dispatch even after the debounce fires"

        harness.move_cursor(0x40)
        harness.fire_debounce_now()
        assert harness.dispatched_offsets == [0x10]

        harness.complete_bridge_call()
        harness.fire_debounce_now()

        assert harness.dispatched_offsets == [0x10, 0x40], "completion must re-flush the most recent pending offset exactly once"

    @staticmethod
    def test_no_pending_offset_means_no_redispatch_on_completion(qapp: QApplication) -> None:
        """Completion with no pending offset must not produce an extra dispatch.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        harness = _DebouncingHarness()

        harness.move_cursor(0x80)
        harness.fire_debounce_now()
        assert harness.dispatched_offsets == [0x80]

        harness.complete_bridge_call()

        assert harness.dispatched_offsets == [0x80], "completion handler must not invent a dispatch when nothing is pending"


@pytest.mark.usefixtures("qapp")
class TestFollowCursorDisabledSuppressesDispatch:
    """Toggling Follow Cursor off must prevent further dispatches."""

    @staticmethod
    def test_unchecked_follow_cursor_swallows_pending(qapp: QApplication) -> None:
        """Move cursor, then uncheck Follow Cursor before the timer fires.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        harness = _DebouncingHarness()

        harness.move_cursor(0x200)
        harness.disable_follow_cursor()
        harness.fire_debounce_now()

        assert harness.dispatched_offsets == [], "no dispatch must occur if Follow Cursor was unchecked between arming and firing"

    @staticmethod
    def test_initial_uncheck_skips_arming(qapp: QApplication) -> None:
        """Uncheck Follow Cursor first, then move cursor; nothing should arm.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        harness = _DebouncingHarness()
        harness.disable_follow_cursor()

        harness.move_cursor(0x300)
        harness.fire_debounce_now()

        assert harness.dispatched_offsets == []
        assert harness.pending_offset_for_test() is None


@pytest.mark.usefixtures("qapp")
class TestBridgeCallParameters:
    """Verify the exact args that reach ``bridge.disassemble`` after debounce fires.

    These tests let ``_on_disassemble`` execute in full (no override) so that
    any change to the bridge call signature — extra parameters, renamed args,
    wrong offset — causes the test to go red.
    """

    @staticmethod
    def _run_loop_until(event: threading.Event, loop: QEventLoop, timeout_ms: int) -> bool:
        """Run ``loop`` until ``event`` is set or ``timeout_ms`` elapses.

        Args:
            event: Threading event set by the bridge recording coroutine.
            loop: Qt event loop to spin while waiting.
            timeout_ms: Maximum wait in milliseconds.

        Returns:
            bool: ``True`` if the event was set before the timeout.
        """
        timer = QTimer()
        timer.setSingleShot(True)
        timer.timeout.connect(loop.quit)
        timer.start(timeout_ms)

        def _check() -> None:
            if event.is_set():
                loop.quit()

        poll = QTimer()
        poll.setInterval(10)
        poll.timeout.connect(_check)
        poll.start()

        loop.exec()
        poll.stop()
        timer.stop()
        return event.is_set()

    @staticmethod
    def test_on_disassemble_passes_cursor_offset_to_bridge(qapp: QApplication) -> None:
        """Calling ``_on_disassemble`` routes the correct cursor offset to bridge.disassemble.

        Uses a real async coroutine on the bridge; does NOT override
        ``_on_disassemble``. The coroutine records its arguments synchronously
        inside the bridge event loop so the assertion is on the real parameters
        the production code passes.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        recording = _RecordingBridge()
        harness = _RealDispatchHarness(recording)

        target_offset = 0x0DEA
        harness.set_cursor(target_offset)

        loop = QEventLoop()
        getattr(harness, "_on_disassemble")()

        called = TestBridgeCallParameters._run_loop_until(getattr(recording, "_called"), loop, _BRIDGE_TIMEOUT_MS)
        assert called, "bridge.disassemble was never invoked; the production call path may be broken"

        assert len(recording.calls) == 1
        call = recording.calls[0]
        assert call.offset == target_offset, f"bridge.disassemble received offset {call.offset:#x}, expected {target_offset:#x}"
        assert call.count == 15, f"bridge.disassemble count={call.count}, expected 15 (from spin box)"
        assert call.arch == "auto", f"bridge.disassemble arch={call.arch!r}, expected 'auto'"
        assert call.mode == "64", f"bridge.disassemble mode={call.mode!r}, expected '64'"

    @staticmethod
    def test_on_disassemble_passes_arch_and_mode_from_combos(qapp: QApplication) -> None:
        """Architecture and mode combos propagate correctly to bridge.disassemble.

        Changes combo selections to x86/32-bit and verifies the bridge receives
        the mapped arch and mode strings, not the raw combo text.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        recording = _RecordingBridge()
        harness = _RealDispatchHarness(recording)

        assert getattr(harness, "_disasm_arch_combo") is not None
        getattr(harness, "_disasm_arch_combo").setCurrentIndex(1)
        assert getattr(harness, "_disasm_mode_combo") is not None
        getattr(harness, "_disasm_mode_combo").setCurrentIndex(1)

        harness.set_cursor(0x0800)

        loop = QEventLoop()
        getattr(harness, "_on_disassemble")()

        called = TestBridgeCallParameters._run_loop_until(getattr(recording, "_called"), loop, _BRIDGE_TIMEOUT_MS)
        assert called, "bridge.disassemble was never invoked"

        assert len(recording.calls) == 1
        call = recording.calls[0]
        assert call.offset == 0x0800
        assert call.arch == "x86", f"expected arch 'x86', got {call.arch!r}"
        assert call.mode == "32", f"expected mode '32', got {call.mode!r}"

    @staticmethod
    def test_on_disassemble_skips_bridge_when_offset_at_end_of_document(qapp: QApplication) -> None:
        """No bridge call is made when the cursor is beyond the document end.

        The production code returns early when ``doc_len - cursor_offset <= 0``;
        this test verifies that guard is exercised and the recording bridge
        sees no call.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        recording = _RecordingBridge()
        harness = _RealDispatchHarness(recording)

        harness.set_cursor(_DOC_LEN)

        getattr(harness, "_on_disassemble")()

        QApplication.processEvents()

        time.sleep(0.05)
        assert len(recording.calls) == 0, "bridge.disassemble must not be called when cursor is at or past document end"
