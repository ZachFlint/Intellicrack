# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit4 C9 (F-0013): hex disassembly follow-cursor debounce.

The defect: ``DisassemblyMixin._on_cursor_moved_disasm`` previously called
``_on_disassemble`` synchronously on every cursor move.  Holding an arrow key
streams hundreds of cursor events per second, each of which became a bridge
``disassemble`` call - the bridge worker thread saturates and the GUI freezes.

The fix introduces three production-grade safeguards:

1. **Debounce timer** -- each cursor move re-arms a single-shot ``QTimer``;
   only the most recent offset survives the wait window.
2. **In-flight guard** -- if a previous bridge call has not returned, no new
   dispatch happens. The completion handler re-flushes the latest pending
   offset so nothing is lost.
3. **Equality check** -- if the pending offset matches the offset of the last
   successful dispatch, the dispatch is suppressed (the table is already
   correct).

These tests construct a ``_RealBridgeHarness`` that lets the production
``_on_disassemble`` execute without any override.  A ``_RecordingBridge``
intercepts ``bridge.disassemble(offset, count, arch, mode)`` calls and
exposes them for assertion, so:

- A burst of N cursor moves produces at most one ``bridge.disassemble`` call.
- A duplicate offset never triggers a second call.
- A cursor move arriving while a bridge call is in flight is held until the
  call completes and then dispatched exactly once.

All assertions target the actual ``bridge.disassemble`` call arguments and
counts, not a custom recording list installed by overriding ``_on_disassemble``.
This ensures that if ``_on_disassemble`` is broken (wrong args, early return,
or silent no-op), the tests go red.
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
_BRIDGE_TIMEOUT_MS: Final[int] = 3000
_BRIDGE_TIMEOUT_SEC: Final[float] = 3.0


@pytest.fixture(scope="module")
def qapp() -> Generator[QApplication]:
    """Provide a process-wide ``QApplication`` for Qt widget construction.

    Yields:
        QApplication: Qt application instance shared across tests.
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

    Every call to ``disassemble`` is appended to ``calls`` and the
    notification event is set, letting tests wait for delivery without
    relying on wall-clock sleeps.

    The coroutine is real async so ``run_bridge_coroutine_logged`` receives
    a genuine awaitable and the ``BridgeCallWorker`` thread executes it on
    the persistent background event loop.  The bridge success callback
    (``_on_disassemble_success``) fires on the Qt main thread after the
    worker emits ``call_finished``.
    """

    def __init__(self) -> None:
        """Initialise an empty call record and a threading event for synchronisation."""
        self.calls: list[_DisassembleCall] = []
        self.called_event: threading.Event = threading.Event()
        self._lock: threading.Lock = threading.Lock()

    async def disassemble(self, offset: int, count: int, arch: str, mode: str) -> list[object]:
        """Record call arguments and return an empty instruction list.

        Args:
            offset: Byte offset to start disassembly.
            count: Number of instructions to disassemble.
            arch: Target architecture string.
            mode: Target mode string.

        Returns:
            list[object]: Empty instruction list.
        """
        with self._lock:
            self.calls.append(_DisassembleCall(offset=offset, count=count, arch=arch, mode=mode))
            self.called_event.set()
        return []

    def reset(self) -> None:
        """Clear recorded calls and reset the notification event."""
        with self._lock:
            self.calls.clear()
            self.called_event.clear()

    def clear_event(self) -> None:
        """Reset the notification event without clearing calls."""
        with self._lock:
            self.called_event.clear()

    def call_count(self) -> int:
        """Return the number of recorded disassemble calls.

        Returns:
            int: Number of recorded calls.
        """
        with self._lock:
            return len(self.calls)

    def wait_for_n_calls(self, n: int, timeout_sec: float = _BRIDGE_TIMEOUT_SEC) -> bool:
        """Block until at least ``n`` ``disassemble`` calls have been recorded.

        Polls using a short loop so the caller is not blocked longer than
        necessary.

        Args:
            n: Minimum number of calls to wait for.
            timeout_sec: Maximum time to wait in seconds.

        Returns:
            bool: ``True`` if at least ``n`` calls were recorded within the timeout.
        """
        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline:
            with self._lock:
                if len(self.calls) >= n:
                    return True
            time.sleep(0.005)
        with self._lock:
            return len(self.calls) >= n


class _RealBridgeHarness(DisassemblyMixin, QWidget):
    """Harness that lets ``_on_disassemble`` execute without override.

    Wires real Qt widgets the mixin reads from and attaches a
    :class:`_RecordingBridge` so the production code path through
    ``_on_disassemble`` -> ``bridge.disassemble(offset, count, arch, mode)``
    is exercised end-to-end.  All debounce, in-flight, and equality-check
    tests assert on ``recording_bridge.calls``, not on a custom recording
    list inside an overridden ``_on_disassemble``.
    """

    def __init__(
        self,
        recording_bridge: _RecordingBridge,
        count: int = 20,
        arch_index: int = 0,
        mode_index: int = 0,
    ) -> None:
        """Initialise the harness with a recording bridge and control settings.

        Args:
            recording_bridge: Bridge whose ``disassemble`` coroutine records args.
            count: Instruction count to configure in the spin box.
            arch_index: Combo index to select for architecture.
            mode_index: Combo index to select for mode.
        """
        super().__init__()
        stub_doc: _StubDocument = _StubDocument(_DOC_LEN)
        self.document: Any | None = stub_doc
        self._document: Any | None = stub_doc
        stub_hw: _StubHexWidget = _StubHexWidget()
        self._hex_widget: Any | None = stub_hw
        self._disasm_arch_combo: QComboBox | None = QComboBox(self)
        self._disasm_arch_combo.addItems(["Auto Detect", "x86", "ARM"])
        self._disasm_arch_combo.setCurrentIndex(arch_index)
        self._disasm_mode_combo: QComboBox | None = QComboBox(self)
        self._disasm_mode_combo.addItems(["64-bit", "32-bit"])
        self._disasm_mode_combo.setCurrentIndex(mode_index)
        self._disasm_count_spin: QSpinBox | None = QSpinBox(self)
        self._disasm_count_spin.setRange(1, 500)
        self._disasm_count_spin.setValue(count)
        follow_cb: QCheckBox = QCheckBox(self)
        follow_cb.setChecked(True)
        self._disasm_follow_cursor: QCheckBox | None = follow_cb
        self._disasm_table: QTableWidget | None = QTableWidget(0, 4, self)
        self._bridge: Any | None = recording_bridge
        timer = QTimer(self)
        timer.setSingleShot(True)
        timer.setInterval(_DEBOUNCE_MS)
        timer.timeout.connect(self._on_follow_cursor_debounced)
        self._disasm_follow_timer: QTimer | None = timer
        self._disasm_pending_offset: int | None = None
        self._disasm_last_dispatched_offset: int | None = None
        self._disasm_in_flight: bool = False
        self._harness_stub_hw: _StubHexWidget = stub_hw
        self._harness_follow_cb: QCheckBox = follow_cb

    def set_cursor(self, offset: int) -> None:
        """Move the stub hex widget cursor to ``offset``.

        Args:
            offset: New cursor byte offset.
        """
        self._harness_stub_hw.set_cursor_offset(offset)

    def move_cursor(self, offset: int) -> None:
        """Simulate the hex widget reporting a new cursor position.

        Args:
            offset: New cursor byte offset.
        """
        self._harness_stub_hw.set_cursor_offset(offset)
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

    def disable_follow_cursor(self) -> None:
        """Programmatically uncheck Follow Cursor between phases of a test."""
        self._harness_follow_cb.setChecked(False)

    def trigger_on_disassemble(self) -> None:
        """Invoke production ``_on_disassemble`` directly without using cursor/debounce path.

        Used by ``TestBridgeCallParameters`` tests that bypass the debounce
        machinery and call the bridge dispatch method directly.
        """
        self._on_disassemble()

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


def _run_qt_until(event: threading.Event, timeout_ms: int) -> bool:
    """Spin the Qt event loop until ``event`` is set or ``timeout_ms`` elapses.

    Args:
        event: Threading event set by the bridge recording coroutine.
        timeout_ms: Maximum wait in milliseconds.

    Returns:
        bool: ``True`` if the event was set before the timeout.
    """
    loop = QEventLoop()
    deadline_timer = QTimer()
    deadline_timer.setSingleShot(True)
    deadline_timer.timeout.connect(loop.quit)
    deadline_timer.start(timeout_ms)

    def _check() -> None:
        if event.is_set():
            loop.quit()

    poll = QTimer()
    poll.setInterval(10)
    poll.timeout.connect(_check)
    poll.start()

    loop.exec()
    poll.stop()
    deadline_timer.stop()
    return event.is_set()


def _run_qt_until_n_calls(recording: _RecordingBridge, n: int, timeout_ms: int) -> bool:
    """Spin the Qt event loop until at least ``n`` bridge calls are recorded or timeout.

    Unlike :func:`_run_qt_until`, this helper re-checks the call count on each
    poll tick so that Qt timers (e.g. the debounce timer re-armed by
    ``_flush_pending_follow_cursor``) get a chance to fire inside the loop.

    Args:
        recording: Recording bridge whose call list is polled.
        n: Minimum number of calls to wait for.
        timeout_ms: Maximum wait in milliseconds.

    Returns:
        bool: ``True`` if at least ``n`` calls were recorded within the timeout.
    """
    loop = QEventLoop()
    deadline_timer = QTimer()
    deadline_timer.setSingleShot(True)
    deadline_timer.timeout.connect(loop.quit)
    deadline_timer.start(timeout_ms)

    def _check() -> None:
        if recording.call_count() >= n:
            loop.quit()

    poll = QTimer()
    poll.setInterval(10)
    poll.timeout.connect(_check)
    poll.start()

    loop.exec()
    poll.stop()
    deadline_timer.stop()
    return recording.call_count() >= n


@pytest.mark.usefixtures("qapp")
class TestBurstCollapsesToSingleDispatch:
    """A burst of cursor moves must dispatch at most once to ``bridge.disassemble`` after the debounce window."""

    @staticmethod
    def test_n_moves_yield_one_bridge_call(qapp: QApplication) -> None:
        """Stream 50 distinct offsets, fire debounce; bridge.disassemble called exactly once.

        The real ``_on_disassemble`` is not overridden.  The assertion is on
        ``recording.calls``, so if ``_on_disassemble`` is deleted or stops
        calling ``bridge.disassemble``, this test goes red.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        recording = _RecordingBridge()
        harness = _RealBridgeHarness(recording)

        for offset in range(50):
            harness.move_cursor(offset * 4)

        assert recording.call_count() == 0, "bridge.disassemble must not be called before the debounce timer fires"

        harness.fire_debounce_now()

        received = _run_qt_until(recording.called_event, _BRIDGE_TIMEOUT_MS)
        assert received, "bridge.disassemble was never called after debounce fire; _on_disassemble may be broken"

        assert recording.call_count() == 1, (
            f"debounce must collapse 50 cursor moves to exactly one bridge call; got {recording.call_count()}"
        )
        assert recording.calls[0].offset == 49 * 4, (
            f"bridge.disassemble must receive the last offset {49 * 4:#x}, got {recording.calls[0].offset:#x}"
        )

    @staticmethod
    def test_no_bridge_call_without_debounce_fire(qapp: QApplication) -> None:
        """50 cursor moves with no debounce fire must produce zero bridge calls.

        Verifies that ``_on_cursor_moved_disasm`` does not call ``_on_disassemble``
        directly but parks the offset in the pending slot.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        recording = _RecordingBridge()
        harness = _RealBridgeHarness(recording)

        for offset in range(50):
            harness.move_cursor(offset * 4)

        QApplication.processEvents()
        assert recording.call_count() == 0, "bridge.disassemble must not be invoked synchronously on cursor move (debounce not fired)"


@pytest.mark.usefixtures("qapp")
class TestEqualityCheckSuppressesDuplicates:
    """A pending offset equal to the last dispatched offset must not re-invoke ``bridge.disassemble``."""

    @staticmethod
    def test_same_offset_after_completion_yields_one_total_bridge_call(qapp: QApplication) -> None:
        """Dispatch once, wait for completion, then re-arm debounce with the same offset.

        The equality check must suppress the second dispatch; ``bridge.disassemble``
        must be called exactly once total.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        recording = _RecordingBridge()
        harness = _RealBridgeHarness(recording)

        harness.move_cursor(0x100)
        harness.fire_debounce_now()

        received = _run_qt_until(recording.called_event, _BRIDGE_TIMEOUT_MS)
        assert received, "first bridge.disassemble call never arrived"
        assert recording.call_count() == 1
        assert recording.calls[0].offset == 0x100

        recording.reset()

        harness.move_cursor(0x100)
        harness.fire_debounce_now()

        QApplication.processEvents()
        time.sleep(0.05)

        assert recording.call_count() == 0, (
            "equality check must suppress bridge.disassemble when pending offset equals last dispatched offset; "
            f"got {recording.call_count()} extra call(s)"
        )


@pytest.mark.usefixtures("qapp")
class TestInFlightGuardHoldsThenFlushes:
    """Cursor moves arriving during a bridge call must be queued and dispatched once on completion."""

    @staticmethod
    def test_pending_offset_dispatches_after_completion(qapp: QApplication) -> None:
        """Dispatch at 0x10, queue 0x20 and 0x40 before the first call completes, expect calls at 0x10 then 0x40.

        The real ``_on_disassemble`` sets ``_disasm_in_flight = True`` synchronously
        before launching the background worker.  The cursor moves at 0x20 and 0x40 are
        queued by calling ``_on_follow_cursor_debounced`` while ``_disasm_in_flight``
        is still ``True`` (the Qt event loop has not yet delivered ``call_finished``
        from the worker).  Only after the Qt event loop runs and ``_on_disassemble_success``
        fires does ``_flush_pending_follow_cursor`` dispatch the second call.

        Asserts exactly 2 total bridge calls at offsets 0x10 and 0x40 -- the in-flight
        guard suppressed 0x20 in favour of the later 0x40.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        recording = _RecordingBridge()
        harness = _RealBridgeHarness(recording)

        harness.move_cursor(0x10)
        harness.fire_debounce_now()

        assert harness.in_flight_for_test(), (
            "in-flight guard must be set synchronously by _on_disassemble before the Qt event loop delivers call_finished"
        )

        harness.move_cursor(0x20)
        harness.fire_debounce_now()
        assert harness.in_flight_for_test(), "in-flight guard must still be set (Qt loop not yet spun)"

        harness.move_cursor(0x40)
        harness.fire_debounce_now()

        total_timeout_ms = _BRIDGE_TIMEOUT_MS + _DEBOUNCE_MS + 500
        reached_two = _run_qt_until_n_calls(recording, 2, total_timeout_ms)

        assert reached_two, (
            "after first bridge call completes and debounce timer re-fires, _on_disassemble_success must flush "
            f"pending offset and trigger a second bridge call; got {recording.call_count()} total call(s)"
        )
        assert recording.calls[0].offset == 0x10, f"first call offset wrong: {recording.calls[0].offset:#x}"
        assert recording.calls[1].offset == 0x40, (
            f"second call must be for the most recent pending offset 0x40, got {recording.calls[1].offset:#x}"
        )

    @staticmethod
    def test_no_pending_offset_means_no_redispatch_on_completion(qapp: QApplication) -> None:
        """Completion with no pending offset must not produce an extra bridge call.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        recording = _RecordingBridge()
        harness = _RealBridgeHarness(recording)

        harness.move_cursor(0x80)
        harness.fire_debounce_now()

        received = _run_qt_until(recording.called_event, _BRIDGE_TIMEOUT_MS)
        assert received, "first bridge.disassemble call never arrived"
        assert recording.call_count() == 1

        recording.clear_event()
        time.sleep(0.15)
        QApplication.processEvents()

        assert harness.pending_offset_for_test() is None, "no second offset was queued; pending must remain None"
        assert recording.call_count() == 1, (
            f"completion handler must not invent a bridge call when nothing is pending; got {recording.call_count()}"
        )


@pytest.mark.usefixtures("qapp")
class TestFollowCursorDisabledSuppressesDispatch:
    """Toggling Follow Cursor off must prevent bridge.disassemble from being called."""

    @staticmethod
    def test_unchecked_follow_cursor_swallows_pending(qapp: QApplication) -> None:
        """Move cursor, uncheck Follow Cursor, then fire debounce: zero bridge calls.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        recording = _RecordingBridge()
        harness = _RealBridgeHarness(recording)

        harness.move_cursor(0x200)
        harness.disable_follow_cursor()
        harness.fire_debounce_now()

        QApplication.processEvents()
        time.sleep(0.05)

        assert recording.call_count() == 0, (
            "bridge.disassemble must not be called when Follow Cursor was unchecked between arming and firing debounce; "
            f"got {recording.call_count()} call(s)"
        )

    @staticmethod
    def test_initial_uncheck_skips_arming(qapp: QApplication) -> None:
        """Uncheck Follow Cursor first, then move cursor; nothing should arm the timer.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        recording = _RecordingBridge()
        harness = _RealBridgeHarness(recording)
        harness.disable_follow_cursor()

        harness.move_cursor(0x300)
        harness.fire_debounce_now()

        QApplication.processEvents()
        time.sleep(0.05)

        assert recording.call_count() == 0, "bridge.disassemble must not be called when Follow Cursor was never enabled"
        assert harness.pending_offset_for_test() is None, "pending offset must not be set when Follow Cursor is unchecked"


@pytest.mark.usefixtures("qapp")
class TestBridgeCallParameters:
    """Verify the exact args that reach ``bridge.disassemble`` when ``_on_disassemble`` runs."""

    @staticmethod
    def test_on_disassemble_passes_cursor_offset_to_bridge(qapp: QApplication) -> None:
        """Calling ``_on_disassemble`` routes the correct cursor offset to bridge.disassemble.

        Uses a real async coroutine on the bridge; does NOT override
        ``_on_disassemble``. The coroutine records its arguments so the
        assertion is on the real parameters the production code passes.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        recording = _RecordingBridge()
        harness = _RealBridgeHarness(recording, count=20)

        target_offset = 0x0DEA
        harness.set_cursor(target_offset)

        harness.trigger_on_disassemble()

        received = _run_qt_until(recording.called_event, _BRIDGE_TIMEOUT_MS)
        assert received, "bridge.disassemble was never invoked; the production call path may be broken"

        assert recording.call_count() == 1
        call = recording.calls[0]
        assert call.offset == target_offset, f"bridge.disassemble received offset {call.offset:#x}, expected {target_offset:#x}"
        assert call.count == 20, f"bridge.disassemble count={call.count}, expected 20 (from spin box)"
        assert call.arch == "auto", f"bridge.disassemble arch={call.arch!r}, expected 'auto' (Auto Detect -> auto)"
        assert call.mode == "64", f"bridge.disassemble mode={call.mode!r}, expected '64' (64-bit -> 64)"

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
        harness = _RealBridgeHarness(recording, count=15, arch_index=1, mode_index=1)

        harness.set_cursor(0x0800)

        harness.trigger_on_disassemble()

        received = _run_qt_until(recording.called_event, _BRIDGE_TIMEOUT_MS)
        assert received, "bridge.disassemble was never invoked"

        assert recording.call_count() == 1
        call = recording.calls[0]
        assert call.offset == 0x0800, f"expected offset 0x0800, got {call.offset:#x}"
        assert call.count == 15, f"expected count 15, got {call.count}"
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
        harness = _RealBridgeHarness(recording)

        harness.set_cursor(_DOC_LEN)

        harness.trigger_on_disassemble()

        QApplication.processEvents()
        time.sleep(0.05)
        assert recording.call_count() == 0, "bridge.disassemble must not be called when cursor is at or past document end"

    @staticmethod
    def test_debounce_burst_yields_one_bridge_call_with_correct_offset(qapp: QApplication) -> None:
        """A debounce burst through the full path delivers the last offset to bridge.disassemble.

        This is the critical end-to-end gate for finding 04-F3: it exercises
        ``_on_cursor_moved_disasm`` -> debounce timer -> ``_on_follow_cursor_debounced``
        -> ``_on_disassemble`` -> ``bridge.disassemble`` without any override,
        and asserts the exact offset value at the bridge level.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        recording = _RecordingBridge()
        harness = _RealBridgeHarness(recording, count=10)

        burst_offsets = [0x100 + i * 8 for i in range(30)]
        for offset in burst_offsets:
            harness.move_cursor(offset)

        assert recording.call_count() == 0, "bridge must not be called mid-burst before debounce fires"

        harness.fire_debounce_now()

        received = _run_qt_until(recording.called_event, _BRIDGE_TIMEOUT_MS)
        assert received, "bridge.disassemble never received any call after debounce fire; production _on_disassemble may be broken"

        expected_offset = burst_offsets[-1]
        assert recording.call_count() == 1, f"burst must collapse to exactly one bridge call, got {recording.call_count()}"
        assert recording.calls[0].offset == expected_offset, (
            f"bridge must receive the last burst offset {expected_offset:#x}, got {recording.calls[0].offset:#x}"
        )
        assert recording.calls[0].count == 10, f"count must match spin box value 10, got {recording.calls[0].count}"
