# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""GUI-audit regression gates for :mod:`intellicrack.ui.panels.x64dbg_panel`.

Each test encodes one finding from the debugger-panel GUI audit and fails
against the pre-fix code:

* H2 - ``_on_debug_event`` ran on the bridge event thread and used
  ``QTimer.singleShot`` (which needs a Qt event loop on the calling thread) to
  schedule an off-thread widget refresh. The fixed panel marshals the event
  through a ``pyqtSignal`` connected to a GUI-thread slot, so the refresh runs
  on the thread that owns the widgets.
* M7 - ``_apply_registers`` always rendered the 64-bit register-name set, so a
  32-bit target showed bogus ``r8``..``r15`` rows and mislabelled ``eax`` as
  ``rax``. The fixed panel selects the register set from ``_is_64bit``.
* LOW stale-view - ``_apply_registers`` / ``_apply_disassembly`` early-returned
  on an empty result, leaving stale content on screen. The fixed panel clears
  the view.
* LOW embed-poll - the panel could not cancel the outstanding embed poll loop,
  so its callback could fire against a torn-down ``embed_host``. The fixed
  panel owns the poll timer, guards the callback, and cancels on teardown.
"""

from __future__ import annotations

import os
import threading
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication, QWidget

from intellicrack.bridges.base import DisassemblyLine
from intellicrack.core.types import RegisterState
from intellicrack.ui.panels import x64dbg_panel
from intellicrack.ui.panels.x64dbg_panel import X64DbgPanel


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

_32BIT_REG_NAMES: frozenset[str] = frozenset({"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags"})
_64BIT_ONLY_NAMES: frozenset[str] = frozenset({"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "rflags"})


def _register_state(**overrides: int) -> RegisterState:
    """Build a real :class:`RegisterState` with all fields populated.

    Args:
        **overrides: Register-name to value overrides applied on top of zero.

    Returns:
        RegisterState: A fully-initialised register state instance.
    """
    fields: dict[str, int] = {
        "rax": 0,
        "rbx": 0,
        "rcx": 0,
        "rdx": 0,
        "rsi": 0,
        "rdi": 0,
        "rbp": 0,
        "rsp": 0,
        "rip": 0,
        "r8": 0,
        "r9": 0,
        "r10": 0,
        "r11": 0,
        "r12": 0,
        "r13": 0,
        "r14": 0,
        "r15": 0,
        "rflags": 0,
        "cs": 0,
        "ds": 0,
        "es": 0,
        "fs": 0,
        "gs": 0,
        "ss": 0,
    } | overrides
    return RegisterState(**fields)


class _X64DbgProbe(X64DbgPanel):
    """Typed accessor subclass exposing protected render and embed members.

    Protected members are accessible from a subclass, keeping the tests fully
    type-correct while still driving the real production panel code.
    """

    def apply_registers(self, regs: RegisterState | None) -> None:
        """Render register state through the real apply path.

        Args:
            regs: Register state to render, or None to exercise the clear path.
        """
        self._apply_registers(regs)

    def set_arch_64bit(self, *, is_64bit: bool) -> None:
        """Set the panel's architecture flag.

        Args:
            is_64bit: True to render the 64-bit register set, False for 32-bit.
        """
        self._is_64bit = is_64bit

    def register_names(self) -> list[str]:
        """Return the register-name column of the register table.

        Returns:
            list[str]: The name-column text of every register row.
        """
        names: list[str] = []
        for row in range(self._reg_table.rowCount()):
            item = self._reg_table.item(row, 0)
            if item is not None:
                names.append(item.text())
        return names

    def register_value(self, name: str) -> str | None:
        """Return the value-column text for a named register row.

        Args:
            name: The register display name to look up.

        Returns:
            str | None: The value cell text, or None when absent.
        """
        for row in range(self._reg_table.rowCount()):
            name_item = self._reg_table.item(row, 0)
            value_item = self._reg_table.item(row, 1)
            if name_item is not None and value_item is not None and name_item.text() == name:
                return value_item.text()
        return None

    def register_row_count(self) -> int:
        """Return the number of register rows currently rendered.

        Returns:
            int: The register table row count.
        """
        return self._reg_table.rowCount()

    def apply_disassembly(self, lines: list[DisassemblyLine]) -> None:
        """Render disassembly lines through the real apply path.

        Args:
            lines: Disassembly lines to render (may be empty to clear).
        """
        self._apply_disassembly(lines)

    def seed_disassembly(self, text: str) -> None:
        """Seed the disassembly view with stale text.

        Args:
            text: Text to place in the disassembly view.
        """
        self._disasm_view.setPlainText(text)

    def disassembly_text(self) -> str:
        """Return the current disassembly view text.

        Returns:
            str: The plain text of the disassembly view.
        """
        return self._disasm_view.toPlainText()

    def emit_debug_event(self, event_type: str) -> None:
        """Invoke the bridge-thread debug-event handler.

        Args:
            event_type: The debug event type to deliver.
        """
        self._on_debug_event(event_type, {})

    def connect_debug_spy(self, slot: Callable[[str], None]) -> None:
        """Connect a spy slot to the debug-event marshalling signal.

        Args:
            slot: Callable invoked with the event type when the signal fires.
        """
        self._debug_event_received.connect(slot)

    def install_running_embed_timer(self) -> QTimer:
        """Install and start a panel-owned embed poll timer.

        Returns:
            QTimer: The running timer now owned by the panel.
        """
        timer = QTimer(self)
        timer.setInterval(500)
        timer.start()
        self._embed_timer = timer
        self._embed_cancelled = False
        return timer

    def embed_timer(self) -> QTimer | None:
        """Return the panel's embed poll timer, if any.

        Returns:
            QTimer | None: The current embed timer or None.
        """
        return self._embed_timer

    def embed_cancelled(self) -> bool:
        """Return the embed cancellation flag.

        Returns:
            bool: True when the embed poll loop has been cancelled.
        """
        return self._embed_cancelled

    def set_embed_cancelled(self, *, cancelled: bool) -> None:
        """Set the embed cancellation flag.

        Args:
            cancelled: New value for the cancellation flag.
        """
        self._embed_cancelled = cancelled

    def poll_embed_once(self, pid: int) -> None:
        """Run a single embed poll tick.

        Args:
            pid: Process ID passed to the poll tick.
        """
        self._poll_embed_tick(pid)

    def embed_window_ready(self, container: QWidget, pid: int) -> None:
        """Invoke the embed-completion handler.

        Args:
            container: The container widget produced by embedding.
            pid: Process ID associated with the embedded window.
        """
        self._embed_window_ready(container, pid)

    def embedded(self) -> QWidget | None:
        """Return the currently installed embedded container.

        Returns:
            QWidget | None: The embedded container, or None.
        """
        return self.embedded_container

    def run_cleanup(self) -> None:
        """Run the panel teardown hook."""
        self._cleanup()


@pytest.fixture
def probe(qapp: QApplication) -> Iterator[_X64DbgProbe]:
    """Create an X64DbgPanel probe for GUI-audit tests.

    Args:
        qapp: Session QApplication fixture ensuring Qt is initialised.

    Yields:
        _X64DbgProbe: A freshly constructed panel probe.
    """
    del qapp
    widget = _X64DbgProbe()
    yield widget
    widget.deleteLater()


def test_h2_debug_event_emits_signal_without_singleshot(probe: _X64DbgProbe, monkeypatch: pytest.MonkeyPatch) -> None:
    """H2: ``_on_debug_event`` marshals via signal, never ``QTimer.singleShot``.

    Pre-fix the handler called ``QTimer.singleShot`` from the bridge event
    thread; post-fix it emits ``_debug_event_received``. This gate fails if the
    signal is not emitted or if ``QTimer.singleShot`` is used again.

    Args:
        probe: The X64DbgPanel probe under test.
        monkeypatch: Pytest monkeypatch fixture.
    """
    received: list[str] = []
    probe.connect_debug_spy(received.append)

    singleshot_calls: list[tuple[object, ...]] = []

    def _record_singleshot(*args: object, **kwargs: object) -> None:
        del kwargs
        singleshot_calls.append(args)

    monkeypatch.setattr(x64dbg_panel.QTimer, "singleShot", _record_singleshot)

    probe.emit_debug_event("breakpoint")

    assert received == ["breakpoint"], "debug event was not marshalled through the signal"
    assert not singleshot_calls, "debug event must not schedule work via QTimer.singleShot"


def test_h2_ignored_event_types_do_not_emit(probe: _X64DbgProbe) -> None:
    """H2: only refresh-worthy debug events are marshalled.

    Args:
        probe: The X64DbgPanel probe under test.
    """
    received: list[str] = []
    probe.connect_debug_spy(received.append)

    probe.emit_debug_event("log")

    assert not received, "non-refresh event types must not trigger a refresh signal"


def test_h2_refresh_runs_on_gui_thread_when_event_from_worker(probe: _X64DbgProbe, qapp: QApplication) -> None:
    """H2: an event raised off-thread refreshes on the GUI thread.

    The debug event is raised from a non-GUI worker thread. The connected slot
    must run on the thread that owns the QApplication (the GUI thread), proving
    the queued-signal marshalling works. Pre-fix, ``QTimer.singleShot`` from a
    worker thread with no event loop never fired, so no refresh occurred.

    Args:
        probe: The X64DbgPanel probe under test.
        qapp: Session QApplication fixture.
    """
    gui_thread_id = threading.get_ident()
    refresh_thread: dict[str, int] = {}

    def _record_thread(_event_type: str) -> None:
        refresh_thread["id"] = threading.get_ident()

    probe.connect_debug_spy(_record_thread)

    def _worker() -> None:
        probe.emit_debug_event("step")

    worker = threading.Thread(target=_worker)
    worker.start()
    worker.join()

    for _ in range(200):
        qapp.processEvents()
        if "id" in refresh_thread:
            break

    assert refresh_thread.get("id") == gui_thread_id, "refresh slot did not run on the GUI thread"


def test_m7_32bit_registers_use_32bit_names(probe: _X64DbgProbe) -> None:
    """M7: a 32-bit target renders 32-bit register names and no r8..r15.

    Pre-fix the panel always used the 64-bit register list, so 32-bit targets
    showed bogus ``r8``..``r15`` rows and labelled the accumulator ``rax``.

    Args:
        probe: The X64DbgPanel probe under test.
    """
    probe.set_arch_64bit(is_64bit=False)
    regs = _register_state(rax=0x11111111, rbx=0x22222222, rip=0xDEADBEEF, rflags=0x00000246)
    probe.apply_registers(regs)

    names = set(probe.register_names())

    assert names >= _32BIT_REG_NAMES, f"missing 32-bit register names: {_32BIT_REG_NAMES - names}"
    assert not (_64BIT_ONLY_NAMES & names), f"32-bit view must not show 64-bit-only registers: {_64BIT_ONLY_NAMES & names}"
    assert "rax" not in names, "32-bit accumulator must be labelled eax, not rax"


def test_m7_32bit_values_read_from_normalised_state(probe: _X64DbgProbe) -> None:
    """M7: 32-bit rows read real values and render 8 hex digits.

    Args:
        probe: The X64DbgPanel probe under test.
    """
    probe.set_arch_64bit(is_64bit=False)
    regs = _register_state(rax=0x11111111, rip=0xDEADBEEF)
    probe.apply_registers(regs)

    assert probe.register_value("eax") == "0x11111111", "eax must render the normalised accumulator value"
    assert probe.register_value("eip") == "0xDEADBEEF", "eip must render the normalised instruction pointer"


def test_m7_64bit_registers_unchanged(probe: _X64DbgProbe) -> None:
    """M7: the 64-bit path still renders the full 64-bit register set.

    Args:
        probe: The X64DbgPanel probe under test.
    """
    probe.set_arch_64bit(is_64bit=True)
    regs = _register_state(rax=0xCAFEF00DDEADBEEF, r15=0x1234567890ABCDEF)
    probe.apply_registers(regs)

    names = set(probe.register_names())

    assert {"rax", "rip", "r8", "r15", "rflags"} <= names, "64-bit view must render the full register set"
    assert "eax" not in names, "64-bit view must not use 32-bit register names"
    assert probe.register_value("rax") == "0xCAFEF00DDEADBEEF", "64-bit accumulator must render 16 hex digits"


def test_stale_view_registers_cleared_on_empty(probe: _X64DbgProbe) -> None:
    """LOW stale-view: an empty register result clears the register table.

    Pre-fix ``_apply_registers`` early-returned on None, leaving stale rows.

    Args:
        probe: The X64DbgPanel probe under test.
    """
    probe.set_arch_64bit(is_64bit=True)
    probe.apply_registers(_register_state(rax=0x1000))
    assert probe.register_row_count() > 0, "precondition: register rows should be populated"

    probe.apply_registers(None)

    assert probe.register_row_count() == 0, "stale register rows must be cleared on an empty result"


def test_stale_view_disassembly_cleared_on_empty(probe: _X64DbgProbe) -> None:
    """LOW stale-view: an empty disassembly result clears the view.

    Pre-fix ``_apply_disassembly`` early-returned on an empty result, leaving
    stale disassembly text (for example after an invalid instruction pointer).

    Args:
        probe: The X64DbgPanel probe under test.
    """
    probe.set_arch_64bit(is_64bit=True)
    real_line = DisassemblyLine(address=0x401000, bytes_str="90", mnemonic="nop", operands="", comment=None)
    probe.apply_disassembly([real_line])
    assert probe.disassembly_text(), "precondition: disassembly view should be populated"

    probe.apply_disassembly([])

    assert not probe.disassembly_text(), "stale disassembly must be cleared on an empty result"


def test_embed_cleanup_cancels_and_stops_poll_timer(probe: _X64DbgProbe) -> None:
    """LOW embed-poll: teardown cancels and stops the outstanding poll timer.

    Pre-fix ``_cleanup`` never touched the embed poll loop, so its callback
    could fire against a torn-down ``embed_host``.

    Args:
        probe: The X64DbgPanel probe under test.
    """
    timer = probe.install_running_embed_timer()
    assert timer.isActive(), "precondition: embed timer should be running"

    probe.run_cleanup()

    assert probe.embed_cancelled() is True, "cleanup must set the embed cancellation flag"
    assert probe.embed_timer() is None, "cleanup must stop and clear the embed poll timer"
    assert not timer.isActive(), "cleanup must stop the underlying QTimer"


def test_embed_poll_tick_aborts_when_cancelled(probe: _X64DbgProbe) -> None:
    """LOW embed-poll: a cancelled poll tick stops without embedding.

    Args:
        probe: The X64DbgPanel probe under test.
    """
    probe.install_running_embed_timer()
    probe.set_embed_cancelled(cancelled=True)

    probe.poll_embed_once(0xFFFFFFF)

    assert probe.embed_timer() is None, "a cancelled poll tick must stop the timer"
    assert probe.embedded() is None, "a cancelled poll tick must not embed a window"


def test_embed_window_ready_guarded_after_cancel(probe: _X64DbgProbe) -> None:
    """LOW embed-poll: the embed callback no-ops once cancelled.

    Pre-fix the embed callback had no cancellation guard and would install the
    container even after the panel began teardown.

    Args:
        probe: The X64DbgPanel probe under test.
    """
    probe.set_embed_cancelled(cancelled=True)
    container = QWidget()

    probe.embed_window_ready(container, 4321)

    assert probe.embedded() is None, "cancelled embed callback must not install the container"
