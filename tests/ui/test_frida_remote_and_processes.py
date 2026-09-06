# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gates for four Frida panel/bridge remote-device and process defects.

* D22 -- Selecting an already-*enumerated* remote device (for example the
  Local Socket provider Frida always reports, id ``"socket"``) routed through
  ``FridaPanel._resolve_device_selection`` -> ``FridaBridge.connect_device``
  -> ``FridaBridge._resolve_frida_device`` as device type ``"remote"`` with
  the enumerated id treated as a *hostname*, so
  ``DeviceManager.add_remote_device("socket")`` tried to DNS-resolve the
  literal string ``"socket"`` instead of looking the already-known device up
  by identity. The fix routes any combo entry carrying an enumerated ``id``
  through a new ``"enumerated"`` device type that resolves via
  ``frida.get_device(id)``, and adds a genuine "Add Remote Device" dialog
  (``FridaPanel._on_add_remote_device``) as the only path that still calls
  ``connect_device("remote", host_port)`` to add a *brand-new* endpoint.

* D23 -- A Processes-refresh failure against a remote device with no running
  ``frida-server`` (``frida.ServerNotRunningError`` / ``frida.TransportError``)
  propagated out of ``FridaBridge.enumerate_processes`` uncaught, escaping the
  background ``BridgeCallWorker`` ``QThread`` and reaching the application's
  ``sys.excepthook`` (installed as ``intellicrack.ui.app._unhandled_exception_hook``)
  instead of the panel's own error handling. The fix wraps the Frida call in
  ``enumerate_processes`` and re-raises a ``ToolError``, which the existing
  ``BridgeCallWorker`` exception tuple already know how to route to
  ``on_error`` -- ``FridaPanel._on_refresh_processes_error`` -- without ever
  reaching the worker thread's own uncaught-exception path.

* D20 -- The process table's Name column was effectively unreadable: even
  though ``ResizeToContents``/``Stretch`` were already assigned, nothing
  bounded the PID column, so it could absorb most of the table's width and
  leave Name a sliver. The fix gives PID a small fixed/interactive width and
  keeps Name on ``Stretch``, so Name always dominates.

* D21 -- After a persistent script load, ``run_btn`` was disabled with no
  explanation and Stop was buried inside a "Scripts" dropdown menu rather
  than being a directly visible toolbar control. The fix sets an explanatory
  tooltip on the disabled Run button and promotes Stop to its own always-
  visible toolbar ``QPushButton``.

Every test drives the real ``FridaPanel`` widget and (where a defect is
bridge-shaped) a real ``FridaBridge`` against the local machine's real Frida
runtime -- the local device's process list, and the real Local Socket /
loopback-TCP remote device objects Frida itself resolves. Nothing here fakes
Frida device or process results; the only substitution is swapping the
*QThread scheduling* of ``run_bridge_coroutine_async`` for a synchronous,
same-thread drain in the D22 tests (an established pattern in this suite,
see ``synchronous_dispatch`` below) so routing assertions are deterministic.
D23 deliberately keeps the real background ``QThread`` dispatch, because that
is exactly the escape path the defect describes.
"""

from __future__ import annotations

import asyncio
import sys
import time
from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtWidgets import QInputDialog, QPushButton

from intellicrack.core.types import FridaProcessEntry, IntellicrackError
from intellicrack.ui.panels import async_bridge as async_bridge_module
from intellicrack.ui.panels.frida_panel import (
    _PROCESS_COL_NAME,
    _PROCESS_COL_PID,
    _PROCESS_PID_COLUMN_WIDTH,
    _RUN_SCRIPT_BLOCKED_TOOLTIP,
    _RUN_SCRIPT_IDLE_TOOLTIP,
    FridaPanel,
)


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from PyQt6.QtWidgets import QApplication

try:
    from intellicrack.bridges.frida_bridge import FridaBridge

    _frida_available: bool = True
except ImportError:
    _frida_available = False


pytestmark = pytest.mark.usefixtures("qapp")

_DISPATCH_EXCEPTIONS: tuple[type[BaseException], ...] = (
    IntellicrackError,
    *async_bridge_module.WORKER_DEFAULT_EXCEPTIONS,
    asyncio.CancelledError,
)

_ENUMERATED_SOCKET_USER_DATA: Final[dict[str, object]] = {
    "id": "socket",
    "type": "remote",
    "name": "Local Socket",
}
_UNREACHABLE_REMOTE_HOST: Final[str] = "127.0.0.1:59991"
_ADD_REMOTE_HOST: Final[str] = "127.0.0.1:59992"
_SETTLE_TIMEOUT_SECONDS: Final[float] = 15.0
_PUMP_SLICE_SECONDS: Final[float] = 0.01


def _run_async[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine synchronously on a dedicated event loop.

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


def _fixed_get_text(value: str) -> Callable[..., tuple[str, bool]]:
    """Build a ``QInputDialog.getText`` replacement returning a fixed accepted value.

    Args:
        value: The text the stand-in dialog reports the user entered.

    Returns:
        Callable[..., tuple[str, bool]]: A drop-in that ignores its arguments
        and returns ``(value, True)``.
    """

    def _impl(*args: object, **kwargs: object) -> tuple[str, bool]:
        del args, kwargs
        return (value, True)

    return _impl


@pytest.fixture
def require_frida() -> None:
    """Skip the current test when frida-python is not installed."""
    if not _frida_available:
        pytest.skip("frida-python required for this test")


@pytest.fixture
def synchronous_dispatch(monkeypatch: pytest.MonkeyPatch) -> list[Coroutine[object, object, object]]:
    """Replace ``run_bridge_coroutine_async`` with a synchronous, draining capture.

    The real bridge coroutine still runs and its real result/exception still
    flows to the panel's real ``on_success``/``on_error`` callbacks; only the
    ``BridgeCallWorker`` ``QThread`` scheduling is swapped for an immediate,
    same-thread run so device-routing assertions do not race a background
    thread.

    Args:
        monkeypatch: Pytest monkeypatch fixture.

    Returns:
        list[Coroutine[object, object, object]]: List that records every
        coroutine the panel tried to dispatch, in dispatch order.
    """
    captured: list[Coroutine[object, object, object]] = []
    drain_loop = asyncio.new_event_loop()

    def fake_dispatch(
        coro: Coroutine[object, object, object],
        on_success: Callable[[object], None] | None = None,
        on_error: Callable[[object], None] | None = None,
        parent: object = None,
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


def _pump_until(app: QApplication, predicate: Callable[[], bool], *, timeout_s: float = _SETTLE_TIMEOUT_SECONDS) -> None:
    """Spin the Qt event loop until ``predicate`` is true.

    Args:
        app: Running application whose events must be dispatched.
        predicate: Zero-argument callable polled after each event-loop tick.
        timeout_s: Maximum time to wait before failing.

    Raises:
        AssertionError: If ``predicate`` never becomes true within ``timeout_s``.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        app.processEvents()
        if predicate():
            app.processEvents()
            return
        time.sleep(_PUMP_SLICE_SECONDS)
    msg = f"condition never became true within {timeout_s}s"
    raise AssertionError(msg)


class TestD22ResolveDeviceSelection:
    """D22 gates for the combo-to-bridge device type mapping."""

    @staticmethod
    def test_enumerated_local_socket_entry_maps_to_enumerated_device_type() -> None:
        """An enumerated combo entry must resolve to ``"enumerated"``, never ``"remote"``.

        Falsifiable: before the fix, ``_resolve_device_selection`` returned
        ``("remote", "socket")`` for this exact user data (Frida reports the
        Local Socket provider's own ``type`` as ``"remote"``), which is the
        root cause of D22 -- this assertion fails against that behavior.
        """
        device_type, host = FridaPanel._resolve_device_selection(
            dict(_ENUMERATED_SOCKET_USER_DATA),
            "Local Socket (remote)",
        )
        assert device_type == "enumerated"
        assert host == "socket"

    @staticmethod
    def test_manual_remote_text_entry_still_maps_to_remote_device_type() -> None:
        """A manually added ``remote:<host>`` combo entry (no dict userData) must still resolve to ``"remote"``.

        Falsifiable: if the enumerated-id branch were broadened to also
        swallow plain-text fallback entries, a manually typed remote host
        would stop reaching ``add_remote_device`` at all.
        """
        device_type, host = FridaPanel._resolve_device_selection(None, f"remote:{_ADD_REMOTE_HOST}")
        assert device_type == "remote"
        assert host == _ADD_REMOTE_HOST


@pytest.mark.usefixtures("require_frida")
class TestD22EnumeratedDeviceConnectsThroughDeviceHandle:
    """D22 gates driving the real panel and a real ``FridaBridge``/Frida runtime."""

    @staticmethod
    def test_selecting_enumerated_local_socket_device_uses_get_device_not_add_remote_device(
        synchronous_dispatch: list[Coroutine[object, object, object]],
    ) -> None:
        """Selecting the enumerated Local Socket device must resolve it by identity, not DNS.

        Adds a combo entry shaped exactly like ``_populate_device_combo``
        would for Frida's real ``socket`` device, selects it (firing the real
        ``currentTextChanged`` -> ``_on_device_changed`` wiring), and lets the
        real ``FridaBridge.connect_device`` coroutine run to completion.

        Falsifiable: ``frida.get_device("socket")`` and
        ``DeviceManager.add_remote_device("socket")`` are observably
        different Frida devices -- the former resolves to
        ``id="socket", name="Local Socket"``, the latter (DNS-resolving the
        literal string ``"socket"`` as a new remote endpoint) resolves to
        ``id="socket@socket", name="socket"``. Before the fix this test's
        bridge-identity assertions fail because the old code took the
        ``add_remote_device`` path.
        """
        panel = FridaPanel()
        bridge = FridaBridge()
        try:
            panel.set_bridge(bridge)

            panel._device_combo.addItem(
                "Local Socket (remote)",
                dict(_ENUMERATED_SOCKET_USER_DATA),
            )
            new_index = panel._device_combo.count() - 1
            panel._device_combo.setCurrentIndex(new_index)

            assert len(synchronous_dispatch) == 1, "selecting the entry must dispatch exactly one bridge coroutine"

            text = panel._console.toPlainText()
            assert "[-]" not in text, f"device connect must not fail: {text}"
            assert "[+] Connected to device: Local Socket" in text, text

            connected = bridge._device
            assert connected is not None
            assert connected.id == "socket", f"device id must be resolved by identity, got {connected.id!r}"
            assert connected.name == "Local Socket"
        finally:
            panel.close()

    @staticmethod
    def test_add_remote_device_dialog_creates_a_genuinely_new_remote_device(
        synchronous_dispatch: list[Coroutine[object, object, object]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Entering a ``host:port`` through the Add Remote Device dialog must create a new remote device.

        Drives the real ``FridaPanel._on_add_remote_device`` handler with
        ``QInputDialog.getText`` monkeypatched to a fixed accepted value (the
        established dialog-stubbing pattern in this suite), letting the real
        ``connect_device("remote", host_port)`` coroutine run.

        Falsifiable: before this handler existed there was no way to reach
        ``connect_device`` with a type of ``"remote"`` and a freshly typed
        host at all -- ``FridaPanel`` had no ``_on_add_remote_device``
        attribute and this call raises ``AttributeError``.
        """
        panel = FridaPanel()
        bridge = FridaBridge()
        try:
            panel.set_bridge(bridge)
            monkeypatch.setattr(QInputDialog, "getText", staticmethod(_fixed_get_text(_ADD_REMOTE_HOST)))

            panel._on_add_remote_device()

            assert len(synchronous_dispatch) == 1, "the dialog accept path must dispatch exactly one bridge coroutine"

            text = panel._console.toPlainText()
            assert "[-]" not in text, f"add-remote-device must not fail: {text}"

            connected = bridge._device
            assert connected is not None
            assert connected.type == "remote"

            entry_text = f"remote:{_ADD_REMOTE_HOST}"
            assert panel._device_combo.findText(entry_text) >= 0, "the new remote device must land as a combo entry"
        finally:
            panel.close()


@pytest.mark.usefixtures("require_frida")
class TestD23ProcessesRefreshFailureStaysInPanel:
    """D23 gates: a remote enumerate failure must never reach the app's crash hook."""

    @staticmethod
    def test_refresh_against_unreachable_remote_device_routes_to_panel_not_excepthook(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A Processes-refresh failure must land in the panel, never in ``sys.excepthook``.

        Connects a real remote ``FridaBridge`` device to a closed loopback
        port (guaranteed no ``frida-server``), then drives the real
        ``FridaPanel._on_refresh_processes`` -> real background
        ``BridgeCallWorker`` ``QThread`` -> real
        ``FridaBridge.enumerate_processes`` path with no dispatch
        substitution, exactly the production call chain. ``sys.excepthook``
        is monkeypatched to a recorder so nothing else in the process can
        answer for it.

        Falsifiable: before the fix, ``enumerate_processes`` let
        ``frida.ServerNotRunningError``/``frida.TransportError`` propagate
        out of the coroutine uncaught. That exception is not a member of
        ``BridgeCallWorker``'s caught exception tuple, so it escapes
        ``QThread.run()`` -- PyQt itself then calls ``sys.excepthook`` with
        it (independently verified live against this PyQt6 build), which is
        precisely the "escapes to app._unhandled_exception_hook" defect.
        This test's ``excepthook_calls == []`` assertion fails against that
        behavior; the Refresh button also never gets re-enabled without the
        ``on_error`` handler actually running.

        Args:
            qapp: Session QApplication fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        bridge = FridaBridge()
        _run_async(bridge.connect_device("remote", _UNREACHABLE_REMOTE_HOST))

        panel = FridaPanel()
        try:
            panel.set_bridge(bridge)

            excepthook_calls: list[BaseException] = []

            def _spy_excepthook(
                exc_type: type[BaseException],
                exc_value: BaseException,
                exc_tb: object,
            ) -> None:
                del exc_type, exc_tb
                excepthook_calls.append(exc_value)

            monkeypatch.setattr(sys, "excepthook", _spy_excepthook)

            panel._on_refresh_processes()
            assert not panel._refresh_procs_btn.isEnabled(), "Refresh must disable itself while the call is in flight"

            _pump_until(qapp, panel._refresh_procs_btn.isEnabled)

            assert excepthook_calls == [], f"the enumeration failure escaped to sys.excepthook (the app crash hook): {excepthook_calls!r}"
            text = panel._console.toPlainText()
            assert "[-] Remote enumerate failed:" in text, text
        finally:
            panel.close()
            qapp.processEvents()


class TestD20ProcessTableNameColumnReadable:
    """D20 gates: the Name column must dominate the table's width, never the PID column."""

    @staticmethod
    def test_name_column_wider_than_pid_after_populate(qapp: QApplication) -> None:
        """After a refresh-shaped populate, Name must be far wider than the fixed PID column.

        Drives the real ``_populate_process_table`` (the exact ``on_success``
        callback ``_on_refresh_processes`` wires up) with real
        ``FridaProcessEntry`` rows carrying ordinary process names, then reads
        the real header's post-layout column widths.

        Falsifiable: before the fix, PID used ``ResizeToContents`` with no
        floor and Name used ``Stretch`` with nothing constraining PID, so a
        table this narrow could leave Name a sliver comparable to (or
        narrower than) PID -- the reported "clipped to ~2 chars" symptom.
        This test's strict-inequality and minimum-width assertions fail
        against that layout.

        Args:
            qapp: Session QApplication fixture.
        """
        panel = FridaPanel()
        try:
            panel.resize(900, 500)
            panel.show()
            qapp.processEvents()
            qapp.processEvents()

            # Pin the table itself to a known, generous width. A headless
            # offscreen layout can otherwise starve the nested table's
            # viewport (leaving the Stretch Name column only a sliver
            # regardless of the panel width), which would make the
            # Name-dominates-PID assertion vacuous. With a concrete width the
            # QHeaderView Stretch section has real space to distribute, so the
            # fixed PID column vs stretched Name column relationship is
            # exercised for real.
            panel._process_table.setFixedWidth(700)

            processes = [
                FridaProcessEntry(pid=4080, name="svchost.exe"),
                FridaProcessEntry(pid=11840, name="explorer.exe"),
            ]
            panel._populate_process_table(processes)
            qapp.processEvents()
            qapp.processEvents()

            assert panel._process_table.rowCount() == 2
            pid_width = panel._process_table.columnWidth(_PROCESS_COL_PID)
            name_width = panel._process_table.columnWidth(_PROCESS_COL_NAME)

            assert pid_width <= _PROCESS_PID_COLUMN_WIDTH + 1, f"PID column must stay bounded to its fixed width, got {pid_width}px"
            assert name_width > pid_width, f"Name column ({name_width}px) must be wider than PID ({pid_width}px)"
            assert name_width > _PROCESS_PID_COLUMN_WIDTH * 2, (
                f"Name column is only {name_width}px wide -- too narrow to read a real process name"
            )
        finally:
            panel.close()
            qapp.processEvents()


class TestD21RunButtonDisabledCarriesHint:
    """D21 gates: a disabled Run button after a persistent load must explain and offer recovery."""

    @staticmethod
    def test_run_button_tooltip_explains_disabled_state_after_persistent_load(qapp: QApplication) -> None:
        """A successful persistent script load must leave Run disabled with an explanatory tooltip.

        Drives the real ``_on_run_script_success`` success callback exactly
        as a completed ``execute_persistent_script`` dispatch would.

        Falsifiable: before the fix, Run was disabled with no tooltip set
        (``toolTip()`` stays empty), so this assertion on non-empty,
        recovery-explaining text fails against that behavior.

        Args:
            qapp: Session QApplication fixture.
        """
        panel = FridaPanel()
        try:
            assert panel.run_btn.toolTip() == _RUN_SCRIPT_IDLE_TOOLTIP

            panel._on_run_script_success(42, "script-handle-123")

            assert not panel.run_btn.isEnabled()
            tooltip = panel.run_btn.toolTip()
            assert tooltip, "a disabled Run button must carry an explanatory tooltip"
            assert tooltip == _RUN_SCRIPT_BLOCKED_TOOLTIP
            assert "stop" in tooltip.lower()
        finally:
            panel.close()
            qapp.processEvents()

    @staticmethod
    def test_stop_is_a_directly_visible_toolbar_button_not_a_hidden_menu_action(qapp: QApplication) -> None:
        """Stop must be its own toolbar ``QPushButton``, not an action buried in a dropdown menu.

        Falsifiable: before the fix, ``panel._stop_btn`` was a ``QAction``
        exposed only through the "Scripts" dropdown button's popup menu, so
        this ``isinstance`` check against a real, directly-clickable
        ``QPushButton`` fails against that shape, and the button must also be
        enabled exactly when a persistent script is active -- the same
        recoverable state Run's tooltip explains.

        Args:
            qapp: Session QApplication fixture.
        """
        panel = FridaPanel()
        try:
            assert isinstance(panel._stop_btn, QPushButton), (
                f"Stop must be a directly visible toolbar QPushButton, got {type(panel._stop_btn).__name__}"
            )
            assert not panel._stop_btn.isEnabled()

            panel._on_run_script_success(42, "script-handle-123")
            assert panel._stop_btn.isEnabled(), "Stop must become the visible, enabled recovery path once Run is disabled"
        finally:
            panel.close()
            qapp.processEvents()
