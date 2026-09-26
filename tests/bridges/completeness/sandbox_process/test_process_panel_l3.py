# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Bridge-completeness remediation gates for PROCESS panel controls (L3).

Covers agent-10 (``audit/bridge-completeness/agent-10-sandbox-process.md``)
L3 wiring for:

* P13 -- ``MemoryTab``'s new "Decommit" button invokes
  ``ProcessBridge.decommit_memory`` with the address/size taken from the UI.
* P42/P43 -- ``SystemTab``'s pipe Read/Write buttons invoke
  ``ProcessBridge.pipe_read``/``pipe_write`` with the selected pipe handle.
* P63/P64 -- ``SystemTab``'s "Duplicate Token"/"Remove Privilege" buttons
  invoke ``ProcessBridge.duplicate_token``/``remove_privilege``.
* P66 -- ``SystemTab``'s "Detect Kernel Debugger" button invokes
  ``ProcessBridge.detect_kernel_debugger``.
* P65 -- ``ThreadsTab``'s "Time Wait" button invokes
  ``ProcessBridge.time_thread_wait`` with the selected thread id.

Every test wires a real ``ProcessBridge`` into the tab and replaces
``run_bridge_coroutine_logged`` in the tab module under test (not the bridge)
with a recording shim. The shim introspects the real coroutine it receives --
its code object, bound ``self`` and bound arguments -- and closes it before
any bridge body runs, so each gate asserts the handler created its coroutine
from the exact ``ProcessBridge`` method, on the wired bridge, with the exact
arguments parsed from the UI. The bridge bodies themselves (real WinAPI
calls) have their own dedicated L1 gates in ``test_process_l1_l2.py``.
"""

from __future__ import annotations

import inspect
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

import pytest
from PyQt6.QtWidgets import (
    QApplication,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
)

from intellicrack.bridges.process import ProcessBridge
from intellicrack.ui.panels.process_panel import (
    memory_tab as _memory_tab_mod,
    system_tab as _system_tab_mod,
    threads_tab as _threads_tab_mod,
)
from intellicrack.ui.panels.process_panel.memory_tab import MemoryTab
from intellicrack.ui.panels.process_panel.system_tab import SystemTab
from intellicrack.ui.panels.process_panel.threads_tab import ThreadsTab


if TYPE_CHECKING:
    from collections.abc import Coroutine, Iterator
    from types import CodeType

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="session")
def qapp() -> Iterator[QApplication]:
    """Provide a session-scoped QApplication.

    Qt requires exactly one QApplication per process.

    Yields:
        QApplication: A live QApplication for widget construction.
    """
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


@pytest.fixture
def memory_tab(qapp: QApplication) -> MemoryTab:
    """Create a MemoryTab instance for testing.

    Args:
        qapp: QApplication fixture -- required to ensure Qt is initialised.

    Returns:
        MemoryTab: A fresh MemoryTab widget.
    """
    assert isinstance(qapp, QApplication)
    return MemoryTab()


@pytest.fixture
def system_tab(qapp: QApplication) -> SystemTab:
    """Create a SystemTab instance for testing.

    Args:
        qapp: QApplication fixture -- required to ensure Qt is initialised.

    Returns:
        SystemTab: A fresh SystemTab widget.
    """
    assert isinstance(qapp, QApplication)
    return SystemTab()


@pytest.fixture
def threads_tab(qapp: QApplication) -> ThreadsTab:
    """Create a ThreadsTab instance for testing.

    Args:
        qapp: QApplication fixture -- required to ensure Qt is initialised.

    Returns:
        ThreadsTab: A fresh ThreadsTab widget.
    """
    assert isinstance(qapp, QApplication)
    return ThreadsTab()


def _set_private(widget: object, attr_name: str, value: object) -> None:
    """Assign a value to a named private attribute of a widget under test.

    Used to wire collaborators (e.g. a real bridge) into private collaborator
    slots without a direct private-attribute assignment expression that would
    fight the widget's declared attribute type.

    Args:
        widget: Widget instance to mutate.
        attr_name: Attribute name to set.
        value: Value to assign.
    """
    setattr(widget, attr_name, value)


def _get_private(widget: object, attr_name: str) -> object:
    """Read a named private attribute of a widget under test.

    Args:
        widget: Widget instance to read from.
        attr_name: Attribute name to read.

    Returns:
        object: The current value of the attribute.
    """
    return getattr(widget, attr_name)


def _invoke(widget: object, method_name: str) -> None:
    """Invoke a named zero-argument handler method on a widget.

    Args:
        widget: Widget whose handler is invoked.
        method_name: Name of the handler method to call.
    """
    handler = getattr(widget, method_name)
    assert callable(handler), f"{type(widget).__name__}.{method_name} must be callable"
    handler()


@dataclass(frozen=True, slots=True)
class _DispatchedBridgeCall:
    """One ``run_bridge_coroutine_logged`` invocation captured before dispatch.

    The real bridge coroutine is introspected (its code object, bound ``self``
    and bound arguments) and then closed, so no bridge body ever runs and no
    "coroutine was never awaited" warning is emitted.

    Attributes:
        coroutine: The exact coroutine object handed to the dispatcher.
        code: Code object the coroutine executes; identifies the bridge method.
        bound_self: The ``self`` the bridge method was bound to.
        arguments: The bridge method's bound arguments, excluding ``self``.
        dispatch_kwargs: Keyword arguments passed to the dispatcher itself
            (``on_success``, ``on_error``, ``event``, ...).
    """

    coroutine: Coroutine[object, object, object]
    code: CodeType
    bound_self: object
    arguments: dict[str, object]
    dispatch_kwargs: dict[str, object]


def _intercept_dispatch(monkeypatch: pytest.MonkeyPatch, module: object) -> list[_DispatchedBridgeCall]:
    """Replace ``run_bridge_coroutine_logged`` in ``module`` with a recording shim.

    Args:
        monkeypatch: pytest monkeypatch fixture.
        module: The module whose dispatcher symbol is replaced.

    Returns:
        list[_DispatchedBridgeCall]: Live list receiving one entry per dispatch.
    """
    captured: list[_DispatchedBridgeCall] = []

    def _record(coro: object, *args: object, **kwargs: object) -> None:
        del args
        assert inspect.iscoroutine(coro), f"dispatcher must receive a real bridge coroutine; got {coro!r}"
        frame_locals = dict(inspect.getcoroutinelocals(coro))
        bound_self = frame_locals.pop("self", None)
        captured.append(
            _DispatchedBridgeCall(
                coroutine=coro,
                code=coro.cr_code,
                bound_self=bound_self,
                arguments=frame_locals,
                dispatch_kwargs=dict(kwargs),
            ),
        )
        coro.close()

    monkeypatch.setattr(module, "run_bridge_coroutine_logged", _record)
    return captured


def _assert_bridge_call(
    call: _DispatchedBridgeCall,
    bridge: object,
    method_name: str,
    expected_arguments: dict[str, object],
) -> None:
    """Assert a dispatched coroutine came from ``bridge.<method_name>`` with the expected arguments.

    Args:
        call: The captured dispatch.
        bridge: The real bridge instance wired into the widget under test.
        method_name: Name of the bridge coroutine method that must have produced the coroutine.
        expected_arguments: Every bound argument of that method (defaults included), excluding ``self``.
    """
    method: object = getattr(type(bridge), method_name)
    assert inspect.isfunction(method), f"{type(bridge).__name__}.{method_name} must be a plain coroutine function"
    assert call.code is method.__code__, (
        f"dispatched coroutine must come from {type(bridge).__name__}.{method_name}; got {call.code.co_qualname}"
    )
    assert call.bound_self is bridge, "dispatched coroutine must be bound to the bridge wired into the widget"
    assert call.arguments == expected_arguments, (
        f"{method_name} bound arguments mismatch: expected {expected_arguments!r}, got {call.arguments!r}"
    )


def _noop_warning_yes(*_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
    """Return Yes without showing a real dialog.

    Args:
        *_args: Positional arguments (ignored).
        **_kwargs: Keyword arguments (ignored).

    Returns:
        QMessageBox.StandardButton: Yes button constant.
    """
    return QMessageBox.StandardButton.Yes


class TestMemoryTabDecommitWiringL3:
    """P13: MemoryTab's Decommit button invokes ProcessBridge.decommit_memory."""

    def test_on_decommit_dispatches_real_bridge_method_with_address_and_size(
        self,
        memory_tab: MemoryTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_decommit dispatches the coroutine from bridge.decommit_memory with the exact pid/address/size.

        Falsified by: removing the ``self._bridge.decommit_memory(pid, addr,
        size)`` call in ``memory_tab.py``'s ``_on_decommit`` (or wiring the
        Decommit button to any other handler) turns this red, since the
        captured coroutine would no longer come from
        ``ProcessBridge.decommit_memory``.

        Args:
            memory_tab: MemoryTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(memory_tab, "_bridge", bridge)
        memory_tab.set_attached_pid(4321)

        dispatch_args = _intercept_dispatch(monkeypatch, _memory_tab_mod)
        monkeypatch.setattr(QMessageBox, "warning", _noop_warning_yes)

        free_addr = cast("QLineEdit", _get_private(memory_tab, "_free_addr"))
        free_addr.setText("0x2000")
        decommit_size = cast("QSpinBox", _get_private(memory_tab, "_decommit_size"))
        decommit_size.setValue(8192)

        _invoke(memory_tab, "_on_decommit")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called when attached with a valid address"
        _assert_bridge_call(dispatch_args[0], bridge, "decommit_memory", {"pid": 4321, "address": 0x2000, "size": 8192})

    def test_on_decommit_no_dispatch_when_unattached(
        self,
        memory_tab: MemoryTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_decommit skips dispatch and shows a warning when no process is attached.

        Args:
            memory_tab: MemoryTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _set_private(memory_tab, "_bridge", ProcessBridge())
        memory_tab.set_attached_pid(None)

        warning_calls: list[tuple[object, ...]] = []

        def _capture_warning(*args: object, **_kwargs: object) -> QMessageBox.StandardButton:
            warning_calls.append(args)
            return QMessageBox.StandardButton.Ok

        dispatch_calls = _intercept_dispatch(monkeypatch, _memory_tab_mod)
        monkeypatch.setattr(QMessageBox, "warning", _capture_warning)

        free_addr = cast("QLineEdit", _get_private(memory_tab, "_free_addr"))
        free_addr.setText("0x2000")

        _invoke(memory_tab, "_on_decommit")

        assert not dispatch_calls, "decommit_memory must not be dispatched without an attached pid"
        assert warning_calls, "_on_decommit must warn the user when unattached"


def _select_pipe_row(system_tab: SystemTab, pipe_name: str, handle: int) -> None:
    """Populate the pipe table with one row and select it.

    Args:
        system_tab: SystemTab fixture to mutate.
        pipe_name: Pipe name to place in column 0.
        handle: Handle value to record in the tab's internal pipe-handle map.
    """
    pipe_table = cast("QTableWidget", _get_private(system_tab, "_pipe_table"))
    pipe_table.setRowCount(1)
    pipe_table.setItem(0, 0, QTableWidgetItem(pipe_name))
    pipe_table.setItem(0, 1, QTableWidgetItem(hex(handle)))
    pipe_table.selectRow(0)
    pipe_handles = cast("dict[str, int]", _get_private(system_tab, "_pipe_handles"))
    pipe_handles[pipe_name] = handle


class TestSystemTabPipeReadWriteWiringL3:
    """P42/P43: SystemTab's pipe Read/Write buttons invoke ProcessBridge.pipe_read/pipe_write."""

    def test_on_pipe_read_dispatches_with_selected_handle_and_size(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_pipe_read dispatches bridge.pipe_read with the selected pipe's handle and the read-size spinbox value.

        Falsified by: the Read button's ``clicked`` connection being removed
        or rewired away from ``_on_pipe_read``, or ``_on_pipe_read`` reading
        the wrong handle/size.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(system_tab, "_bridge", bridge)
        _select_pipe_row(system_tab, r"\\.\pipe\TestPipe", 0x1234)

        read_size = cast("QSpinBox", _get_private(system_tab, "_pipe_read_size"))
        read_size.setValue(2048)

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)

        _invoke(system_tab, "_on_pipe_read")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called when a pipe row is selected"
        _assert_bridge_call(dispatch_args[0], bridge, "pipe_read", {"handle": 0x1234, "size": 2048})

    def test_on_pipe_read_warns_when_no_pipe_selected(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_pipe_read shows a warning and skips dispatch when no pipe row is selected.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _set_private(system_tab, "_bridge", ProcessBridge())

        warning_calls: list[tuple[object, ...]] = []

        def _capture_warning(*args: object, **_kwargs: object) -> QMessageBox.StandardButton:
            warning_calls.append(args)
            return QMessageBox.StandardButton.Ok

        dispatch_calls = _intercept_dispatch(monkeypatch, _system_tab_mod)
        monkeypatch.setattr(QMessageBox, "warning", _capture_warning)

        _invoke(system_tab, "_on_pipe_read")

        assert not dispatch_calls, "pipe_read must not be dispatched without a selected pipe row"
        assert warning_calls, "_on_pipe_read must warn the user when no pipe is selected"

    def test_on_pipe_write_dispatches_with_selected_handle_and_parsed_hex_bytes(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_pipe_write dispatches bridge.pipe_write with the selected handle and the parsed hex-input bytes.

        Falsified by: the Write button's ``clicked`` connection being
        rewired away from ``_on_pipe_write``, or the hex-to-bytes parsing
        being broken so the wrong payload reaches the bridge.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(system_tab, "_bridge", bridge)
        _select_pipe_row(system_tab, r"\\.\pipe\TestPipe", 0x5678)

        io_data = cast("QPlainTextEdit", _get_private(system_tab, "_pipe_io_data"))
        io_data.setPlainText("90 90 CC 48")

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)

        _invoke(system_tab, "_on_pipe_write")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called when a pipe row is selected with valid hex input"
        _assert_bridge_call(
            dispatch_args[0],
            bridge,
            "pipe_write",
            {"handle": 0x5678, "data": bytes.fromhex("90 90 CC 48".replace(" ", ""))},
        )

    def test_on_pipe_write_rejects_invalid_hex_without_dispatch(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_pipe_write skips dispatch and reports an error for malformed hex input.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(system_tab, "_bridge", bridge)
        _select_pipe_row(system_tab, r"\\.\pipe\TestPipe", 0x5678)

        io_data = cast("QPlainTextEdit", _get_private(system_tab, "_pipe_io_data"))
        io_data.setPlainText("not-hex-data")

        dispatch_calls = _intercept_dispatch(monkeypatch, _system_tab_mod)

        _invoke(system_tab, "_on_pipe_write")

        assert not dispatch_calls, "pipe_write must not be dispatched with invalid hex input"
        status_label = cast("QLabel", _get_private(system_tab, "_pipe_io_status"))
        assert "Invalid hex data" in status_label.text()


class TestSystemTabTokenControlsWiringL3:
    """P63/P64: SystemTab's Duplicate Token / Remove Privilege buttons invoke the real bridge methods."""

    def test_on_duplicate_token_dispatches_with_attached_pid(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_duplicate_token dispatches bridge.duplicate_token with the attached pid.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(system_tab, "_bridge", bridge)
        system_tab.set_attached_pid(9001)

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)

        _invoke(system_tab, "_on_duplicate_token")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called when attached"
        _assert_bridge_call(dispatch_args[0], bridge, "duplicate_token", {"pid": 9001})

    def test_on_remove_privilege_dispatches_with_pid_and_privilege_name(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_remove_privilege dispatches bridge.remove_privilege with the attached pid and entered privilege name.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(system_tab, "_bridge", bridge)
        system_tab.set_attached_pid(9002)

        priv_name = cast("QLineEdit", _get_private(system_tab, "_remove_priv_name"))
        priv_name.setText("SeShutdownPrivilege")

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)
        monkeypatch.setattr(QMessageBox, "warning", _noop_warning_yes)

        _invoke(system_tab, "_on_remove_privilege")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called with a non-empty privilege name"
        _assert_bridge_call(dispatch_args[0], bridge, "remove_privilege", {"pid": 9002, "privilege_name": "SeShutdownPrivilege"})

    def test_on_remove_privilege_requires_non_empty_name(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_remove_privilege skips dispatch when the privilege name field is blank.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _set_private(system_tab, "_bridge", ProcessBridge())
        system_tab.set_attached_pid(9003)

        priv_name = cast("QLineEdit", _get_private(system_tab, "_remove_priv_name"))
        priv_name.setText("")

        dispatch_calls = _intercept_dispatch(monkeypatch, _system_tab_mod)

        _invoke(system_tab, "_on_remove_privilege")

        assert not dispatch_calls, "remove_privilege must not be dispatched with a blank privilege name"


class TestSystemTabDetectKernelDebuggerWiringL3:
    """P66: SystemTab's Detect Kernel Debugger button invokes ProcessBridge.detect_kernel_debugger."""

    def test_on_detect_kernel_debugger_dispatches_with_attached_pid(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_detect_kernel_debugger dispatches bridge.detect_kernel_debugger with the attached pid.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(system_tab, "_bridge", bridge)
        system_tab.set_attached_pid(9004)

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)

        _invoke(system_tab, "_on_detect_kernel_debugger")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called when attached"
        _assert_bridge_call(dispatch_args[0], bridge, "detect_kernel_debugger", {"pid": 9004})

    def test_success_callback_renders_detected_status(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The success callback renders 'Kernel debugger detected' when the bridge reports True.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(system_tab, "_bridge", bridge)
        system_tab.set_attached_pid(9005)

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)

        _invoke(system_tab, "_on_detect_kernel_debugger")

        captured_on_success = [call.dispatch_kwargs["on_success"] for call in dispatch_args]
        assert captured_on_success, "expected an on_success callback to be captured"
        success_cb = captured_on_success[0]
        assert callable(success_cb)
        detected = True
        success_cb(detected)

        status_label = cast("QLabel", _get_private(system_tab, "_kernel_dbg_status"))
        assert status_label.text() == "Kernel debugger detected"


class TestThreadsTabTimeWaitWiringL3:
    """P65: ThreadsTab's Time Wait button invokes ProcessBridge.time_thread_wait."""

    def test_on_time_thread_wait_dispatches_with_selected_tid(
        self,
        threads_tab: ThreadsTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_time_thread_wait dispatches bridge.time_thread_wait with the selected row's tid.

        Args:
            threads_tab: ThreadsTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(threads_tab, "_bridge", bridge)

        thread_table = cast("QTableWidget", _get_private(threads_tab, "_thread_table"))
        thread_table.setRowCount(1)
        thread_table.setItem(0, 0, QTableWidgetItem("5150"))
        thread_table.selectRow(0)

        dispatch_args = _intercept_dispatch(monkeypatch, _threads_tab_mod)

        _invoke(threads_tab, "_on_time_thread_wait")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called when a thread row is selected"
        _assert_bridge_call(dispatch_args[0], bridge, "time_thread_wait", {"tid": 5150, "timeout_ms": 0})

    def test_on_time_thread_wait_warns_when_no_thread_selected(
        self,
        threads_tab: ThreadsTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_time_thread_wait shows a warning and skips dispatch when no thread row is selected.

        Args:
            threads_tab: ThreadsTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _set_private(threads_tab, "_bridge", ProcessBridge())

        warning_calls: list[tuple[object, ...]] = []

        def _capture_warning(*args: object, **_kwargs: object) -> QMessageBox.StandardButton:
            warning_calls.append(args)
            return QMessageBox.StandardButton.Ok

        dispatch_calls = _intercept_dispatch(monkeypatch, _threads_tab_mod)
        monkeypatch.setattr(QMessageBox, "warning", _capture_warning)

        _invoke(threads_tab, "_on_time_thread_wait")

        assert not dispatch_calls, "time_thread_wait must not be dispatched without a selected thread"
        assert warning_calls, "_on_time_thread_wait must warn the user when no thread is selected"

    def test_success_callback_renders_wait_result(
        self,
        threads_tab: ThreadsTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The success callback renders the tid, result, and elapsed microseconds in the status label.

        Args:
            threads_tab: ThreadsTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(threads_tab, "_bridge", bridge)

        thread_table = cast("QTableWidget", _get_private(threads_tab, "_thread_table"))
        thread_table.setRowCount(1)
        thread_table.setItem(0, 0, QTableWidgetItem("42"))
        thread_table.selectRow(0)

        dispatch_args = _intercept_dispatch(monkeypatch, _threads_tab_mod)

        _invoke(threads_tab, "_on_time_thread_wait")

        captured_on_success = [call.dispatch_kwargs["on_success"] for call in dispatch_args]
        assert captured_on_success, "expected an on_success callback to be captured"
        success_cb = captured_on_success[0]
        assert callable(success_cb)
        success_cb({"result": "signaled", "elapsed_us": 1234})

        status_label = cast("QLabel", _get_private(threads_tab, "_wait_status"))
        assert status_label.text() == "TID 42: signaled (1234 us)"
