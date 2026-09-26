# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Bridge-completeness wiring gates (L3) for newly-wired PROCESS panel controls.

Each test drives the *real* handler on a live ``MemoryTab``/``SystemTab`` wired
to a real ``ProcessBridge``, after replacing ``run_bridge_coroutine_logged`` in
the tab module under test with a recording shim (never the bridge). The shim
introspects the real coroutine it receives -- code object, bound ``self`` and
bound arguments -- then closes it before any bridge body runs. The gate asserts:

* the coroutine handed to ``run_bridge_coroutine_logged`` was created by the
  corresponding ``ProcessBridge`` method on the wired bridge, proving the
  button is wired to that method and no other, and
* that method was bound to the exact arguments parsed from the UI widgets,
  proving the handler's argument marshalling.

Negative-path tests assert that guarded handlers skip dispatch entirely (and
surface a warning) when required input is missing or malformed.

The bridge bodies (real WinAPI behaviour) have their own dedicated L1 gates.
Removing or rewiring any handler's bridge call turns its gate red.
"""

from __future__ import annotations

import inspect
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

import pytest
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QLineEdit,
    QMessageBox,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
)

from intellicrack.bridges.process import ProcessBridge
from intellicrack.ui.panels.process_panel import (
    memory_tab as _memory_tab_mod,
    system_tab as _system_tab_mod,
)
from intellicrack.ui.panels.process_panel.memory_tab import MemoryTab
from intellicrack.ui.panels.process_panel.system_tab import SystemTab


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


def _set_private(widget: object, attr_name: str, value: object) -> None:
    """Assign a value to a named private attribute of a widget under test.

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


def _capture_warnings(monkeypatch: pytest.MonkeyPatch) -> list[tuple[object, ...]]:
    """Replace ``QMessageBox.warning`` with a non-modal capture returning Ok.

    Args:
        monkeypatch: pytest monkeypatch fixture.

    Returns:
        list[tuple[object, ...]]: Live list receiving the positional arguments of
            each ``QMessageBox.warning`` call.
    """
    calls: list[tuple[object, ...]] = []

    def _capture(*args: object, **kwargs: object) -> QMessageBox.StandardButton:
        del kwargs
        calls.append(args)
        return QMessageBox.StandardButton.Ok

    monkeypatch.setattr(QMessageBox, "warning", _capture)
    return calls


def _select_device_row(system_tab: SystemTab, device_path: str, handle: int) -> None:
    """Populate the device table with one selected row and register its handle.

    Args:
        system_tab: SystemTab fixture to mutate.
        device_path: Device path placed in column 0.
        handle: Handle value recorded in column 1 (hex) and the handle-tracking map.
    """
    table = cast("QTableWidget", _get_private(system_tab, "_device_table"))
    table.setRowCount(1)
    table.setItem(0, 0, QTableWidgetItem(device_path))
    table.setItem(0, 1, QTableWidgetItem(hex(handle)))
    table.selectRow(0)
    handles = cast("dict[int, str]", _get_private(system_tab, "_device_handles"))
    handles[handle] = device_path


def _select_section_row(system_tab: SystemTab, handle: int, name: str) -> None:
    """Populate the section table with one selected row and register its handle.

    Args:
        system_tab: SystemTab fixture to mutate.
        handle: Section handle placed in column 0 (hex) and the handle-tracking map.
        name: Section name placed in column 1.
    """
    table = cast("QTableWidget", _get_private(system_tab, "_section_table"))
    table.setRowCount(1)
    table.setItem(0, 0, QTableWidgetItem(hex(handle)))
    table.setItem(0, 1, QTableWidgetItem(name))
    table.selectRow(0)
    handles = cast("dict[int, str]", _get_private(system_tab, "_section_handles"))
    handles[handle] = name


def _select_view_row(system_tab: SystemTab, base: int, owning_handle: int) -> None:
    """Populate the views table with one selected mapped-view row.

    Args:
        system_tab: SystemTab fixture to mutate.
        base: View base address placed in column 0 (hex) and the view-tracking map.
        owning_handle: Owning section handle recorded for the view.
    """
    table = cast("QTableWidget", _get_private(system_tab, "_views_table"))
    table.setRowCount(1)
    table.setItem(0, 0, QTableWidgetItem(hex(base)))
    table.setItem(0, 1, QTableWidgetItem(hex(owning_handle)))
    table.selectRow(0)
    views = cast("dict[int, int]", _get_private(system_tab, "_section_views"))
    views[base] = owning_handle


class TestMemoryTabWorkingSetWiringL3:
    """MemoryTab's Working Set button invokes ProcessBridge.get_process_memory_mb."""

    def test_on_working_set_dispatches_with_attached_pid(
        self,
        memory_tab: MemoryTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_working_set dispatches bridge.get_process_memory_mb with the attached pid.

        Falsified by: removing the ``self._bridge.get_process_memory_mb(pid)``
        call, rewiring the button to another handler, or passing the wrong pid.

        Args:
            memory_tab: MemoryTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(memory_tab, "_bridge", bridge)
        memory_tab.set_attached_pid(7788)

        dispatch_args = _intercept_dispatch(monkeypatch, _memory_tab_mod)

        _invoke(memory_tab, "_on_working_set")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called when attached"
        _assert_bridge_call(dispatch_args[0], bridge, "get_process_memory_mb", {"pid": 7788})

    def test_on_working_set_no_dispatch_when_unattached(
        self,
        memory_tab: MemoryTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_working_set skips dispatch and warns when no process is attached.

        Args:
            memory_tab: MemoryTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _set_private(memory_tab, "_bridge", ProcessBridge())
        memory_tab.set_attached_pid(None)

        dispatch_args = _intercept_dispatch(monkeypatch, _memory_tab_mod)
        warning_calls = _capture_warnings(monkeypatch)

        _invoke(memory_tab, "_on_working_set")

        assert dispatch_args == [], "get_process_memory_mb must not be dispatched without an attached pid"
        assert warning_calls, "_on_working_set must warn the user when unattached"


class TestSystemTabDeviceOpenWiringL3:
    """SystemTab's device Open button invokes ProcessBridge.device_open."""

    def test_on_device_open_dispatches_with_device_path(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_device_open dispatches bridge.device_open with the entered device path.

        Falsified by: rewiring the Open button away from ``_on_device_open`` or
        reading the wrong widget for the device path.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(system_tab, "_bridge", bridge)
        device_path = cast("QLineEdit", _get_private(system_tab, "_device_path"))
        device_path.setText(r"\\.\MyDriver")

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)

        _invoke(system_tab, "_on_device_open")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called with a non-empty device path"
        _assert_bridge_call(dispatch_args[0], bridge, "device_open", {"device_path": r"\\.\MyDriver"})

    def test_on_device_open_requires_non_empty_path(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_device_open skips dispatch and warns when the device path is blank.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _set_private(system_tab, "_bridge", ProcessBridge())
        device_path = cast("QLineEdit", _get_private(system_tab, "_device_path"))
        device_path.setText("")

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)
        warning_calls = _capture_warnings(monkeypatch)

        _invoke(system_tab, "_on_device_open")

        assert dispatch_args == [], "device_open must not be dispatched with a blank device path"
        assert warning_calls, "_on_device_open must warn the user when the path is blank"


class TestSystemTabDeviceIoctlWiringL3:
    """SystemTab's Send IOCTL button invokes ProcessBridge.device_ioctl."""

    def test_on_device_ioctl_dispatches_with_parsed_handle_code_input_and_size(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_device_ioctl dispatches bridge.device_ioctl with the selected handle, parsed code, input, and output size.

        Falsified by: rewiring Send IOCTL away from ``_on_device_ioctl``, using
        ``int()`` without base-0 hex parsing for the IOCTL code, dropping the
        input payload, or reading the wrong output-size widget.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(system_tab, "_bridge", bridge)
        _select_device_row(system_tab, r"\\.\MyDriver", 0x1234)

        cast("QLineEdit", _get_private(system_tab, "_ioctl_code")).setText("0x0022E004")
        cast("QLineEdit", _get_private(system_tab, "_ioctl_input")).setText("dead beef")
        cast("QSpinBox", _get_private(system_tab, "_ioctl_output_size")).setValue(8192)

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)

        _invoke(system_tab, "_on_device_ioctl")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called with a selected device and valid code"
        _assert_bridge_call(
            dispatch_args[0],
            bridge,
            "device_ioctl",
            {"handle": 0x1234, "ioctl_code": 0x0022E004, "input_data": "deadbeef", "output_size": 8192},
        )

    def test_on_device_ioctl_omits_input_when_field_blank(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_device_ioctl passes ``None`` for input_data when the input field is blank.

        Falsified by: passing an empty string instead of ``None`` for a blank
        input field (breaks the ``input_text or None`` marshalling).

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(system_tab, "_bridge", bridge)
        _select_device_row(system_tab, r"\\.\MyDriver", 0x1234)

        cast("QLineEdit", _get_private(system_tab, "_ioctl_code")).setText("0x1000")
        cast("QLineEdit", _get_private(system_tab, "_ioctl_input")).setText("")
        cast("QSpinBox", _get_private(system_tab, "_ioctl_output_size")).setValue(256)

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)

        _invoke(system_tab, "_on_device_ioctl")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must still dispatch with a blank input field"
        _assert_bridge_call(
            dispatch_args[0],
            bridge,
            "device_ioctl",
            {"handle": 0x1234, "ioctl_code": 0x1000, "input_data": None, "output_size": 256},
        )

    def test_on_device_ioctl_no_dispatch_without_selected_device(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_device_ioctl skips dispatch and warns when no open device is selected.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _set_private(system_tab, "_bridge", ProcessBridge())
        cast("QLineEdit", _get_private(system_tab, "_ioctl_code")).setText("0x1000")

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)
        warning_calls = _capture_warnings(monkeypatch)

        _invoke(system_tab, "_on_device_ioctl")

        assert dispatch_args == [], "device_ioctl must not be dispatched without a selected device"
        assert warning_calls, "_on_device_ioctl must warn when no device is selected"

    def test_on_device_ioctl_rejects_invalid_code_without_dispatch(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_device_ioctl skips dispatch and warns when the IOCTL code is unparseable.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _set_private(system_tab, "_bridge", ProcessBridge())
        _select_device_row(system_tab, r"\\.\MyDriver", 0x1234)
        cast("QLineEdit", _get_private(system_tab, "_ioctl_code")).setText("not-a-code")

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)
        warning_calls = _capture_warnings(monkeypatch)

        _invoke(system_tab, "_on_device_ioctl")

        assert dispatch_args == [], "device_ioctl must not be dispatched with an invalid IOCTL code"
        assert warning_calls, "_on_device_ioctl must warn on an invalid IOCTL code"


class TestSystemTabDeviceCloseWiringL3:
    """SystemTab's device Close button invokes ProcessBridge.device_close."""

    def test_on_device_close_dispatches_with_selected_handle(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_device_close dispatches bridge.device_close with the selected device handle.

        Falsified by: rewiring Close away from ``_on_device_close`` or reading a
        handle other than the selected device row's.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(system_tab, "_bridge", bridge)
        _select_device_row(system_tab, r"\\.\MyDriver", 0xABCD)

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)

        _invoke(system_tab, "_on_device_close")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called with a selected device"
        _assert_bridge_call(dispatch_args[0], bridge, "device_close", {"handle": 0xABCD})

    def test_on_device_close_no_dispatch_without_selection(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_device_close skips dispatch and warns when no device row is selected.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _set_private(system_tab, "_bridge", ProcessBridge())

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)
        warning_calls = _capture_warnings(monkeypatch)

        _invoke(system_tab, "_on_device_close")

        assert dispatch_args == [], "device_close must not be dispatched without a selected device"
        assert warning_calls, "_on_device_close must warn when no device is selected"


class TestSystemTabCreateSectionWiringL3:
    """SystemTab's Create Section button invokes ProcessBridge.create_section."""

    def test_on_create_section_dispatches_with_size_and_name(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_create_section dispatches bridge.create_section with the size spinbox and name field.

        Falsified by: rewiring Create Section away from ``_on_create_section`` or
        reading the wrong size/name widgets.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(system_tab, "_bridge", bridge)
        cast("QSpinBox", _get_private(system_tab, "_section_size")).setValue(16384)
        cast("QLineEdit", _get_private(system_tab, "_section_name")).setText("MySection")

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)

        _invoke(system_tab, "_on_create_section")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called for a create-section request"
        _assert_bridge_call(dispatch_args[0], bridge, "create_section", {"size": 16384, "section_name": "MySection"})

    def test_on_create_section_passes_none_name_when_blank(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_create_section passes ``None`` as the section name when the name field is blank.

        Falsified by: passing an empty string instead of ``None`` for an
        anonymous section (breaks the ``name_text or None`` marshalling).

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(system_tab, "_bridge", bridge)
        cast("QSpinBox", _get_private(system_tab, "_section_size")).setValue(4096)
        cast("QLineEdit", _get_private(system_tab, "_section_name")).setText("")

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)

        _invoke(system_tab, "_on_create_section")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called for an anonymous create-section request"
        _assert_bridge_call(dispatch_args[0], bridge, "create_section", {"size": 4096, "section_name": None})


class TestSystemTabMapSectionWiringL3:
    """SystemTab's Map button invokes ProcessBridge.map_section."""

    def test_on_map_section_dispatches_with_selected_handle_and_size(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_map_section dispatches bridge.map_section with the selected section handle and map-size spinbox.

        Falsified by: rewiring Map away from ``_on_map_section`` or reading the
        wrong handle/size widgets.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(system_tab, "_bridge", bridge)
        _select_section_row(system_tab, 0x4444, "MySection")
        cast("QSpinBox", _get_private(system_tab, "_map_size")).setValue(32768)

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)

        _invoke(system_tab, "_on_map_section")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called with a selected section"
        _assert_bridge_call(dispatch_args[0], bridge, "map_section", {"handle": 0x4444, "size": 32768})

    def test_on_map_section_no_dispatch_without_selection(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_map_section skips dispatch and warns when no section row is selected.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _set_private(system_tab, "_bridge", ProcessBridge())

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)
        warning_calls = _capture_warnings(monkeypatch)

        _invoke(system_tab, "_on_map_section")

        assert dispatch_args == [], "map_section must not be dispatched without a selected section"
        assert warning_calls, "_on_map_section must warn when no section is selected"


class TestSystemTabUnmapSectionWiringL3:
    """SystemTab's Unmap button invokes ProcessBridge.unmap_section."""

    def test_on_unmap_section_dispatches_with_selected_base_address(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_unmap_section dispatches bridge.unmap_section with the selected view's base address.

        Falsified by: rewiring Unmap away from ``_on_unmap_section`` or reading a
        base address other than the selected view row's.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(system_tab, "_bridge", bridge)
        _select_view_row(system_tab, 0x7F000000, 0x4444)

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)

        _invoke(system_tab, "_on_unmap_section")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called with a selected view"
        _assert_bridge_call(dispatch_args[0], bridge, "unmap_section", {"base_address": 0x7F000000})

    def test_on_unmap_section_no_dispatch_without_selection(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_unmap_section skips dispatch and warns when no mapped view is selected.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _set_private(system_tab, "_bridge", ProcessBridge())

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)
        warning_calls = _capture_warnings(monkeypatch)

        _invoke(system_tab, "_on_unmap_section")

        assert dispatch_args == [], "unmap_section must not be dispatched without a selected view"
        assert warning_calls, "_on_unmap_section must warn when no view is selected"


class TestSystemTabEnumerateHandlesWiringL3:
    """SystemTab's Enumerate (Raw) button invokes ProcessBridge.enumerate_handles."""

    def test_on_enumerate_handles_dispatches_with_parsed_pid_filter(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_enumerate_handles dispatches bridge.enumerate_handles with the parsed PID filter.

        Falsified by: rewiring Enumerate (Raw) away from ``_on_enumerate_handles``
        or failing to parse the PID-filter field.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(system_tab, "_bridge", bridge)
        cast("QLineEdit", _get_private(system_tab, "_handles_pid")).setText("4321")

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)

        _invoke(system_tab, "_on_enumerate_handles")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called for a valid PID filter"
        _assert_bridge_call(dispatch_args[0], bridge, "enumerate_handles", {"pid": 4321})

    def test_on_enumerate_handles_passes_none_for_blank_filter(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_enumerate_handles passes ``None`` (all processes) when the PID-filter field is blank.

        Falsified by: substituting a non-None value for an empty PID filter.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(system_tab, "_bridge", bridge)
        cast("QLineEdit", _get_private(system_tab, "_handles_pid")).setText("")

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)

        _invoke(system_tab, "_on_enumerate_handles")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called for a blank PID filter"
        _assert_bridge_call(dispatch_args[0], bridge, "enumerate_handles", {"pid": None})

    def test_on_enumerate_handles_rejects_invalid_pid_without_dispatch(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_enumerate_handles skips dispatch and warns when the PID filter is non-numeric.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _set_private(system_tab, "_bridge", ProcessBridge())
        cast("QLineEdit", _get_private(system_tab, "_handles_pid")).setText("bogus")

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)
        warning_calls = _capture_warnings(monkeypatch)

        _invoke(system_tab, "_on_enumerate_handles")

        assert dispatch_args == [], "enumerate_handles must not be dispatched with an invalid PID filter"
        assert warning_calls, "_on_enumerate_handles must warn on an invalid PID filter"


class TestSystemTabEnumHandlesWiringL3:
    """SystemTab's Enumerate (Typed) button invokes ProcessBridge.enum_handles."""

    def test_on_enum_handles_dispatches_with_parsed_pid_filter(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_enum_handles dispatches bridge.enum_handles with the parsed PID filter.

        Falsified by: rewiring Enumerate (Typed) away from ``_on_enum_handles``
        or dispatching enumerate_handles instead of enum_handles.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(system_tab, "_bridge", bridge)
        cast("QLineEdit", _get_private(system_tab, "_handles_pid")).setText("909")

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)

        _invoke(system_tab, "_on_enum_handles")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called for a valid PID filter"
        _assert_bridge_call(dispatch_args[0], bridge, "enum_handles", {"pid": 909})
        assert "enumerate_handles" not in [call.code.co_name for call in dispatch_args]


class TestSystemTabEnumerateServicesWiringL3:
    """SystemTab's Enumerate All Services button invokes ProcessBridge.enumerate_services."""

    def test_on_enumerate_all_services_active_only_true(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_enumerate_all_services dispatches enumerate_services(active=True) when the checkbox is checked.

        Falsified by: hard-coding the ``active`` kwarg or ignoring the checkbox state.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(system_tab, "_bridge", bridge)
        cast("QCheckBox", _get_private(system_tab, "_svc_active_only")).setChecked(True)

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)

        _invoke(system_tab, "_on_enumerate_all_services")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called"
        _assert_bridge_call(dispatch_args[0], bridge, "enumerate_services", {"active": True})

    def test_on_enumerate_all_services_active_only_false(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_enumerate_all_services dispatches enumerate_services(active=False) when the checkbox is unchecked.

        Falsified by: hard-coding the ``active`` kwarg to True regardless of the checkbox.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(system_tab, "_bridge", bridge)
        cast("QCheckBox", _get_private(system_tab, "_svc_active_only")).setChecked(False)

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)

        _invoke(system_tab, "_on_enumerate_all_services")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called"
        _assert_bridge_call(dispatch_args[0], bridge, "enumerate_services", {"active": False})


class TestSystemTabMitigationPolicyWiringL3:
    """SystemTab's mitigation-policy buttons invoke the flat/extension policy bridge methods."""

    def test_on_mitigation_summary_dispatches_with_attached_pid(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_mitigation_summary dispatches bridge.get_mitigation_policy with the attached pid.

        Falsified by: rewiring Summary Policy away from ``_on_mitigation_summary``
        or dispatching a different policy method.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(system_tab, "_bridge", bridge)
        system_tab.set_attached_pid(2468)

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)

        _invoke(system_tab, "_on_mitigation_summary")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called"
        _assert_bridge_call(dispatch_args[0], bridge, "get_mitigation_policy", {"pid": 2468})

    def test_on_extension_policy_dispatches_with_attached_pid(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_extension_policy dispatches bridge.get_extension_policy with the attached pid.

        Falsified by: rewiring Extension Policy away from ``_on_extension_policy``
        or dispatching get_mitigation_policy instead.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(system_tab, "_bridge", bridge)
        system_tab.set_attached_pid(1357)

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)

        _invoke(system_tab, "_on_extension_policy")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called"
        _assert_bridge_call(dispatch_args[0], bridge, "get_extension_policy", {"pid": 1357})
        assert "get_mitigation_policy" not in [call.code.co_name for call in dispatch_args]


class TestSystemTabReadRegistryTypedWiringL3:
    """SystemTab's Read (Typed) button invokes ProcessBridge.read_registry."""

    def test_on_read_registry_typed_dispatches_with_hive_key_and_value(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_read_registry_typed dispatches bridge.read_registry with the hive, key path, and value name.

        Falsified by: rewiring Read (Typed) away from ``_on_read_registry_typed``
        or reading the wrong hive/key/value widgets.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(system_tab, "_bridge", bridge)
        cast("QComboBox", _get_private(system_tab, "_reg_hive")).setCurrentText("HKCU")
        cast("QLineEdit", _get_private(system_tab, "_reg_typed_key")).setText(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        cast("QLineEdit", _get_private(system_tab, "_reg_typed_value")).setText("ProductName")

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)

        _invoke(system_tab, "_on_read_registry_typed")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called with hive/key/value present"
        _assert_bridge_call(
            dispatch_args[0],
            bridge,
            "read_registry",
            {"hive": "HKCU", "key_path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "value_name": "ProductName"},
        )

    def test_on_read_registry_typed_requires_key_and_value(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_read_registry_typed skips dispatch and warns when the value name is blank.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _set_private(system_tab, "_bridge", ProcessBridge())
        cast("QComboBox", _get_private(system_tab, "_reg_hive")).setCurrentText("HKLM")
        cast("QLineEdit", _get_private(system_tab, "_reg_typed_key")).setText(r"SOFTWARE\Microsoft")
        cast("QLineEdit", _get_private(system_tab, "_reg_typed_value")).setText("")

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)
        warning_calls = _capture_warnings(monkeypatch)

        _invoke(system_tab, "_on_read_registry_typed")

        assert dispatch_args == [], "read_registry must not be dispatched with a blank value name"
        assert warning_calls, "_on_read_registry_typed must warn when key/value are missing"


class TestSystemTabEnumerateSystemProcessesWiringL3:
    """SystemTab's Enumerate button invokes ProcessBridge.enumerate_system_processes."""

    def test_on_enumerate_system_processes_dispatches_with_no_arguments(
        self,
        system_tab: SystemTab,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_on_enumerate_system_processes dispatches bridge.enumerate_system_processes with no arguments.

        Falsified by: rewiring Enumerate away from ``_on_enumerate_system_processes``
        or passing spurious arguments to the system-wide enumeration.

        Args:
            system_tab: SystemTab fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = ProcessBridge()
        _set_private(system_tab, "_bridge", bridge)

        dispatch_args = _intercept_dispatch(monkeypatch, _system_tab_mod)

        _invoke(system_tab, "_on_enumerate_system_processes")

        assert len(dispatch_args) == 1, "run_bridge_coroutine_logged must be called"
        _assert_bridge_call(dispatch_args[0], bridge, "enumerate_system_processes", {})
