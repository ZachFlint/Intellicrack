# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the input-validation, error and result-rendering paths of the Frida instrumentation widgets.

Every test drives a real widget from ``intellicrack.ui.panels.frida_instrumentation_tab``. Button handlers that reach the bridge are run
through the real asynchronous dispatch against a genuine, unattached ``FridaBridge``: the bridge itself refuses the request with its own
``ToolError`` ("not attached to a process"), which travels through the real worker thread and comes back to the widget's error handler.
Success handlers are fed the payload shapes that ``FridaBridge`` returns (``bool``, ``int``, ``str``, ``list[str]``, ``None``). No test
attaches to a process.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest
from PyQt6.QtWidgets import QComboBox, QLabel, QLineEdit, QPushButton, QSpinBox, QTableWidget, QTableWidgetItem, QWidget

from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.core.types import SymbolInfo
from intellicrack.ui.panels import frida_instrumentation_tab as tab_module
from intellicrack.ui.panels.async_bridge import bridge_workers_for, drain_bridge_workers_for
from intellicrack.ui.panels.frida_instrumentation_tab import (
    InterceptorLifecycleControls,
    MemoryPatchStringControls,
    ScriptMessagingControls,
    StalkerCallProbeControls,
    StalkerConfigControls,
    SymbolLookupControls,
    SystemFunctionCallControls,
    TypedMemoryAccessControls,
)


if TYPE_CHECKING:
    from collections.abc import Callable, Generator

    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")

_WAIT_MS: int = 20_000
_NOT_ATTACHED: str = "not attached to a process"
_NO_BRIDGE: str = "No bridge available"


def priv[T](obj: object, name: str, typ: type[T]) -> T:
    """Read a private attribute with a known static type.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name, including its leading underscore.
        typ: Static type of the attribute, used only for typing.

    Returns:
        T: The attribute value.
    """
    del typ
    value: T = getattr(obj, name)
    return value


def method(obj: object, name: str) -> Callable[..., object]:
    """Look up a (possibly private) method or function by name.

    Args:
        obj: Object, class or module that owns the callable.
        name: Attribute name.

    Returns:
        Callable[..., object]: The callable.
    """
    return cast("Callable[..., object]", getattr(obj, name))


def _managed[W: QWidget](qtbot: QtBot, widget: W) -> Generator[W]:
    """Own a widget for one test and join the workers it dispatched on teardown.

    Args:
        qtbot: pytest-qt fixture that closes the widget after the test.
        widget: Widget to hand to the test.

    Yields:
        W: The same widget.
    """
    qtbot.addWidget(widget)
    try:
        yield widget
    finally:
        drain_bridge_workers_for(widget)


def _dispatch(qtbot: QtBot, button: QPushButton) -> None:
    """Click a button that starts a bridge call and wait for the call to come back.

    The handler disables the button while the call is in flight and the result handler enables it again, so the wait ends only after the
    real worker has delivered its result or error.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        button: Button whose handler dispatches the call.
    """
    button.click()
    assert not button.isEnabled(), "the handler must disable the button while the bridge call is in flight"
    qtbot.waitUntil(button.isEnabled, timeout=_WAIT_MS)


def _text(widget: QWidget, name: str) -> str:
    """Read the text of a label owned by a widget.

    Args:
        widget: Widget that owns the label.
        name: Attribute name of the label.

    Returns:
        str: The label's current text.
    """
    return priv(widget, name, QLabel).text()


def _set_text(widget: QWidget, name: str, text: str) -> None:
    """Type text into a line edit owned by a widget.

    Args:
        widget: Widget that owns the line edit.
        name: Attribute name of the line edit.
        text: Text to enter.
    """
    priv(widget, name, QLineEdit).setText(text)


def _select_type(combo: QComboBox, text: str) -> None:
    """Select an existing entry of a combo box by its text.

    Args:
        combo: Combo box to change.
        text: Text of the entry to select.
    """
    index = combo.findText(text)
    assert index >= 0
    combo.setCurrentIndex(index)


@pytest.fixture
def bridge() -> FridaBridge:
    """Provide a real bridge that is not attached to any process.

    Returns:
        FridaBridge: A freshly constructed, unattached bridge.
    """
    return FridaBridge()


@pytest.fixture
def interceptor(qtbot: QtBot) -> Generator[InterceptorLifecycleControls]:
    """Provide the Interceptor revert/flush controls.

    Args:
        qtbot: pytest-qt fixture that owns the widget.

    Yields:
        InterceptorLifecycleControls: The widget.
    """
    yield from _managed(qtbot, InterceptorLifecycleControls())


@pytest.fixture
def probes(qtbot: QtBot) -> Generator[StalkerCallProbeControls]:
    """Provide the Stalker call-probe controls.

    Args:
        qtbot: pytest-qt fixture that owns the widget.

    Yields:
        StalkerCallProbeControls: The widget.
    """
    yield from _managed(qtbot, StalkerCallProbeControls())


@pytest.fixture
def patcher(qtbot: QtBot) -> Generator[MemoryPatchStringControls]:
    """Provide the code-patch and string-allocation controls.

    Args:
        qtbot: pytest-qt fixture that owns the widget.

    Yields:
        MemoryPatchStringControls: The widget.
    """
    yield from _managed(qtbot, MemoryPatchStringControls())


@pytest.fixture
def typed(qtbot: QtBot) -> Generator[TypedMemoryAccessControls]:
    """Provide the typed memory read/write controls.

    Args:
        qtbot: pytest-qt fixture that owns the widget.

    Yields:
        TypedMemoryAccessControls: The widget.
    """
    yield from _managed(qtbot, TypedMemoryAccessControls())


@pytest.fixture
def symbols(qtbot: QtBot) -> Generator[SymbolLookupControls]:
    """Provide the symbol and module lookup controls.

    Args:
        qtbot: pytest-qt fixture that owns the widget.

    Yields:
        SymbolLookupControls: The widget.
    """
    yield from _managed(qtbot, SymbolLookupControls())


@pytest.fixture
def syscall(qtbot: QtBot) -> Generator[SystemFunctionCallControls]:
    """Provide the system-function call controls.

    Args:
        qtbot: pytest-qt fixture that owns the widget.

    Yields:
        SystemFunctionCallControls: The widget.
    """
    yield from _managed(qtbot, SystemFunctionCallControls())


@pytest.fixture
def stalker(qtbot: QtBot) -> Generator[StalkerConfigControls]:
    """Provide the Stalker configuration controls.

    Args:
        qtbot: pytest-qt fixture that owns the widget.

    Yields:
        StalkerConfigControls: The widget.
    """
    yield from _managed(qtbot, StalkerConfigControls())


@pytest.fixture
def messaging(qtbot: QtBot) -> Generator[ScriptMessagingControls]:
    """Provide the script messaging controls.

    Args:
        qtbot: pytest-qt fixture that owns the widget.

    Yields:
        ScriptMessagingControls: The widget.
    """
    yield from _managed(qtbot, ScriptMessagingControls())


@pytest.mark.parametrize(
    ("text", "expected"),
    [("", None), ("   ", None), ("\t", None), (" 0x401000 ", 0x401000), ("7FFE0000", 0x7FFE0000), ("zz", None)],
)
def test_parse_hex_address_blank_is_none_and_hex_is_parsed(text: str, expected: int | None) -> None:
    """A blank address is rejected without a parse attempt; hex text is read as base 16.

    Args:
        text: Text typed into an address field.
        expected: Address the helper must return.
    """
    assert method(tab_module, "_parse_hex_address")(text) == expected


@pytest.mark.parametrize(
    ("file_name", "line_number", "expected"),
    [("kernel32.c", None, "kernel32.c"), ("kernel32.c", 7, "kernel32.c:7"), (None, 7, ""), ("", 7, "")],
)
def test_format_symbol_source_variants(file_name: str | None, line_number: int | None, expected: str) -> None:
    """A source location renders as file and line, the bare file, or nothing.

    Args:
        file_name: Resolved source file name, if any.
        line_number: Resolved source line, if any.
        expected: Text the helper must return.
    """
    symbol = SymbolInfo(name="f", address=0x1000, module_name="m.dll", file_name=file_name, line_number=line_number)
    assert method(tab_module, "_format_symbol_source")(symbol) == expected


def test_symbol_without_line_number_shows_only_the_file_in_the_table(symbols: SymbolLookupControls) -> None:
    """A symbol resolved to a file without a line number fills the Source column with the bare file name.

    Args:
        symbols: Symbol lookup widget.
    """
    symbol = SymbolInfo(name="Alpha", address=0x2000, module_name="a.dll", file_name="alpha.c", line_number=None)
    method(symbols, "_populate_symbols_from_module")([symbol])
    table = priv(symbols, "_symbols_table", QTableWidget)
    source_item = table.item(0, 3)
    assert source_item is not None
    assert source_item.text() == "alpha.c"


def test_elided_result_text_is_left_whole_when_the_label_has_no_width(qtbot: QtBot) -> None:
    """A label with zero width cannot elide, so it shows the full text and carries it as its tooltip.

    Args:
        qtbot: pytest-qt fixture that owns the label.
    """
    label = QLabel()
    qtbot.addWidget(label)
    label.setFixedWidth(0)
    assert label.width() == 0
    full_text = "0x7FFFFFFFFFFFFFFF"
    method(tab_module, "_set_elided_result_text")(label, full_text)
    assert label.text() == full_text
    assert label.toolTip() == full_text


@pytest.mark.parametrize("button_name", ["_revert_btn", "_flush_btn"])
def test_interceptor_buttons_without_bridge_report_it(interceptor: InterceptorLifecycleControls, button_name: str) -> None:
    """Revert and Flush with no bridge set report it and start no bridge call.

    Args:
        interceptor: Interceptor lifecycle widget.
        button_name: Attribute name of the button to click.
    """
    _set_text(interceptor, "_revert_target_input", "0x401000")
    button = priv(interceptor, button_name, QPushButton)
    button.click()
    assert _text(interceptor, "_status_label") == _NO_BRIDGE
    assert button.isEnabled()
    assert bridge_workers_for(interceptor) == []


def test_interceptor_revert_requires_a_target(interceptor: InterceptorLifecycleControls, bridge: FridaBridge) -> None:
    """Revert with an empty target asks for one and starts no bridge call.

    Args:
        interceptor: Interceptor lifecycle widget.
        bridge: Unattached bridge.
    """
    interceptor.set_bridge(bridge)
    _set_text(interceptor, "_revert_target_input", "   ")
    button = priv(interceptor, "_revert_btn", QPushButton)
    button.click()
    assert _text(interceptor, "_status_label") == "Enter a target"
    assert button.isEnabled()
    assert bridge_workers_for(interceptor) == []


def test_interceptor_revert_failure_is_reported_and_button_restored(
    qtbot: QtBot,
    interceptor: InterceptorLifecycleControls,
    bridge: FridaBridge,
) -> None:
    """A bridge that refuses the revert has its error shown and the Revert button enabled again.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        interceptor: Interceptor lifecycle widget.
        bridge: Unattached bridge.
    """
    interceptor.set_bridge(bridge)
    _set_text(interceptor, "_revert_target_input", "0x401000")
    _dispatch(qtbot, priv(interceptor, "_revert_btn", QPushButton))
    assert _text(interceptor, "_status_label") == f"Revert failed: {_NOT_ATTACHED}"


def test_interceptor_flush_failure_is_reported_and_button_restored(
    qtbot: QtBot,
    interceptor: InterceptorLifecycleControls,
    bridge: FridaBridge,
) -> None:
    """A bridge that refuses the flush has its error shown and the Flush button enabled again.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        interceptor: Interceptor lifecycle widget.
        bridge: Unattached bridge.
    """
    interceptor.set_bridge(bridge)
    _dispatch(qtbot, priv(interceptor, "_flush_btn", QPushButton))
    assert _text(interceptor, "_status_label") == f"Flush failed: {_NOT_ATTACHED}"


@pytest.mark.parametrize("button_name", ["_probe_add_btn", "_probe_remove_btn"])
def test_probe_buttons_without_bridge_report_it(probes: StalkerCallProbeControls, button_name: str) -> None:
    """Add Probe and Remove Selected with no bridge set report it and start no bridge call.

    Args:
        probes: Call-probe widget.
        button_name: Attribute name of the button to click.
    """
    button = priv(probes, button_name, QPushButton)
    button.click()
    assert _text(probes, "_status_label") == _NO_BRIDGE
    assert button.isEnabled()
    assert bridge_workers_for(probes) == []


@pytest.mark.parametrize(
    ("address", "callback", "expected"),
    [("", "send(1);", "Invalid address"), ("not-hex", "send(1);", "Invalid address"), ("0x401000", "   ", "Enter callback JS code")],
)
def test_probe_add_rejects_bad_input(
    probes: StalkerCallProbeControls,
    bridge: FridaBridge,
    address: str,
    callback: str,
    expected: str,
) -> None:
    """Add Probe refuses a bad address or an empty callback before any bridge call and adds no row.

    Args:
        probes: Call-probe widget.
        bridge: Unattached bridge.
        address: Text typed into the address field.
        callback: Text typed into the callback field.
        expected: Status the widget must show.
    """
    probes.set_bridge(bridge)
    _set_text(probes, "_probe_addr_input", address)
    _set_text(probes, "_probe_callback_input", callback)
    button = priv(probes, "_probe_add_btn", QPushButton)
    button.click()
    assert _text(probes, "_status_label") == expected
    assert button.isEnabled()
    assert priv(probes, "_probe_table", QTableWidget).rowCount() == 0
    assert bridge_workers_for(probes) == []


def test_probe_add_failure_is_reported_and_adds_no_row(
    qtbot: QtBot,
    probes: StalkerCallProbeControls,
    bridge: FridaBridge,
) -> None:
    """A bridge that refuses the probe has its error shown, the button restored and the table untouched.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        probes: Call-probe widget.
        bridge: Unattached bridge.
    """
    probes.set_bridge(bridge)
    _set_text(probes, "_probe_addr_input", "0x401000")
    _set_text(probes, "_probe_callback_input", "send(1);")
    _dispatch(qtbot, priv(probes, "_probe_add_btn", QPushButton))
    assert _text(probes, "_status_label") == f"Add probe failed: {_NOT_ATTACHED}"
    assert priv(probes, "_probe_table", QTableWidget).rowCount() == 0
    assert priv(probes, "_probe_ids", list[str]) == []


@pytest.mark.parametrize("selection", ["none", "stray"])
def test_probe_remove_without_a_matching_selection_asks_for_one(
    probes: StalkerCallProbeControls,
    bridge: FridaBridge,
    selection: str,
) -> None:
    """Remove Selected with no selected row, or a row that has no probe ID behind it, asks for a selection.

    Args:
        probes: Call-probe widget.
        bridge: Unattached bridge.
        selection: ``none`` for an empty selection, ``stray`` to select a table row that has no tracked probe ID.
    """
    probes.set_bridge(bridge)
    table = priv(probes, "_probe_table", QTableWidget)
    if selection == "stray":
        table.insertRow(0)
        table.setItem(0, 0, QTableWidgetItem("orphan"))
        table.setCurrentCell(0, 0)
        assert table.currentRow() == 0
    button = priv(probes, "_probe_remove_btn", QPushButton)
    button.click()
    assert _text(probes, "_status_label") == "Select a probe to remove"
    assert button.isEnabled()
    assert bridge_workers_for(probes) == []


def test_probe_remove_of_unknown_probe_keeps_the_row_and_says_so(
    qtbot: QtBot,
    probes: StalkerCallProbeControls,
    bridge: FridaBridge,
) -> None:
    """When the bridge reports the probe ID as unknown, the row stays and the status says the probe was not found.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        probes: Call-probe widget.
        bridge: Unattached bridge that tracks no probes.
    """
    probes.set_bridge(bridge)
    table = priv(probes, "_probe_table", QTableWidget)
    table.insertRow(0)
    table.setItem(0, 0, QTableWidgetItem("deadbeef"))
    table.setItem(0, 1, QTableWidgetItem("0x401000"))
    priv(probes, "_probe_ids", list[str]).append("deadbeef")
    table.setCurrentCell(0, 0)
    _dispatch(qtbot, priv(probes, "_probe_remove_btn", QPushButton))
    assert _text(probes, "_status_label") == "Probe deadbeef was not found"
    assert table.rowCount() == 1
    assert priv(probes, "_probe_ids", list[str]) == ["deadbeef"]


def test_probe_remove_failure_is_reported_and_button_restored(probes: StalkerCallProbeControls) -> None:
    """A failed probe removal shows the error and enables Remove Selected again.

    Args:
        probes: Call-probe widget.
    """
    button = priv(probes, "_probe_remove_btn", QPushButton)
    button.setEnabled(False)
    method(probes, "_on_remove_call_probe_error")("cafe1234", RuntimeError("target went away"))
    assert button.isEnabled()
    assert _text(probes, "_status_label") == "Remove probe failed: target went away"


def test_patch_and_allocate_without_bridge_report_it(patcher: MemoryPatchStringControls) -> None:
    """Patch Code and Allocate with no bridge set report it in their own labels and start no bridge call.

    Args:
        patcher: Patch and allocate widget.
    """
    priv(patcher, "_patch_btn", QPushButton).click()
    assert _text(patcher, "_patch_status_label") == _NO_BRIDGE
    priv(patcher, "_alloc_string_btn", QPushButton).click()
    assert _text(patcher, "_alloc_string_result") == _NO_BRIDGE
    assert bridge_workers_for(patcher) == []


@pytest.mark.parametrize(
    ("address", "data", "expected"),
    [
        ("", "90 90", "Invalid address"),
        ("xyz", "90 90", "Invalid address"),
        ("0x401000", "   ", "Enter bytes to patch"),
        ("0x401000", "zz", "Invalid hex data"),
        ("0x401000", "9", "Invalid hex data"),
    ],
)
def test_patch_code_rejects_bad_input(
    patcher: MemoryPatchStringControls,
    bridge: FridaBridge,
    address: str,
    data: str,
    expected: str,
) -> None:
    """Patch Code refuses a bad address, empty bytes or malformed hex before any bridge call.

    Args:
        patcher: Patch and allocate widget.
        bridge: Unattached bridge.
        address: Text typed into the address field.
        data: Text typed into the bytes field.
        expected: Status the widget must show.
    """
    patcher.set_bridge(bridge)
    _set_text(patcher, "_patch_addr_input", address)
    _set_text(patcher, "_patch_data_input", data)
    button = priv(patcher, "_patch_btn", QPushButton)
    button.click()
    assert _text(patcher, "_patch_status_label") == expected
    assert button.isEnabled()
    assert bridge_workers_for(patcher) == []


def test_patch_code_failure_is_reported_and_button_restored(
    qtbot: QtBot,
    patcher: MemoryPatchStringControls,
    bridge: FridaBridge,
) -> None:
    """A bridge that refuses the patch has its error shown and the Patch Code button enabled again.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        patcher: Patch and allocate widget.
        bridge: Unattached bridge.
    """
    patcher.set_bridge(bridge)
    _set_text(patcher, "_patch_addr_input", "0x401000")
    _set_text(patcher, "_patch_data_input", "90 90")
    _dispatch(qtbot, priv(patcher, "_patch_btn", QPushButton))
    assert _text(patcher, "_patch_status_label") == f"Patch failed: {_NOT_ATTACHED}"


def test_allocate_string_requires_a_value(patcher: MemoryPatchStringControls, bridge: FridaBridge) -> None:
    """Allocate with an empty value asks for one and starts no bridge call.

    Args:
        patcher: Patch and allocate widget.
        bridge: Unattached bridge.
    """
    patcher.set_bridge(bridge)
    button = priv(patcher, "_alloc_string_btn", QPushButton)
    button.click()
    assert _text(patcher, "_alloc_string_result") == "Enter a string value"
    assert button.isEnabled()
    assert bridge_workers_for(patcher) == []


def test_allocate_string_failure_is_reported_and_button_restored(
    qtbot: QtBot,
    patcher: MemoryPatchStringControls,
    bridge: FridaBridge,
) -> None:
    """A bridge that refuses the allocation has its error shown and the Allocate button enabled again.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        patcher: Patch and allocate widget.
        bridge: Unattached bridge.
    """
    patcher.set_bridge(bridge)
    _set_text(patcher, "_alloc_string_input", "hello world")
    _dispatch(qtbot, priv(patcher, "_alloc_string_btn", QPushButton))
    assert _text(patcher, "_alloc_string_result") == f"Allocate failed: {_NOT_ATTACHED}"


@pytest.mark.parametrize("button_name", ["_typed_read_btn", "_typed_write_btn"])
def test_typed_buttons_without_bridge_report_it(typed: TypedMemoryAccessControls, button_name: str) -> None:
    """Read and Write with no bridge set report it and start no bridge call.

    Args:
        typed: Typed memory widget.
        button_name: Attribute name of the button to click.
    """
    button = priv(typed, button_name, QPushButton)
    button.click()
    assert _text(typed, "_typed_status_label") == _NO_BRIDGE
    assert button.isEnabled()
    assert bridge_workers_for(typed) == []


@pytest.mark.parametrize("button_name", ["_typed_read_btn", "_typed_write_btn"])
@pytest.mark.parametrize("address", ["", "   ", "0xZZ"])
def test_typed_buttons_reject_a_bad_address(
    typed: TypedMemoryAccessControls,
    bridge: FridaBridge,
    button_name: str,
    address: str,
) -> None:
    """Read and Write refuse a blank or malformed address before any bridge call.

    Args:
        typed: Typed memory widget.
        bridge: Unattached bridge.
        button_name: Attribute name of the button to click.
        address: Text typed into the address field.
    """
    typed.set_bridge(bridge)
    _set_text(typed, "_typed_addr_input", address)
    button = priv(typed, button_name, QPushButton)
    button.click()
    assert _text(typed, "_typed_status_label") == "Invalid address"
    assert button.isEnabled()
    assert bridge_workers_for(typed) == []


def test_typed_read_failure_is_reported_and_button_restored(
    qtbot: QtBot,
    typed: TypedMemoryAccessControls,
    bridge: FridaBridge,
) -> None:
    """A bridge that refuses the read has its error shown and the Read button enabled again.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        typed: Typed memory widget.
        bridge: Unattached bridge.
    """
    typed.set_bridge(bridge)
    _set_text(typed, "_typed_addr_input", "0x401000")
    _select_type(priv(typed, "_typed_type_combo", QComboBox), "u16")
    _dispatch(qtbot, priv(typed, "_typed_read_btn", QPushButton))
    assert _text(typed, "_typed_status_label") == f"Read failed: {_NOT_ATTACHED}"
    assert not _text(typed, "_typed_read_result_label")


@pytest.mark.parametrize(
    ("result", "expected"),
    [(0x5A4D, "23117"), (None, "None"), ("MZ", "MZ"), (3.5, "3.5")],
)
def test_typed_read_result_is_rendered_as_text(typed: TypedMemoryAccessControls, result: object, expected: str) -> None:
    """A decoded value of any type the bridge returns is shown as its text and the Read button is enabled again.

    Args:
        typed: Typed memory widget.
        result: Value as returned by ``FridaBridge.read_typed_value``.
        expected: Text the value label must show.
    """
    button = priv(typed, "_typed_read_btn", QPushButton)
    button.setEnabled(False)
    method(typed, "_on_read_typed_value_done")(result)
    assert button.isEnabled()
    assert _text(typed, "_typed_read_result_label") == expected
    assert _text(typed, "_typed_status_label") == "Read complete"


def test_typed_write_refuses_cstring(typed: TypedMemoryAccessControls, bridge: FridaBridge) -> None:
    """The cstring type is read-only, so Write explains that and starts no bridge call.

    Args:
        typed: Typed memory widget.
        bridge: Unattached bridge.
    """
    typed.set_bridge(bridge)
    _set_text(typed, "_typed_addr_input", "0x401000")
    _select_type(priv(typed, "_typed_type_combo", QComboBox), "cstring")
    _set_text(typed, "_typed_write_value_input", "text")
    button = priv(typed, "_typed_write_btn", QPushButton)
    button.click()
    assert _text(typed, "_typed_status_label") == "cstring is read-only; use utf8 to write a string"
    assert button.isEnabled()
    assert bridge_workers_for(typed) == []


@pytest.mark.parametrize(
    ("value_type", "value_text"),
    [("u32", "abc"), ("s8", "1.5"), ("pointer", ""), ("float", "abc"), ("double", "")],
)
def test_typed_write_rejects_a_value_that_does_not_fit_the_type(
    typed: TypedMemoryAccessControls,
    bridge: FridaBridge,
    value_type: str,
    value_text: str,
) -> None:
    """Write refuses text that cannot be parsed as the selected type before any bridge call.

    Args:
        typed: Typed memory widget.
        bridge: Unattached bridge.
        value_type: Type selected in the combo box.
        value_text: Text typed into the value field.
    """
    typed.set_bridge(bridge)
    _set_text(typed, "_typed_addr_input", "0x401000")
    _select_type(priv(typed, "_typed_type_combo", QComboBox), value_type)
    _set_text(typed, "_typed_write_value_input", value_text)
    button = priv(typed, "_typed_write_btn", QPushButton)
    button.click()
    assert _text(typed, "_typed_status_label") == f"Invalid value for type {value_type}"
    assert button.isEnabled()
    assert bridge_workers_for(typed) == []


@pytest.mark.parametrize(
    ("value_type", "value_text"),
    [("u32", "0x10"), ("float", "3.5"), ("utf8", "text")],
)
def test_typed_write_failure_is_reported_and_button_restored(
    qtbot: QtBot,
    typed: TypedMemoryAccessControls,
    bridge: FridaBridge,
    value_type: str,
    value_text: str,
) -> None:
    """A bridge that refuses the write has its error shown and the Write button enabled again.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        typed: Typed memory widget.
        bridge: Unattached bridge.
        value_type: Type selected in the combo box.
        value_text: Text typed into the value field.
    """
    typed.set_bridge(bridge)
    _set_text(typed, "_typed_addr_input", "0x401000")
    _select_type(priv(typed, "_typed_type_combo", QComboBox), value_type)
    _set_text(typed, "_typed_write_value_input", value_text)
    _dispatch(qtbot, priv(typed, "_typed_write_btn", QPushButton))
    assert _text(typed, "_typed_status_label") == f"Write failed: {_NOT_ATTACHED}"


@pytest.mark.parametrize(("result", "expected"), [(True, "Write complete"), (False, "Write failed")])
def test_typed_write_result_is_reported(typed: TypedMemoryAccessControls, result: object, expected: str) -> None:
    """The bridge's success flag decides the write status and the Write button is enabled again.

    Args:
        typed: Typed memory widget.
        result: Flag as returned by ``FridaBridge.write_typed_value``.
        expected: Status the widget must show.
    """
    button = priv(typed, "_typed_write_btn", QPushButton)
    button.setEnabled(False)
    method(typed, "_on_write_typed_value_done")(result)
    assert button.isEnabled()
    assert _text(typed, "_typed_status_label") == expected


@pytest.mark.parametrize(
    ("value_type", "raw_text", "expected"),
    [
        ("float", "3.5", 3.5),
        ("double", "-0.25", -0.25),
        ("utf8", "héllo wörld", "héllo wörld"),
        ("u32", "0x10", 16),
        ("s8", "-5", -5),
        ("pointer", "0x1000", 4096),
        ("u8", "255", 255),
    ],
)
def test_parse_typed_write_text_produces_the_expected_python_type(value_type: str, raw_text: str, expected: object) -> None:
    """Floats parse as float, utf8 stays text, and every other type parses as an integer in any base prefix.

    Args:
        value_type: Selected value type.
        raw_text: Text from the value field.
        expected: Value the parser must return.
    """
    parsed = method(TypedMemoryAccessControls, "_parse_typed_write_text")(value_type, raw_text)
    assert parsed == expected
    assert type(parsed) is type(expected)


@pytest.mark.parametrize(("value_type", "raw_text"), [("float", "abc"), ("double", ""), ("u16", "abc"), ("s64", "2.5")])
def test_parse_typed_write_text_rejects_malformed_numbers(value_type: str, raw_text: str) -> None:
    """Text that is not a number of the selected kind raises ``ValueError``.

    Args:
        value_type: Selected value type.
        raw_text: Text from the value field.
    """
    with pytest.raises(ValueError, match=r"could not convert|invalid literal"):
        method(TypedMemoryAccessControls, "_parse_typed_write_text")(value_type, raw_text)


@pytest.mark.parametrize(
    ("button_name", "label_name"),
    [("_enum_symbols_btn", "_status_label"), ("_find_module_btn", "_reverse_result_label"), ("_find_matching_btn", "_status_label")],
)
def test_symbol_buttons_without_bridge_report_it(symbols: SymbolLookupControls, button_name: str, label_name: str) -> None:
    """Every symbol lookup button with no bridge set reports it in its own label and starts no bridge call.

    Args:
        symbols: Symbol lookup widget.
        button_name: Attribute name of the button to click.
        label_name: Attribute name of the label that shows the outcome.
    """
    button = priv(symbols, button_name, QPushButton)
    button.click()
    assert _text(symbols, label_name) == _NO_BRIDGE
    assert button.isEnabled()
    assert bridge_workers_for(symbols) == []


@pytest.mark.parametrize(
    ("button_name", "input_name", "input_text", "label_name", "expected"),
    [
        ("_enum_symbols_btn", "_enum_module_input", "  ", "_status_label", "Enter a module name"),
        ("_find_matching_btn", "_glob_pattern_input", "", "_status_label", "Enter a glob pattern"),
        ("_find_module_btn", "_reverse_addr_input", "", "_reverse_result_label", "Invalid address"),
        ("_find_module_btn", "_reverse_addr_input", "not-hex", "_reverse_result_label", "Invalid address"),
    ],
)
def test_symbol_lookups_reject_empty_or_malformed_input(
    symbols: SymbolLookupControls,
    bridge: FridaBridge,
    button_name: str,
    input_name: str,
    input_text: str,
    label_name: str,
    expected: str,
) -> None:
    """Each symbol lookup refuses empty or malformed input before any bridge call.

    Args:
        symbols: Symbol lookup widget.
        bridge: Unattached bridge.
        button_name: Attribute name of the button to click.
        input_name: Attribute name of the input to fill.
        input_text: Text typed into the input.
        label_name: Attribute name of the label that shows the outcome.
        expected: Text the label must show.
    """
    symbols.set_bridge(bridge)
    _set_text(symbols, input_name, input_text)
    button = priv(symbols, button_name, QPushButton)
    button.click()
    assert _text(symbols, label_name) == expected
    assert button.isEnabled()
    assert bridge_workers_for(symbols) == []


def test_find_module_by_address_reports_an_unmapped_address(symbols: SymbolLookupControls) -> None:
    """A lookup that finds no module says so and re-enables the button.

    Args:
        symbols: Symbol lookup widget.
    """
    button = priv(symbols, "_find_module_btn", QPushButton)
    button.setEnabled(False)
    method(symbols, "_on_find_module_by_address_done")(None)
    assert button.isEnabled()
    assert _text(symbols, "_reverse_result_label") == "No module found at that address"


@pytest.mark.parametrize(
    ("populate_name", "button_name", "status_name"),
    [
        ("_populate_symbols_from_module", "_enum_symbols_btn", "_status_label"),
        ("_populate_symbols_from_matching", "_find_matching_btn", "_status_label"),
    ],
)
def test_symbol_table_is_cleared_when_the_result_is_not_a_list(
    symbols: SymbolLookupControls,
    populate_name: str,
    button_name: str,
    status_name: str,
) -> None:
    """A result that is not a list empties the table, re-enables the button and reports no count.

    Args:
        symbols: Symbol lookup widget.
        populate_name: Name of the result handler to feed.
        button_name: Attribute name of the button the handler re-enables.
        status_name: Attribute name of the status label.
    """
    method(symbols, "_populate_symbols_from_module")(
        [SymbolInfo(name="Old", address=0x10, module_name="old.dll", file_name=None, line_number=None)],
    )
    table = priv(symbols, "_symbols_table", QTableWidget)
    assert table.rowCount() == 1
    status_before = _text(symbols, status_name)
    button = priv(symbols, button_name, QPushButton)
    button.setEnabled(False)
    method(symbols, populate_name)(None)
    assert table.rowCount() == 0
    assert button.isEnabled()
    assert _text(symbols, status_name) == status_before


def test_system_call_without_bridge_reports_it(syscall: SystemFunctionCallControls) -> None:
    """Call with no bridge set reports it and starts no bridge call.

    Args:
        syscall: System function call widget.
    """
    button = priv(syscall, "_syscall_call_btn", QPushButton)
    button.click()
    assert _text(syscall, "_status_label") == _NO_BRIDGE
    assert button.isEnabled()
    assert bridge_workers_for(syscall) == []


@pytest.mark.parametrize(
    ("address", "args", "expected"),
    [
        ("", "", "Invalid address"),
        ("qq", "1", "Invalid address"),
        ("0x401000", "1, x", "Invalid arguments"),
        ("0x401000", "1,,2", "Invalid arguments"),
    ],
)
def test_system_call_rejects_bad_address_or_arguments(
    syscall: SystemFunctionCallControls,
    bridge: FridaBridge,
    address: str,
    args: str,
    expected: str,
) -> None:
    """Call refuses a bad address or non-integer arguments before any bridge call.

    Args:
        syscall: System function call widget.
        bridge: Unattached bridge.
        address: Text typed into the address field.
        args: Text typed into the arguments field.
        expected: Status the widget must show.
    """
    syscall.set_bridge(bridge)
    _set_text(syscall, "_syscall_addr_input", address)
    _set_text(syscall, "_syscall_args_input", args)
    button = priv(syscall, "_syscall_call_btn", QPushButton)
    button.click()
    assert _text(syscall, "_status_label") == expected
    assert button.isEnabled()
    assert bridge_workers_for(syscall) == []


@pytest.mark.parametrize("args", ["", "1, 0x2"])
def test_system_call_failure_is_reported_with_or_without_arguments(
    qtbot: QtBot,
    syscall: SystemFunctionCallControls,
    bridge: FridaBridge,
    args: str,
) -> None:
    """A bridge that refuses the call has its error shown and the Call button enabled again.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        syscall: System function call widget.
        bridge: Unattached bridge.
        args: Text typed into the arguments field.
    """
    syscall.set_bridge(bridge)
    _set_text(syscall, "_syscall_addr_input", "0x401000")
    _set_text(syscall, "_syscall_args_input", args)
    _dispatch(qtbot, priv(syscall, "_syscall_call_btn", QPushButton))
    assert _text(syscall, "_status_label") == f"Call failed: {_NOT_ATTACHED}"


@pytest.mark.parametrize("button_name", ["_exclude_btn", "_invalidate_btn", "_gc_btn", "_set_threshold_btn"])
def test_stalker_config_buttons_without_bridge_report_it(stalker: StalkerConfigControls, button_name: str) -> None:
    """Every Stalker configuration button with no bridge set reports it and starts no bridge call.

    Args:
        stalker: Stalker configuration widget.
        button_name: Attribute name of the button to click.
    """
    button = priv(stalker, button_name, QPushButton)
    button.click()
    assert _text(stalker, "_status_label") == _NO_BRIDGE
    assert button.isEnabled()
    assert bridge_workers_for(stalker) == []


@pytest.mark.parametrize(
    ("base", "size", "expected"),
    [
        ("", "4096", "Invalid base address"),
        ("nope", "4096", "Invalid base address"),
        ("0x401000", "", "Invalid size"),
        ("0x401000", "big", "Invalid size"),
    ],
)
def test_stalker_exclude_rejects_bad_input(
    stalker: StalkerConfigControls,
    bridge: FridaBridge,
    base: str,
    size: str,
    expected: str,
) -> None:
    """Exclude Range refuses a bad base address or size before any bridge call.

    Args:
        stalker: Stalker configuration widget.
        bridge: Unattached bridge.
        base: Text typed into the base field.
        size: Text typed into the size field.
        expected: Status the widget must show.
    """
    stalker.set_bridge(bridge)
    _set_text(stalker, "_exclude_base_input", base)
    _set_text(stalker, "_exclude_size_input", size)
    button = priv(stalker, "_exclude_btn", QPushButton)
    button.click()
    assert _text(stalker, "_status_label") == expected
    assert button.isEnabled()
    assert bridge_workers_for(stalker) == []


def test_stalker_exclude_failure_is_reported_and_button_restored(
    qtbot: QtBot,
    stalker: StalkerConfigControls,
    bridge: FridaBridge,
) -> None:
    """A bridge that refuses the exclusion has its error shown and the button enabled again.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        stalker: Stalker configuration widget.
        bridge: Unattached bridge.
    """
    stalker.set_bridge(bridge)
    _set_text(stalker, "_exclude_base_input", "0x401000")
    _set_text(stalker, "_exclude_size_input", "0x1000")
    _dispatch(qtbot, priv(stalker, "_exclude_btn", QPushButton))
    assert _text(stalker, "_status_label") == f"Exclude range failed: {_NOT_ATTACHED}"


@pytest.mark.parametrize(("result", "expected"), [(True, "Excluded 0xABC000 (size 4096)"), (False, "Exclude reported failure")])
def test_stalker_exclude_result_is_reported(stalker: StalkerConfigControls, result: object, expected: str) -> None:
    """The bridge's success flag decides the exclusion status and the button is enabled again.

    Args:
        stalker: Stalker configuration widget.
        result: Flag as returned by ``FridaBridge.stalker_exclude``.
        expected: Status the widget must show.
    """
    button = priv(stalker, "_exclude_btn", QPushButton)
    button.setEnabled(False)
    method(stalker, "_on_stalker_exclude_done")(0xABC000, 4096, result)
    assert button.isEnabled()
    assert _text(stalker, "_status_label") == expected


@pytest.mark.parametrize(
    ("address", "thread_id", "expected"),
    [("", "", "Invalid address"), ("nope", "", "Invalid address"), ("0x401000", "tid", "Invalid thread ID")],
)
def test_stalker_invalidate_rejects_bad_input(
    stalker: StalkerConfigControls,
    bridge: FridaBridge,
    address: str,
    thread_id: str,
    expected: str,
) -> None:
    """Invalidate refuses a bad address or thread ID before any bridge call.

    Args:
        stalker: Stalker configuration widget.
        bridge: Unattached bridge.
        address: Text typed into the address field.
        thread_id: Text typed into the thread ID field.
        expected: Status the widget must show.
    """
    stalker.set_bridge(bridge)
    _set_text(stalker, "_invalidate_addr_input", address)
    _set_text(stalker, "_invalidate_tid_input", thread_id)
    button = priv(stalker, "_invalidate_btn", QPushButton)
    button.click()
    assert _text(stalker, "_status_label") == expected
    assert button.isEnabled()
    assert bridge_workers_for(stalker) == []


@pytest.mark.parametrize("thread_id", ["", "0x10", "1234"])
def test_stalker_invalidate_failure_is_reported_with_or_without_thread(
    qtbot: QtBot,
    stalker: StalkerConfigControls,
    bridge: FridaBridge,
    thread_id: str,
) -> None:
    """A bridge that refuses the invalidation has its error shown whether or not a thread ID was entered.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        stalker: Stalker configuration widget.
        bridge: Unattached bridge.
        thread_id: Text typed into the thread ID field.
    """
    stalker.set_bridge(bridge)
    _set_text(stalker, "_invalidate_addr_input", "0x401000")
    _set_text(stalker, "_invalidate_tid_input", thread_id)
    _dispatch(qtbot, priv(stalker, "_invalidate_btn", QPushButton))
    assert _text(stalker, "_status_label") == f"Invalidate failed: {_NOT_ATTACHED}"


@pytest.mark.parametrize(("result", "expected"), [(True, "Invalidated 0xDEAD0"), (False, "Invalidate reported failure")])
def test_stalker_invalidate_result_is_reported(stalker: StalkerConfigControls, result: object, expected: str) -> None:
    """The bridge's success flag decides the invalidation status and the button is enabled again.

    Args:
        stalker: Stalker configuration widget.
        result: Flag as returned by ``FridaBridge.stalker_invalidate``.
        expected: Status the widget must show.
    """
    button = priv(stalker, "_invalidate_btn", QPushButton)
    button.setEnabled(False)
    method(stalker, "_on_stalker_invalidate_done")(0xDEAD0, result)
    assert button.isEnabled()
    assert _text(stalker, "_status_label") == expected


def test_stalker_garbage_collect_failure_is_reported_and_button_restored(
    qtbot: QtBot,
    stalker: StalkerConfigControls,
    bridge: FridaBridge,
) -> None:
    """A bridge that refuses garbage collection has its error shown and the button enabled again.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        stalker: Stalker configuration widget.
        bridge: Unattached bridge.
    """
    stalker.set_bridge(bridge)
    _dispatch(qtbot, priv(stalker, "_gc_btn", QPushButton))
    assert _text(stalker, "_status_label") == f"Garbage collect failed: {_NOT_ATTACHED}"


@pytest.mark.parametrize(("result", "expected"), [(True, "Garbage collected"), (False, "Garbage collect reported failure")])
def test_stalker_garbage_collect_result_is_reported(stalker: StalkerConfigControls, result: object, expected: str) -> None:
    """The bridge's success flag decides the garbage-collection status and the button is enabled again.

    Args:
        stalker: Stalker configuration widget.
        result: Flag as returned by ``FridaBridge.stalker_garbage_collect``.
        expected: Status the widget must show.
    """
    button = priv(stalker, "_gc_btn", QPushButton)
    button.setEnabled(False)
    method(stalker, "_on_stalker_garbage_collect_done")(result)
    assert button.isEnabled()
    assert _text(stalker, "_status_label") == expected


def test_stalker_trust_threshold_failure_is_reported_and_button_restored(
    qtbot: QtBot,
    stalker: StalkerConfigControls,
    bridge: FridaBridge,
) -> None:
    """A bridge that refuses the threshold has its error shown and the button enabled again.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        stalker: Stalker configuration widget.
        bridge: Unattached bridge.
    """
    stalker.set_bridge(bridge)
    priv(stalker, "_trust_threshold_spin", QSpinBox).setValue(7)
    _dispatch(qtbot, priv(stalker, "_set_threshold_btn", QPushButton))
    assert _text(stalker, "_status_label") == f"Set trust threshold failed: {_NOT_ATTACHED}"


@pytest.mark.parametrize(("result", "expected"), [(True, "Trust threshold set to 7"), (False, "Set threshold reported failure")])
def test_stalker_trust_threshold_result_is_reported(stalker: StalkerConfigControls, result: object, expected: str) -> None:
    """The bridge's success flag decides the threshold status and the button is enabled again.

    Args:
        stalker: Stalker configuration widget.
        result: Flag as returned by ``FridaBridge.stalker_set_trust_threshold``.
        expected: Status the widget must show.
    """
    button = priv(stalker, "_set_threshold_btn", QPushButton)
    button.setEnabled(False)
    method(stalker, "_on_stalker_set_trust_threshold_done")(7, result)
    assert button.isEnabled()
    assert _text(stalker, "_status_label") == expected


def test_script_id_is_read_stripped(messaging: ScriptMessagingControls) -> None:
    """The script ID the operator typed is returned without surrounding whitespace.

    Args:
        messaging: Script messaging widget.
    """
    _set_text(messaging, "_script_id_input", "  abc123 \t")
    assert method(messaging, "_resolve_script_id")() == "abc123"


@pytest.mark.parametrize("button_name", ["_rpc_call_btn", "_list_exports_btn"])
def test_messaging_buttons_without_bridge_report_it(messaging: ScriptMessagingControls, button_name: str) -> None:
    """RPC Call and List Exports with no bridge set report it and start no bridge call.

    Args:
        messaging: Script messaging widget.
        button_name: Attribute name of the button to click.
    """
    button = priv(messaging, button_name, QPushButton)
    button.click()
    assert _text(messaging, "_status_label") == _NO_BRIDGE
    assert button.isEnabled()
    assert bridge_workers_for(messaging) == []


@pytest.mark.parametrize(
    ("script_id", "method_name", "args", "expected"),
    [
        ("", "ping", "", "Enter a script ID"),
        ("   ", "ping", "", "Enter a script ID"),
        ("s1", "  ", "", "Enter an RPC method name"),
        ("s1", "ping", "[1,", "Args must be a JSON array"),
        ("s1", "ping", '{"a": 1}', "Args must be a JSON array"),
        ("s1", "ping", "5", "Args must be a JSON array"),
    ],
)
def test_rpc_call_rejects_bad_input(
    messaging: ScriptMessagingControls,
    bridge: FridaBridge,
    script_id: str,
    method_name: str,
    args: str,
    expected: str,
) -> None:
    """RPC Call refuses a missing script ID, a missing method or arguments that are not a JSON array before any bridge call.

    Args:
        messaging: Script messaging widget.
        bridge: Unattached bridge.
        script_id: Text typed into the script ID field.
        method_name: Text typed into the method field.
        args: Text typed into the arguments field.
        expected: Status the widget must show.
    """
    messaging.set_bridge(bridge)
    _set_text(messaging, "_script_id_input", script_id)
    _set_text(messaging, "_rpc_method_input", method_name)
    _set_text(messaging, "_rpc_args_input", args)
    button = priv(messaging, "_rpc_call_btn", QPushButton)
    button.click()
    assert _text(messaging, "_status_label") == expected
    assert button.isEnabled()
    assert bridge_workers_for(messaging) == []


@pytest.mark.parametrize("args", ["", '[1, "two", true]'])
def test_rpc_call_failure_is_reported_with_or_without_arguments(
    qtbot: QtBot,
    messaging: ScriptMessagingControls,
    bridge: FridaBridge,
    args: str,
) -> None:
    """A bridge that does not know the script has its error shown and the RPC Call button enabled again.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        messaging: Script messaging widget.
        bridge: Unattached bridge that tracks no scripts.
        args: Text typed into the arguments field.
    """
    messaging.set_bridge(bridge)
    _set_text(messaging, "_script_id_input", "s1")
    _set_text(messaging, "_rpc_method_input", "ping")
    _set_text(messaging, "_rpc_args_input", args)
    _dispatch(qtbot, priv(messaging, "_rpc_call_btn", QPushButton))
    assert _text(messaging, "_status_label") == "RPC call failed: script not found"


@pytest.mark.parametrize("script_id", ["", "  "])
def test_list_exports_requires_a_script_id(messaging: ScriptMessagingControls, bridge: FridaBridge, script_id: str) -> None:
    """List Exports with no script ID asks for one and starts no bridge call.

    Args:
        messaging: Script messaging widget.
        bridge: Unattached bridge.
        script_id: Text typed into the script ID field.
    """
    messaging.set_bridge(bridge)
    _set_text(messaging, "_script_id_input", script_id)
    button = priv(messaging, "_list_exports_btn", QPushButton)
    button.click()
    assert _text(messaging, "_status_label") == "Enter a script ID"
    assert button.isEnabled()
    assert bridge_workers_for(messaging) == []


def test_list_exports_failure_is_reported_and_button_restored(
    qtbot: QtBot,
    messaging: ScriptMessagingControls,
    bridge: FridaBridge,
) -> None:
    """A bridge that does not know the script has its error shown and the List Exports button enabled again.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        messaging: Script messaging widget.
        bridge: Unattached bridge that tracks no scripts.
    """
    messaging.set_bridge(bridge)
    _set_text(messaging, "_script_id_input", "s1")
    _dispatch(qtbot, priv(messaging, "_list_exports_btn", QPushButton))
    assert _text(messaging, "_status_label") == "List exports failed: script not found"


@pytest.mark.parametrize(
    ("result", "expected"),
    [(["alpha", "beta"], "Exports: alpha, beta"), ([], "Exports: (none)"), ("solo", "Exports: solo"), ("", "Exports: (none)")],
)
def test_list_exports_result_is_rendered(messaging: ScriptMessagingControls, result: object, expected: str) -> None:
    """Export names are joined with commas, an empty result reads as none, and the button is enabled again.

    Args:
        messaging: Script messaging widget.
        result: Value as returned by ``FridaBridge.list_rpc_exports``.
        expected: Text the result label must show.
    """
    button = priv(messaging, "_list_exports_btn", QPushButton)
    button.setEnabled(False)
    method(messaging, "_on_list_rpc_exports_done")(result)
    assert button.isEnabled()
    assert _text(messaging, "_rpc_result_label") == expected
