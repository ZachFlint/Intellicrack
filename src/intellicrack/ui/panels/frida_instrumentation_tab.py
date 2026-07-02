# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Instrumentation-control widgets embedded in the Frida panel's Hooks, Stalker, Memory, Symbols, and Advanced sections.

Provides self-contained Qt widgets for the Frida instrumentation primitives that have a real bridge method and tool
definition but historically had no reachable GUI control: ``Interceptor.revert``/``flush`` (hook lifecycle),
``Stalker.addCallProbe``/``removeCallProbe`` (call-probe management), ``Stalker.exclude``/``garbageCollect``/
``invalidate``/``setTrustThreshold`` (Stalker tuning), ``Memory.patchCode`` and the
``Memory.allocUtf8String``/``allocAnsiString``/``allocUtf16String`` family (code patching and string allocation),
``Module.enumerateSymbols``/``Process.findModuleByAddress``/``DebugSymbol.findFunctionsMatching`` (symbol and module
lookups), the ``SystemFunction``-based ``call_system_function`` (errno/``GetLastError`` capture), RPC exports and
raw script messaging (``rpc_call``/``post_message``/``eternalize_script``), and cancellation tokens
(``create_cancellable``/``cancel``). Each widget is driven directly by ``FridaBridge`` methods
(``bridges/frida_bridge.py``) via ``run_bridge_coroutine_logged``.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Final, cast

from PyQt6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_logged
from intellicrack.ui.resources.font_manager import FontManager


if TYPE_CHECKING:
    from intellicrack.bridges.frida_bridge import FridaBridge

_logger = get_logger(__name__)

_PANEL_MARGIN: Final[int] = 0
_PANEL_SPACING: Final[int] = 2
_ADDR_INPUT_MAX_WIDTH: Final[int] = 160
_NATIVE_TYPES: Final[list[str]] = ["pointer", "int", "uint", "void", "float", "double", "int32", "uint32", "int64", "uint64"]
_CALLING_CONVENTIONS: Final[list[str]] = ["default", "sysv", "stdcall", "thiscall", "fastcall", "mscdecl", "win64"]
_STRING_ENCODINGS: Final[list[str]] = ["utf8", "ansi", "utf16"]
_SYMBOL_COLUMNS: Final[list[str]] = ["Name", "Address", "Is Global", "Type"]
_PROBE_COLUMNS: Final[list[str]] = ["Probe ID", "Address"]
_TRUST_THRESHOLD_MIN: Final[int] = -1
_TRUST_THRESHOLD_MAX: Final[int] = 1000


def _parse_hex_address(text: str) -> int | None:
    """Parse a hex address string to an integer.

    Args:
        text: Address string (e.g. ``'0x401000'`` or ``'401000'``).

    Returns:
        int | None: Parsed address, or ``None`` if the text is empty or malformed.
    """
    stripped = text.strip()
    if not stripped:
        return None
    try:
        return int(stripped, 16)
    except ValueError:
        _logger.warning("frida_instrumentation_address_parse_failed", input_text=stripped)
        return None


class InterceptorLifecycleControls(QWidget):
    """Revert/flush controls for the ``Interceptor`` hook lifecycle.

    Exposes ``Interceptor.revert`` (undo a single hook/replacement by target) and ``Interceptor.flush``
    (apply pending inline-cache changes for all active hooks) alongside the existing Add/Remove/Refresh
    hook controls in the Hooks section.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the Interceptor lifecycle controls row.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: FridaBridge | None = None

        layout = QHBoxLayout(self)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        layout.addWidget(QLabel("Revert target:"))
        self._revert_target_input = QLineEdit()
        self._revert_target_input.setPlaceholderText("0x401000 or module!function")
        layout.addWidget(self._revert_target_input)

        self._revert_btn = QPushButton("Revert")
        self._revert_btn.setObjectName("tool_button")
        self._revert_btn.clicked.connect(self._on_revert_hook)
        layout.addWidget(self._revert_btn)

        self._flush_btn = QPushButton("Flush")
        self._flush_btn.setObjectName("tool_button")
        self._flush_btn.clicked.connect(self._on_flush_interceptor)
        layout.addWidget(self._flush_btn)

        self._status_label = QLabel("")
        layout.addWidget(self._status_label)
        layout.addStretch()

    def set_bridge(self, bridge: FridaBridge) -> None:
        """Set the FridaBridge instance used to service revert/flush requests.

        Args:
            bridge: The FridaBridge to use.
        """
        self._bridge = bridge

    def _on_revert_hook(self) -> None:
        """Revert a single hook or function replacement via ``Interceptor.revert``."""
        if self._bridge is None:
            self._status_label.setText("No bridge available")
            _logger.warning("frida_revert_hook_failed_no_bridge")
            return
        target = self._revert_target_input.text().strip()
        if not target:
            self._status_label.setText("Enter a target")
            return
        self._revert_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.revert_hook(target),
            on_success=lambda r: self._on_revert_hook_done(target, r),
            on_error=lambda e: self._on_revert_hook_error(target, e),
            parent=self,
            event="frida_revert_hook",
            logger=_logger,
            level="info",
            target=target,
        )

    def _on_revert_hook_done(self, target: str, result: object) -> None:
        """Handle successful hook revert.

        Args:
            target: The target that was reverted.
            result: Success flag returned by the bridge.
        """
        self._revert_btn.setEnabled(True)
        self._status_label.setText(f"Reverted {target}" if result else f"Revert reported failure for {target}")
        _logger.info("frida_hook_reverted", target=target, success=bool(result))

    def _on_revert_hook_error(self, target: str, exc: object) -> None:
        """Handle hook revert failure.

        Args:
            target: The target that failed to revert.
            exc: The exception that occurred.
        """
        self._revert_btn.setEnabled(True)
        self._status_label.setText(f"Revert failed: {exc}")
        _logger.warning("frida_revert_hook_failed", target=target, error=str(exc))

    def _on_flush_interceptor(self) -> None:
        """Flush pending Interceptor inline-cache changes via ``Interceptor.flush``."""
        if self._bridge is None:
            self._status_label.setText("No bridge available")
            _logger.warning("frida_flush_interceptor_failed_no_bridge")
            return
        self._flush_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.flush_interceptor(),
            on_success=self._on_flush_interceptor_done,
            on_error=self._on_flush_interceptor_error,
            parent=self,
            event="frida_flush_interceptor",
            logger=_logger,
            level="info",
        )

    def _on_flush_interceptor_done(self, result: object) -> None:
        """Handle successful interceptor flush.

        Args:
            result: Success flag returned by the bridge.
        """
        self._flush_btn.setEnabled(True)
        self._status_label.setText("Interceptor flushed" if result else "Flush reported failure")
        _logger.info("frida_interceptor_flushed", success=bool(result))

    def _on_flush_interceptor_error(self, exc: object) -> None:
        """Handle interceptor flush failure.

        Args:
            exc: The exception that occurred.
        """
        self._flush_btn.setEnabled(True)
        self._status_label.setText(f"Flush failed: {exc}")
        _logger.warning("frida_flush_interceptor_failed", error=str(exc))


class StalkerCallProbeControls(QWidget):
    """Add/remove controls and a live table for ``Stalker`` call probes.

    Exposes ``Stalker.addCallProbe`` (fires a JS callback whenever a specific address is called) and
    ``Stalker.removeCallProbe``, distinct from the full-trace Start/Stop Trace controls already present
    in the Stalker tab.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the Stalker call-probe manager widget.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: FridaBridge | None = None
        self._probe_ids: list[str] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        title = QLabel("Call Probes")
        title.setFont(FontManager.get_instance().get_ui_font_bold(9))
        layout.addWidget(title)

        add_row = QHBoxLayout()
        add_row.addWidget(QLabel("Address:"))
        self._probe_addr_input = QLineEdit()
        self._probe_addr_input.setPlaceholderText("0x401000")
        self._probe_addr_input.setMaximumWidth(_ADDR_INPUT_MAX_WIDTH)
        add_row.addWidget(self._probe_addr_input)
        add_row.addWidget(QLabel("Callback JS:"))
        self._probe_callback_input = QLineEdit()
        self._probe_callback_input.setPlaceholderText("send({ type: 'call_probe', arg0: args[0].toString() });")
        add_row.addWidget(self._probe_callback_input)
        self._probe_add_btn = QPushButton("Add Probe")
        self._probe_add_btn.setObjectName("tool_button")
        self._probe_add_btn.clicked.connect(self._on_add_call_probe)
        add_row.addWidget(self._probe_add_btn)
        self._probe_remove_btn = QPushButton("Remove Selected")
        self._probe_remove_btn.setObjectName("tool_button")
        self._probe_remove_btn.clicked.connect(self._on_remove_call_probe)
        add_row.addWidget(self._probe_remove_btn)
        layout.addLayout(add_row)

        self._probe_table = QTableWidget(0, len(_PROBE_COLUMNS))
        self._probe_table.setHorizontalHeaderLabels(_PROBE_COLUMNS)
        self._probe_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._probe_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        probe_h = self._probe_table.horizontalHeader()
        if probe_h is not None:
            probe_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self._probe_table)

        self._status_label = QLabel("")
        layout.addWidget(self._status_label)

    def set_bridge(self, bridge: FridaBridge) -> None:
        """Set the FridaBridge instance used to manage call probes.

        Args:
            bridge: The FridaBridge to use.
        """
        self._bridge = bridge

    def _on_add_call_probe(self) -> None:
        """Install a new call probe via ``Stalker.addCallProbe``."""
        if self._bridge is None:
            self._status_label.setText("No bridge available")
            _logger.warning("frida_stalker_add_call_probe_failed_no_bridge")
            return
        addr = _parse_hex_address(self._probe_addr_input.text())
        if addr is None:
            self._status_label.setText("Invalid address")
            return
        callback_code = self._probe_callback_input.text().strip()
        if not callback_code:
            self._status_label.setText("Enter callback JS code")
            return
        self._probe_add_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.stalker_add_call_probe(addr, callback_code),
            on_success=lambda r: self._on_add_call_probe_done(addr, r),
            on_error=lambda e: self._on_add_call_probe_error(addr, e),
            parent=self,
            event="frida_stalker_add_call_probe",
            logger=_logger,
            level="info",
            address=hex(addr),
        )

    def _on_add_call_probe_done(self, addr: int, result: object) -> None:
        """Handle successful call-probe installation.

        Args:
            addr: Address the probe was installed at.
            result: Probe ID returned by the bridge.
        """
        self._probe_add_btn.setEnabled(True)
        probe_id = str(result)
        row = self._probe_table.rowCount()
        self._probe_table.insertRow(row)
        self._probe_table.setItem(row, 0, QTableWidgetItem(probe_id))
        self._probe_table.setItem(row, 1, QTableWidgetItem(f"0x{addr:X}"))
        self._probe_ids.append(probe_id)
        self._status_label.setText(f"Probe {probe_id} added at 0x{addr:X}")
        _logger.info("frida_stalker_call_probe_added", probe_id=probe_id, address=hex(addr))

    def _on_add_call_probe_error(self, addr: int, exc: object) -> None:
        """Handle call-probe installation failure.

        Args:
            addr: Address the probe was attempted at.
            exc: The exception that occurred.
        """
        self._probe_add_btn.setEnabled(True)
        self._status_label.setText(f"Add probe failed: {exc}")
        _logger.warning("frida_stalker_add_call_probe_failed", address=hex(addr), error=str(exc))

    def _on_remove_call_probe(self) -> None:
        """Remove the selected call probe via ``Stalker.removeCallProbe``."""
        if self._bridge is None:
            self._status_label.setText("No bridge available")
            _logger.warning("frida_stalker_remove_call_probe_failed_no_bridge")
            return
        row = self._probe_table.currentRow()
        if row < 0 or row >= len(self._probe_ids):
            self._status_label.setText("Select a probe to remove")
            return
        probe_id = self._probe_ids[row]
        self._probe_remove_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.stalker_remove_call_probe(probe_id),
            on_success=lambda r: self._on_remove_call_probe_done(row, probe_id, r),
            on_error=lambda e: self._on_remove_call_probe_error(probe_id, e),
            parent=self,
            event="frida_stalker_remove_call_probe",
            logger=_logger,
            level="info",
            probe_id=probe_id,
        )

    def _on_remove_call_probe_done(self, row: int, probe_id: str, result: object) -> None:
        """Handle successful call-probe removal.

        Args:
            row: Table row index of the removed probe.
            probe_id: ID of the removed probe.
            result: Success flag returned by the bridge.
        """
        self._probe_remove_btn.setEnabled(True)
        if result and 0 <= row < len(self._probe_ids):
            self._probe_table.removeRow(row)
            del self._probe_ids[row]
            self._status_label.setText(f"Probe {probe_id} removed")
        else:
            self._status_label.setText(f"Probe {probe_id} was not found")
        _logger.info("frida_stalker_call_probe_removed", probe_id=probe_id, success=bool(result))

    def _on_remove_call_probe_error(self, probe_id: str, exc: object) -> None:
        """Handle call-probe removal failure.

        Args:
            probe_id: ID of the probe that failed to be removed.
            exc: The exception that occurred.
        """
        self._probe_remove_btn.setEnabled(True)
        self._status_label.setText(f"Remove probe failed: {exc}")
        _logger.warning("frida_stalker_remove_call_probe_failed", probe_id=probe_id, error=str(exc))


class MemoryPatchStringControls(QWidget):
    """Code-patching and string-allocation controls for the Memory section.

    Exposes ``Memory.patchCode`` (write bytes through the writable/executable code-patching API, flushing the
    instruction cache) and the ``Memory.allocUtf8String``/``allocAnsiString``/``allocUtf16String`` family via a
    single encoding-aware allocate-string control.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the memory patch/string-allocation controls.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: FridaBridge | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        patch_title = QLabel("Patch Code")
        patch_title.setFont(FontManager.get_instance().get_ui_font_bold(9))
        layout.addWidget(patch_title)

        patch_row = QHBoxLayout()
        patch_row.addWidget(QLabel("Address:"))
        self._patch_addr_input = QLineEdit()
        self._patch_addr_input.setPlaceholderText("0x401000")
        self._patch_addr_input.setMaximumWidth(_ADDR_INPUT_MAX_WIDTH)
        patch_row.addWidget(self._patch_addr_input)
        patch_row.addWidget(QLabel("Bytes (hex):"))
        self._patch_data_input = QLineEdit()
        self._patch_data_input.setPlaceholderText("90 90 90")
        patch_row.addWidget(self._patch_data_input)
        self._patch_btn = QPushButton("Patch Code")
        self._patch_btn.setObjectName("tool_button")
        self._patch_btn.clicked.connect(self._on_patch_code)
        patch_row.addWidget(self._patch_btn)
        layout.addLayout(patch_row)

        self._patch_status_label = QLabel("")
        layout.addWidget(self._patch_status_label)

        alloc_title = QLabel("Allocate String")
        alloc_title.setFont(FontManager.get_instance().get_ui_font_bold(9))
        layout.addWidget(alloc_title)

        alloc_row = QHBoxLayout()
        alloc_row.addWidget(QLabel("Value:"))
        self._alloc_string_input = QLineEdit()
        self._alloc_string_input.setPlaceholderText("hello world")
        alloc_row.addWidget(self._alloc_string_input)
        alloc_row.addWidget(QLabel("Encoding:"))
        self._alloc_encoding_combo = QComboBox()
        self._alloc_encoding_combo.addItems(_STRING_ENCODINGS)
        alloc_row.addWidget(self._alloc_encoding_combo)
        self._alloc_string_btn = QPushButton("Allocate")
        self._alloc_string_btn.setObjectName("tool_button")
        self._alloc_string_btn.clicked.connect(self._on_allocate_string)
        alloc_row.addWidget(self._alloc_string_btn)
        layout.addLayout(alloc_row)

        self._alloc_string_result = QLabel("")
        layout.addWidget(self._alloc_string_result)
        layout.addStretch()

    def set_bridge(self, bridge: FridaBridge) -> None:
        """Set the FridaBridge instance used to patch code and allocate strings.

        Args:
            bridge: The FridaBridge to use.
        """
        self._bridge = bridge

    def _on_patch_code(self) -> None:
        """Patch code at an address via ``Memory.patchCode``."""
        if self._bridge is None:
            self._patch_status_label.setText("No bridge available")
            _logger.warning("frida_patch_code_failed_no_bridge")
            return
        addr = _parse_hex_address(self._patch_addr_input.text())
        if addr is None:
            self._patch_status_label.setText("Invalid address")
            return
        hex_data = self._patch_data_input.text().strip()
        if not hex_data:
            self._patch_status_label.setText("Enter bytes to patch")
            return
        try:
            bytes.fromhex(hex_data.replace(" ", ""))
        except ValueError:
            self._patch_status_label.setText("Invalid hex data")
            _logger.warning("frida_patch_code_invalid_hex", input_text=hex_data)
            return
        self._patch_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.patch_code(addr, hex_data),
            on_success=lambda r: self._on_patch_code_done(addr, r),
            on_error=lambda e: self._on_patch_code_error(addr, e),
            parent=self,
            event="frida_patch_code",
            logger=_logger,
            level="info",
            address=hex(addr),
        )

    def _on_patch_code_done(self, addr: int, result: object) -> None:
        """Handle successful code patch.

        Args:
            addr: Address that was patched.
            result: Success flag returned by the bridge.
        """
        self._patch_btn.setEnabled(True)
        self._patch_status_label.setText(f"Patched 0x{addr:X}" if result else f"Patch reported failure at 0x{addr:X}")
        _logger.info("frida_code_patched_via_gui", address=hex(addr), success=bool(result))

    def _on_patch_code_error(self, addr: int, exc: object) -> None:
        """Handle code patch failure.

        Args:
            addr: Address that failed to patch.
            exc: The exception that occurred.
        """
        self._patch_btn.setEnabled(True)
        self._patch_status_label.setText(f"Patch failed: {exc}")
        _logger.warning("frida_patch_code_failed", address=hex(addr), error=str(exc))

    def _on_allocate_string(self) -> None:
        """Allocate a string in the target process via ``Memory.alloc*String``."""
        if self._bridge is None:
            self._alloc_string_result.setText("No bridge available")
            _logger.warning("frida_allocate_string_failed_no_bridge")
            return
        value = self._alloc_string_input.text()
        if not value:
            self._alloc_string_result.setText("Enter a string value")
            return
        encoding = self._alloc_encoding_combo.currentText()
        self._alloc_string_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.allocate_string(value, encoding=encoding),
            on_success=self._on_allocate_string_done,
            on_error=self._on_allocate_string_error,
            parent=self,
            event="frida_allocate_string",
            logger=_logger,
            level="info",
            encoding=encoding,
        )

    def _on_allocate_string_done(self, result: object) -> None:
        """Handle successful string allocation.

        Args:
            result: Address of the allocated string returned by the bridge.
        """
        self._alloc_string_btn.setEnabled(True)
        self._alloc_string_result.setText(f"0x{result:X}" if isinstance(result, int) else str(result))
        _logger.info("frida_string_allocated_via_gui", address=result)

    def _on_allocate_string_error(self, exc: object) -> None:
        """Handle string allocation failure.

        Args:
            exc: The exception that occurred.
        """
        self._alloc_string_btn.setEnabled(True)
        self._alloc_string_result.setText(f"Allocate failed: {exc}")
        _logger.warning("frida_allocate_string_failed", error=str(exc))


class SymbolLookupControls(QWidget):
    """Module-symbol dump, address-to-module, and glob function-search controls for the Symbols section.

    Exposes ``Module.enumerateSymbols`` (full symbol dump for a named module), ``Process.findModuleByAddress``
    (reverse address-to-module lookup), and ``DebugSymbol.findFunctionsMatching`` (glob-pattern function search),
    complementing the existing find-base/resolve/find-named/API controls already in the Symbols tab.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the extra symbol/module lookup controls.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: FridaBridge | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        title = QLabel("Module Symbols / Reverse Lookup")
        title.setFont(FontManager.get_instance().get_ui_font_bold(9))
        layout.addWidget(title)

        enum_row = QHBoxLayout()
        enum_row.addWidget(QLabel("Module:"))
        self._enum_module_input = QLineEdit()
        self._enum_module_input.setPlaceholderText("kernel32.dll")
        enum_row.addWidget(self._enum_module_input)
        self._enum_symbols_btn = QPushButton("Enumerate Symbols")
        self._enum_symbols_btn.setObjectName("tool_button")
        self._enum_symbols_btn.clicked.connect(self._on_enumerate_symbols)
        enum_row.addWidget(self._enum_symbols_btn)
        layout.addLayout(enum_row)

        reverse_row = QHBoxLayout()
        reverse_row.addWidget(QLabel("Address:"))
        self._reverse_addr_input = QLineEdit()
        self._reverse_addr_input.setPlaceholderText("0x401000")
        self._reverse_addr_input.setMaximumWidth(_ADDR_INPUT_MAX_WIDTH)
        reverse_row.addWidget(self._reverse_addr_input)
        self._find_module_btn = QPushButton("Find Module by Address")
        self._find_module_btn.setObjectName("tool_button")
        self._find_module_btn.clicked.connect(self._on_find_module_by_address)
        reverse_row.addWidget(self._find_module_btn)
        self._reverse_result_label = QLabel("")
        reverse_row.addWidget(self._reverse_result_label)
        reverse_row.addStretch()
        layout.addLayout(reverse_row)

        glob_row = QHBoxLayout()
        glob_row.addWidget(QLabel("Pattern:"))
        self._glob_pattern_input = QLineEdit()
        self._glob_pattern_input.setPlaceholderText("*CreateFile*")
        glob_row.addWidget(self._glob_pattern_input)
        self._find_matching_btn = QPushButton("Find Functions Matching")
        self._find_matching_btn.setObjectName("tool_button")
        self._find_matching_btn.clicked.connect(self._on_find_functions_matching)
        glob_row.addWidget(self._find_matching_btn)
        layout.addLayout(glob_row)

        self._symbols_table = QTableWidget(0, len(_SYMBOL_COLUMNS))
        self._symbols_table.setHorizontalHeaderLabels(_SYMBOL_COLUMNS)
        self._symbols_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        sym_h = self._symbols_table.horizontalHeader()
        if sym_h is not None:
            sym_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self._symbols_table)

        self._status_label = QLabel("")
        layout.addWidget(self._status_label)

    def set_bridge(self, bridge: FridaBridge) -> None:
        """Set the FridaBridge instance used to service symbol/module lookups.

        Args:
            bridge: The FridaBridge to use.
        """
        self._bridge = bridge

    def _on_enumerate_symbols(self) -> None:
        """Dump every symbol in a named module via ``Module.enumerateSymbols``."""
        if self._bridge is None:
            self._status_label.setText("No bridge available")
            _logger.warning("frida_enumerate_symbols_failed_no_bridge")
            return
        module_name = self._enum_module_input.text().strip()
        if not module_name:
            self._status_label.setText("Enter a module name")
            return
        self._enum_symbols_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.enumerate_symbols(module_name),
            on_success=self._populate_symbols_from_module,
            on_error=lambda e: self._on_symbol_lookup_error("Enumerate symbols", e),
            parent=self,
            event="frida_enumerate_symbols",
            logger=_logger,
            module=module_name,
        )

    def _populate_symbols_from_module(self, result: object) -> None:
        """Populate the symbols table from a module symbol dump.

        Args:
            result: List of SymbolInfo from the bridge.
        """
        self._enum_symbols_btn.setEnabled(True)
        self._symbols_table.setRowCount(0)
        if isinstance(result, list):
            for sym in cast("list[object]", result):
                name = str(getattr(sym, "name", ""))
                addr = getattr(sym, "address", 0)
                row = self._symbols_table.rowCount()
                self._symbols_table.insertRow(row)
                self._symbols_table.setItem(row, 0, QTableWidgetItem(name))
                self._symbols_table.setItem(row, 1, QTableWidgetItem(f"0x{addr:X}" if isinstance(addr, int) else str(addr)))
                self._symbols_table.setItem(row, 2, QTableWidgetItem(""))
                self._symbols_table.setItem(row, 3, QTableWidgetItem(""))
            self._status_label.setText(f"{self._symbols_table.rowCount()} symbols found")
        _logger.info("frida_symbols_enumerated_via_gui", count=self._symbols_table.rowCount())

    def _on_find_module_by_address(self) -> None:
        """Resolve which module contains an address via ``Process.findModuleByAddress``."""
        if self._bridge is None:
            self._reverse_result_label.setText("No bridge available")
            _logger.warning("frida_find_module_by_address_failed_no_bridge")
            return
        addr = _parse_hex_address(self._reverse_addr_input.text())
        if addr is None:
            self._reverse_result_label.setText("Invalid address")
            return
        self._find_module_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.find_module_by_address(addr),
            on_success=self._on_find_module_by_address_done,
            on_error=lambda e: self._on_symbol_lookup_error("Find module by address", e),
            parent=self,
            event="frida_find_module_by_address",
            logger=_logger,
            address=hex(addr),
        )

    def _on_find_module_by_address_done(self, result: object) -> None:
        """Handle successful reverse module lookup.

        Args:
            result: ModuleInfo returned by the bridge, or ``None`` if the address is not mapped.
        """
        self._find_module_btn.setEnabled(True)
        if result is None:
            self._reverse_result_label.setText("No module found at that address")
            return
        name = str(getattr(result, "name", ""))
        base = getattr(result, "base_address", 0)
        self._reverse_result_label.setText(f"{name} (base 0x{base:X})" if isinstance(base, int) else name)
        _logger.info("frida_find_module_by_address_completed_via_gui", module_name=name)

    def _on_find_functions_matching(self) -> None:
        """Search functions by glob pattern via ``DebugSymbol.findFunctionsMatching``."""
        if self._bridge is None:
            self._status_label.setText("No bridge available")
            _logger.warning("frida_find_functions_matching_failed_no_bridge")
            return
        pattern = self._glob_pattern_input.text().strip()
        if not pattern:
            self._status_label.setText("Enter a glob pattern")
            return
        self._find_matching_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.find_functions_matching(pattern),
            on_success=self._populate_symbols_from_matching,
            on_error=lambda e: self._on_symbol_lookup_error("Find functions matching", e),
            parent=self,
            event="frida_find_functions_matching",
            logger=_logger,
            pattern=pattern,
        )

    def _populate_symbols_from_matching(self, result: object) -> None:
        """Populate the symbols table from a glob-pattern function search.

        Args:
            result: List of SymbolInfo from the bridge.
        """
        self._find_matching_btn.setEnabled(True)
        self._symbols_table.setRowCount(0)
        if isinstance(result, list):
            for sym in cast("list[object]", result):
                name = str(getattr(sym, "name", ""))
                addr = getattr(sym, "address", 0)
                module = str(getattr(sym, "module_name", "") or "")
                row = self._symbols_table.rowCount()
                self._symbols_table.insertRow(row)
                self._symbols_table.setItem(row, 0, QTableWidgetItem(name))
                self._symbols_table.setItem(row, 1, QTableWidgetItem(f"0x{addr:X}" if isinstance(addr, int) else str(addr)))
                self._symbols_table.setItem(row, 2, QTableWidgetItem(module))
                self._symbols_table.setItem(row, 3, QTableWidgetItem(""))
            self._status_label.setText(f"{self._symbols_table.rowCount()} functions matched")
        _logger.info("frida_find_functions_matching_completed_via_gui", count=self._symbols_table.rowCount())

    def _on_symbol_lookup_error(self, operation: str, exc: object) -> None:
        """Handle a symbol/module lookup failure.

        Args:
            operation: Human-readable name of the failed operation.
            exc: The exception that occurred.
        """
        self._enum_symbols_btn.setEnabled(True)
        self._find_module_btn.setEnabled(True)
        self._find_matching_btn.setEnabled(True)
        self._status_label.setText(f"{operation} failed: {exc}")
        _logger.warning("frida_symbol_lookup_failed", operation=operation, error=str(exc))


class SystemFunctionCallControls(QWidget):
    """Errno/``GetLastError``-capturing native call controls for the Advanced section.

    Exposes ``call_system_function`` (backed by Frida's ``SystemFunction`` class) as a distinct call path from
    the plain ``NativeFunction``-based Call button already present in the Advanced tab's Function Calling block.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the system-function call controls.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: FridaBridge | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        title = QLabel("System Function Call (errno / GetLastError)")
        title.setFont(FontManager.get_instance().get_ui_font_bold(9))
        layout.addWidget(title)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Address:"))
        self._syscall_addr_input = QLineEdit()
        self._syscall_addr_input.setPlaceholderText("0x401000")
        row1.addWidget(self._syscall_addr_input)
        row1.addWidget(QLabel("Args:"))
        self._syscall_args_input = QLineEdit()
        self._syscall_args_input.setPlaceholderText("0, 1, 2")
        row1.addWidget(self._syscall_args_input)
        self._syscall_call_btn = QPushButton("Call (capture errno)")
        self._syscall_call_btn.setObjectName("tool_button")
        self._syscall_call_btn.clicked.connect(self._on_call_system_function)
        row1.addWidget(self._syscall_call_btn)
        layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Return:"))
        self._syscall_ret_type = QComboBox()
        self._syscall_ret_type.addItems(_NATIVE_TYPES)
        row2.addWidget(self._syscall_ret_type)
        row2.addWidget(QLabel("Arg types:"))
        self._syscall_arg_types_input = QLineEdit()
        self._syscall_arg_types_input.setPlaceholderText("pointer, int, int")
        row2.addWidget(self._syscall_arg_types_input)
        row2.addWidget(QLabel("Convention:"))
        self._syscall_cc = QComboBox()
        self._syscall_cc.addItems(_CALLING_CONVENTIONS)
        row2.addWidget(self._syscall_cc)
        row2.addStretch()
        layout.addLayout(row2)

        result_row = QHBoxLayout()
        result_row.addWidget(QLabel("Value:"))
        self._syscall_value_label = QLabel("")
        result_row.addWidget(self._syscall_value_label)
        result_row.addWidget(QLabel("errno:"))
        self._syscall_errno_label = QLabel("")
        result_row.addWidget(self._syscall_errno_label)
        result_row.addWidget(QLabel("GetLastError:"))
        self._syscall_last_error_label = QLabel("")
        result_row.addWidget(self._syscall_last_error_label)
        result_row.addStretch()
        layout.addLayout(result_row)

        self._status_label = QLabel("")
        layout.addWidget(self._status_label)

    def set_bridge(self, bridge: FridaBridge) -> None:
        """Set the FridaBridge instance used to invoke system function calls.

        Args:
            bridge: The FridaBridge to use.
        """
        self._bridge = bridge

    def _on_call_system_function(self) -> None:
        """Call a system function, capturing errno/GetLastError, via ``SystemFunction``."""
        if self._bridge is None:
            self._status_label.setText("No bridge available")
            _logger.warning("frida_call_system_function_failed_no_bridge")
            return
        addr = _parse_hex_address(self._syscall_addr_input.text())
        if addr is None:
            self._status_label.setText("Invalid address")
            return

        args_text = self._syscall_args_input.text().strip()
        args: list[int] | None = None
        if args_text:
            try:
                args = [int(a.strip(), 0) for a in args_text.split(",")]
            except ValueError:
                self._status_label.setText("Invalid arguments")
                _logger.warning("frida_call_system_function_invalid_args", input_text=args_text)
                return

        ret_type = self._syscall_ret_type.currentText()
        arg_types_text = self._syscall_arg_types_input.text().strip()
        arg_types = [t.strip() for t in arg_types_text.split(",")] if arg_types_text else None
        cc = self._syscall_cc.currentText()

        self._syscall_call_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.call_system_function(addr, args, return_type=ret_type, arg_types=arg_types, calling_convention=cc),
            on_success=self._on_call_system_function_done,
            on_error=self._on_call_system_function_error,
            parent=self,
            event="frida_call_system_function",
            logger=_logger,
            level="info",
            address=hex(addr),
            return_type=ret_type,
            calling_convention=cc,
        )

    def _on_call_system_function_done(self, result: object) -> None:
        """Handle a successful system function call.

        Args:
            result: SystemCallResult from the bridge.
        """
        self._syscall_call_btn.setEnabled(True)
        value = getattr(result, "value", None)
        errno = getattr(result, "errno", None)
        last_error = getattr(result, "last_error", None)
        self._syscall_value_label.setText(f"0x{value:X}" if isinstance(value, int) else str(value))
        self._syscall_errno_label.setText(str(errno))
        self._syscall_last_error_label.setText(str(last_error))
        self._status_label.setText("Call succeeded")
        _logger.info("frida_call_system_function_completed_via_gui", value=value, errno=errno, last_error=last_error)

    def _on_call_system_function_error(self, exc: object) -> None:
        """Handle a system function call failure.

        Args:
            exc: The exception that occurred.
        """
        self._syscall_call_btn.setEnabled(True)
        self._status_label.setText(f"Call failed: {exc}")
        _logger.warning("frida_call_system_function_failed", error=str(exc))


class StalkerConfigControls(QWidget):
    """Exclude/garbage-collect/invalidate/trust-threshold controls for the Stalker tuning API.

    Exposes ``Stalker.exclude`` (skip a memory range during code tracing), ``Stalker.garbageCollect``
    (reclaim resources for terminated threads), ``Stalker.invalidate`` (drop cached instrumentation for
    an address so it is re-instrumented on next execution), and ``Stalker.trustThreshold`` (control cached
    instrumented-code reuse), distinct from the full-trace Start/Stop Trace and call-probe controls already
    present in the Stalker tab.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the Stalker configuration controls.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: FridaBridge | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        title = QLabel("Stalker Config")
        title.setFont(FontManager.get_instance().get_ui_font_bold(9))
        layout.addWidget(title)

        exclude_row = QHBoxLayout()
        exclude_row.addWidget(QLabel("Exclude base:"))
        self._exclude_base_input = QLineEdit()
        self._exclude_base_input.setPlaceholderText("0x401000")
        self._exclude_base_input.setMaximumWidth(_ADDR_INPUT_MAX_WIDTH)
        exclude_row.addWidget(self._exclude_base_input)
        exclude_row.addWidget(QLabel("Size:"))
        self._exclude_size_input = QLineEdit()
        self._exclude_size_input.setPlaceholderText("4096")
        exclude_row.addWidget(self._exclude_size_input)
        self._exclude_btn = QPushButton("Exclude Range")
        self._exclude_btn.setObjectName("tool_button")
        self._exclude_btn.clicked.connect(self._on_stalker_exclude)
        exclude_row.addWidget(self._exclude_btn)
        layout.addLayout(exclude_row)

        invalidate_row = QHBoxLayout()
        invalidate_row.addWidget(QLabel("Invalidate address:"))
        self._invalidate_addr_input = QLineEdit()
        self._invalidate_addr_input.setPlaceholderText("0x401000")
        self._invalidate_addr_input.setMaximumWidth(_ADDR_INPUT_MAX_WIDTH)
        invalidate_row.addWidget(self._invalidate_addr_input)
        invalidate_row.addWidget(QLabel("Thread ID:"))
        self._invalidate_tid_input = QLineEdit()
        self._invalidate_tid_input.setPlaceholderText("current thread")
        invalidate_row.addWidget(self._invalidate_tid_input)
        self._invalidate_btn = QPushButton("Invalidate")
        self._invalidate_btn.setObjectName("tool_button")
        self._invalidate_btn.clicked.connect(self._on_stalker_invalidate)
        invalidate_row.addWidget(self._invalidate_btn)
        layout.addLayout(invalidate_row)

        threshold_row = QHBoxLayout()
        threshold_row.addWidget(QLabel("Trust threshold:"))
        self._trust_threshold_spin = QSpinBox()
        self._trust_threshold_spin.setRange(_TRUST_THRESHOLD_MIN, _TRUST_THRESHOLD_MAX)
        self._trust_threshold_spin.setValue(3)
        self._trust_threshold_spin.setToolTip("-1 disables trust (always re-instrument), 0 trusts immediately")
        threshold_row.addWidget(self._trust_threshold_spin)
        self._set_threshold_btn = QPushButton("Set Threshold")
        self._set_threshold_btn.setObjectName("tool_button")
        self._set_threshold_btn.clicked.connect(self._on_stalker_set_trust_threshold)
        threshold_row.addWidget(self._set_threshold_btn)
        self._gc_btn = QPushButton("Garbage Collect")
        self._gc_btn.setObjectName("tool_button")
        self._gc_btn.clicked.connect(self._on_stalker_garbage_collect)
        threshold_row.addWidget(self._gc_btn)
        layout.addLayout(threshold_row)

        self._status_label = QLabel("")
        layout.addWidget(self._status_label)

    def set_bridge(self, bridge: FridaBridge) -> None:
        """Set the FridaBridge instance used to service Stalker configuration requests.

        Args:
            bridge: The FridaBridge to use.
        """
        self._bridge = bridge

    def _on_stalker_exclude(self) -> None:
        """Exclude a memory range from Stalker instrumentation via ``Stalker.exclude``."""
        if self._bridge is None:
            self._status_label.setText("No bridge available")
            _logger.warning("frida_stalker_exclude_failed_no_bridge")
            return
        base = _parse_hex_address(self._exclude_base_input.text())
        if base is None:
            self._status_label.setText("Invalid base address")
            return
        size_text = self._exclude_size_input.text().strip()
        try:
            size = int(size_text, 0)
        except ValueError:
            self._status_label.setText("Invalid size")
            _logger.warning("frida_stalker_exclude_invalid_size", input_text=size_text)
            return
        self._exclude_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.stalker_exclude(base, size),
            on_success=lambda r: self._on_stalker_exclude_done(base, size, r),
            on_error=lambda e: self._on_stalker_config_error("Exclude range", e, self._exclude_btn),
            parent=self,
            event="frida_stalker_exclude",
            logger=_logger,
            level="info",
            base_address=hex(base),
            size=size,
        )

    def _on_stalker_exclude_done(self, base: int, size: int, result: object) -> None:
        """Handle successful Stalker range exclusion.

        Args:
            base: Base address of the excluded range.
            size: Size in bytes of the excluded range.
            result: Success flag returned by the bridge.
        """
        self._exclude_btn.setEnabled(True)
        self._status_label.setText(f"Excluded 0x{base:X} (size {size})" if result else "Exclude reported failure")
        _logger.info("frida_stalker_range_excluded_via_gui", base_address=hex(base), size=size, success=bool(result))

    def _on_stalker_invalidate(self) -> None:
        """Invalidate cached Stalker instrumentation for an address via ``Stalker.invalidate``."""
        if self._bridge is None:
            self._status_label.setText("No bridge available")
            _logger.warning("frida_stalker_invalidate_failed_no_bridge")
            return
        addr = _parse_hex_address(self._invalidate_addr_input.text())
        if addr is None:
            self._status_label.setText("Invalid address")
            return
        tid_text = self._invalidate_tid_input.text().strip()
        thread_id: int | None = None
        if tid_text:
            try:
                thread_id = int(tid_text, 0)
            except ValueError:
                self._status_label.setText("Invalid thread ID")
                _logger.warning("frida_stalker_invalidate_invalid_tid", input_text=tid_text)
                return
        self._invalidate_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.stalker_invalidate(addr, thread_id),
            on_success=lambda r: self._on_stalker_invalidate_done(addr, r),
            on_error=lambda e: self._on_stalker_config_error("Invalidate", e, self._invalidate_btn),
            parent=self,
            event="frida_stalker_invalidate",
            logger=_logger,
            level="info",
            address=hex(addr),
            thread_id=thread_id,
        )

    def _on_stalker_invalidate_done(self, addr: int, result: object) -> None:
        """Handle successful Stalker instrumentation invalidation.

        Args:
            addr: Address whose cached instrumentation was invalidated.
            result: Success flag returned by the bridge.
        """
        self._invalidate_btn.setEnabled(True)
        self._status_label.setText(f"Invalidated 0x{addr:X}" if result else "Invalidate reported failure")
        _logger.info("frida_stalker_invalidated_via_gui", address=hex(addr), success=bool(result))

    def _on_stalker_garbage_collect(self) -> None:
        """Reclaim Stalker resources for terminated threads via ``Stalker.garbageCollect``."""
        if self._bridge is None:
            self._status_label.setText("No bridge available")
            _logger.warning("frida_stalker_garbage_collect_failed_no_bridge")
            return
        self._gc_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.stalker_garbage_collect(),
            on_success=self._on_stalker_garbage_collect_done,
            on_error=lambda e: self._on_stalker_config_error("Garbage collect", e, self._gc_btn),
            parent=self,
            event="frida_stalker_garbage_collect",
            logger=_logger,
            level="info",
        )

    def _on_stalker_garbage_collect_done(self, result: object) -> None:
        """Handle successful Stalker garbage collection.

        Args:
            result: Success flag returned by the bridge.
        """
        self._gc_btn.setEnabled(True)
        self._status_label.setText("Garbage collected" if result else "Garbage collect reported failure")
        _logger.info("frida_stalker_garbage_collected_via_gui", success=bool(result))

    def _on_stalker_set_trust_threshold(self) -> None:
        """Set Stalker's trust threshold via ``Stalker.trustThreshold``."""
        if self._bridge is None:
            self._status_label.setText("No bridge available")
            _logger.warning("frida_stalker_set_trust_threshold_failed_no_bridge")
            return
        threshold = self._trust_threshold_spin.value()
        self._set_threshold_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.stalker_set_trust_threshold(threshold),
            on_success=lambda r: self._on_stalker_set_trust_threshold_done(threshold, r),
            on_error=lambda e: self._on_stalker_config_error("Set trust threshold", e, self._set_threshold_btn),
            parent=self,
            event="frida_stalker_set_trust_threshold",
            logger=_logger,
            level="info",
            threshold=threshold,
        )

    def _on_stalker_set_trust_threshold_done(self, threshold: int, result: object) -> None:
        """Handle successful trust-threshold update.

        Args:
            threshold: The threshold value that was applied.
            result: Success flag returned by the bridge.
        """
        self._set_threshold_btn.setEnabled(True)
        self._status_label.setText(f"Trust threshold set to {threshold}" if result else "Set threshold reported failure")
        _logger.info("frida_stalker_trust_threshold_set_via_gui", threshold=threshold, success=bool(result))

    def _on_stalker_config_error(self, operation: str, exc: object, button: QPushButton) -> None:
        """Handle a Stalker configuration operation failure.

        Args:
            operation: Human-readable name of the failed operation.
            exc: The exception that occurred.
            button: The button to re-enable.
        """
        button.setEnabled(True)
        self._status_label.setText(f"{operation} failed: {exc}")
        _logger.warning("frida_stalker_config_failed", operation=operation, error=str(exc))


class ScriptMessagingControls(QWidget):
    """RPC-export invocation, raw message posting, and eternalization controls for a running script.

    Exposes ``rpc_call`` (invoke a ``rpc.exports``-declared function in the target script), ``post_message``
    (send a raw JSON message into the script's ``recv`` handler), and ``eternalize_script`` (detach the script
    from its Python handle so it survives process detach), operating on the currently active persistent
    script tracked by the owning panel.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the script messaging controls.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: FridaBridge | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        title = QLabel("Script Messaging (RPC / postMessage / eternalize)")
        title.setFont(FontManager.get_instance().get_ui_font_bold(9))
        layout.addWidget(title)

        script_row = QHBoxLayout()
        script_row.addWidget(QLabel("Script ID:"))
        self._script_id_input = QLineEdit()
        self._script_id_input.setPlaceholderText("active persistent script ID")
        script_row.addWidget(self._script_id_input)
        self._eternalize_btn = QPushButton("Eternalize")
        self._eternalize_btn.setObjectName("tool_button")
        self._eternalize_btn.clicked.connect(self._on_eternalize_script)
        script_row.addWidget(self._eternalize_btn)
        layout.addLayout(script_row)

        rpc_row = QHBoxLayout()
        rpc_row.addWidget(QLabel("RPC method:"))
        self._rpc_method_input = QLineEdit()
        self._rpc_method_input.setPlaceholderText("exportedFunctionName")
        rpc_row.addWidget(self._rpc_method_input)
        rpc_row.addWidget(QLabel("Args (JSON array):"))
        self._rpc_args_input = QLineEdit()
        self._rpc_args_input.setPlaceholderText('[1, "two", true]')
        rpc_row.addWidget(self._rpc_args_input)
        self._rpc_call_btn = QPushButton("RPC Call")
        self._rpc_call_btn.setObjectName("tool_button")
        self._rpc_call_btn.clicked.connect(self._on_rpc_call)
        rpc_row.addWidget(self._rpc_call_btn)
        layout.addLayout(rpc_row)

        self._rpc_result_label = QLabel("")
        layout.addWidget(self._rpc_result_label)

        message_row = QHBoxLayout()
        message_row.addWidget(QLabel("Message (JSON):"))
        self._post_message_input = QPlainTextEdit()
        self._post_message_input.setPlaceholderText('{"type": "config", "value": 1}')
        self._post_message_input.setMaximumHeight(_ADDR_INPUT_MAX_WIDTH // 2)
        message_row.addWidget(self._post_message_input)
        self._post_message_btn = QPushButton("Post Message")
        self._post_message_btn.setObjectName("tool_button")
        self._post_message_btn.clicked.connect(self._on_post_message)
        message_row.addWidget(self._post_message_btn)
        layout.addLayout(message_row)

        self._status_label = QLabel("")
        layout.addWidget(self._status_label)

    def set_bridge(self, bridge: FridaBridge) -> None:
        """Set the FridaBridge instance used to service script messaging requests.

        Args:
            bridge: The FridaBridge to use.
        """
        self._bridge = bridge

    def set_active_script_id(self, script_id: str | None) -> None:
        """Prefill the script-ID field with the panel's currently active persistent script.

        Args:
            script_id: ID of the active persistent script, or ``None`` if no script is loaded.
        """
        self._script_id_input.setText(script_id or "")

    def _resolve_script_id(self) -> str:
        """Read the script ID currently entered in the script-ID field.

        Returns:
            str: The stripped script ID text (may be empty).
        """
        return self._script_id_input.text().strip()

    def _on_rpc_call(self) -> None:
        """Invoke an RPC-exported function in the target script via ``rpc_call``."""
        if self._bridge is None:
            self._status_label.setText("No bridge available")
            _logger.warning("frida_rpc_call_failed_no_bridge")
            return
        script_id = self._resolve_script_id()
        if not script_id:
            self._status_label.setText("Enter a script ID")
            return
        method_name = self._rpc_method_input.text().strip()
        if not method_name:
            self._status_label.setText("Enter an RPC method name")
            return
        args_text = self._rpc_args_input.text().strip()
        args: list[object] | None = None
        if args_text:
            try:
                parsed_args = json.loads(args_text)
            except json.JSONDecodeError:
                self._status_label.setText("Args must be a JSON array")
                _logger.warning("frida_rpc_call_invalid_args", input_text=args_text)
                return
            if not isinstance(parsed_args, list):
                self._status_label.setText("Args must be a JSON array")
                return
            args = cast("list[object]", parsed_args)
        self._rpc_call_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.rpc_call(script_id, method_name, args),
            on_success=self._on_rpc_call_done,
            on_error=lambda e: self._on_script_messaging_error("RPC call", e, self._rpc_call_btn),
            parent=self,
            event="frida_rpc_call",
            logger=_logger,
            level="info",
            script_id=script_id,
            method=method_name,
        )

    def _on_rpc_call_done(self, result: object) -> None:
        """Handle a successful RPC call.

        Args:
            result: Return value from the RPC-exported function.
        """
        self._rpc_call_btn.setEnabled(True)
        self._rpc_result_label.setText(f"Result: {result}")
        _logger.info("frida_rpc_call_completed_via_gui", result_type=type(result).__name__)

    def _on_post_message(self) -> None:
        """Post a raw JSON message to the target script via ``post_message``."""
        if self._bridge is None:
            self._status_label.setText("No bridge available")
            _logger.warning("frida_post_message_failed_no_bridge")
            return
        script_id = self._resolve_script_id()
        if not script_id:
            self._status_label.setText("Enter a script ID")
            return
        message = self._post_message_input.toPlainText().strip()
        if not message:
            self._status_label.setText("Enter a JSON message")
            return
        try:
            json.loads(message)
        except json.JSONDecodeError:
            self._status_label.setText("Message must be valid JSON")
            _logger.warning("frida_post_message_invalid_json", input_text=message)
            return
        self._post_message_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.post_message(script_id, message),
            on_success=self._on_post_message_done,
            on_error=lambda e: self._on_script_messaging_error("Post message", e, self._post_message_btn),
            parent=self,
            event="frida_post_message",
            logger=_logger,
            level="info",
            script_id=script_id,
        )

    def _on_post_message_done(self, result: object) -> None:
        """Handle a successful message post.

        Args:
            result: Success flag returned by the bridge.
        """
        self._post_message_btn.setEnabled(True)
        self._status_label.setText("Message posted" if result else "Post message reported failure")
        _logger.info("frida_message_posted_via_gui", success=bool(result))

    def _on_eternalize_script(self) -> None:
        """Detach the target script from its Python handle via ``eternalize_script``."""
        if self._bridge is None:
            self._status_label.setText("No bridge available")
            _logger.warning("frida_eternalize_script_failed_no_bridge")
            return
        script_id = self._resolve_script_id()
        if not script_id:
            self._status_label.setText("Enter a script ID")
            return
        self._eternalize_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.eternalize_script(script_id),
            on_success=lambda r: self._on_eternalize_script_done(script_id, r),
            on_error=lambda e: self._on_script_messaging_error("Eternalize", e, self._eternalize_btn),
            parent=self,
            event="frida_eternalize_script",
            logger=_logger,
            level="info",
            script_id=script_id,
        )

    def _on_eternalize_script_done(self, script_id: str, result: object) -> None:
        """Handle a successful script eternalization.

        Args:
            script_id: ID of the script that was eternalized.
            result: Success flag returned by the bridge.
        """
        self._eternalize_btn.setEnabled(True)
        self._status_label.setText(f"Script {script_id} eternalized" if result else "Eternalize reported failure")
        _logger.info("frida_script_eternalized_via_gui", script_id=script_id, success=bool(result))

    def _on_script_messaging_error(self, operation: str, exc: object, button: QPushButton) -> None:
        """Handle a script messaging operation failure.

        Args:
            operation: Human-readable name of the failed operation.
            exc: The exception that occurred.
            button: The button to re-enable.
        """
        button.setEnabled(True)
        self._status_label.setText(f"{operation} failed: {exc}")
        _logger.warning("frida_script_messaging_failed", operation=operation, error=str(exc))


class CancellableControls(QWidget):
    """Cancellation-token lifecycle controls for long-running Frida operations.

    Exposes ``create_cancellable`` (mint a new ``frida.Cancellable`` token) and ``cancel`` (trigger a
    previously created token), giving the GUI a way to abort long-running bridge calls that accept an
    optional ``cancellable_id``. The most recently created token ID is surfaced via
    :meth:`last_cancellable_id` so other controls (e.g. Attach/Spawn) can opt into passing it.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the cancellable-token controls.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: FridaBridge | None = None
        self._last_cancellable_id: str | None = None

        layout = QHBoxLayout(self)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        layout.addWidget(QLabel("Cancellable:"))
        self._cancellable_id_input = QLineEdit()
        self._cancellable_id_input.setPlaceholderText("no cancellable created yet")
        self._cancellable_id_input.setReadOnly(True)
        layout.addWidget(self._cancellable_id_input)

        self._create_btn = QPushButton("Create Cancellable")
        self._create_btn.setObjectName("tool_button")
        self._create_btn.clicked.connect(self._on_create_cancellable)
        layout.addWidget(self._create_btn)

        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.setObjectName("tool_button")
        self._cancel_btn.setEnabled(False)
        self._cancel_btn.clicked.connect(self._on_cancel)
        layout.addWidget(self._cancel_btn)

        self._status_label = QLabel("")
        layout.addWidget(self._status_label)
        layout.addStretch()

    def set_bridge(self, bridge: FridaBridge) -> None:
        """Set the FridaBridge instance used to manage cancellation tokens.

        Args:
            bridge: The FridaBridge to use.
        """
        self._bridge = bridge

    def last_cancellable_id(self) -> str | None:
        """Return the most recently created, not-yet-cancelled cancellable ID.

        Returns:
            str | None: The active cancellable ID, or ``None`` if none has been created (or it was
            already cancelled).
        """
        return self._last_cancellable_id

    def _on_create_cancellable(self) -> None:
        """Mint a new cancellation token via ``create_cancellable``."""
        if self._bridge is None:
            self._status_label.setText("No bridge available")
            _logger.warning("frida_create_cancellable_failed_no_bridge")
            return
        self._create_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.create_cancellable(),
            on_success=self._on_create_cancellable_done,
            on_error=self._on_create_cancellable_error,
            parent=self,
            event="frida_create_cancellable",
            logger=_logger,
            level="info",
        )

    def _on_create_cancellable_done(self, result: object) -> None:
        """Handle successful cancellable creation.

        Args:
            result: Cancellable ID returned by the bridge.
        """
        self._create_btn.setEnabled(True)
        cancellable_id = str(result)
        self._last_cancellable_id = cancellable_id
        self._cancellable_id_input.setText(cancellable_id)
        self._cancel_btn.setEnabled(True)
        self._status_label.setText(f"Created {cancellable_id}")
        _logger.info("frida_cancellable_created_via_gui", cancellable_id=cancellable_id)

    def _on_create_cancellable_error(self, exc: object) -> None:
        """Handle cancellable creation failure.

        Args:
            exc: The exception that occurred.
        """
        self._create_btn.setEnabled(True)
        self._status_label.setText(f"Create failed: {exc}")
        _logger.warning("frida_create_cancellable_failed", error=str(exc))

    def _on_cancel(self) -> None:
        """Trigger the current cancellation token via ``cancel``."""
        if self._bridge is None:
            self._status_label.setText("No bridge available")
            _logger.warning("frida_cancel_failed_no_bridge")
            return
        cancellable_id = self._last_cancellable_id
        if not cancellable_id:
            self._status_label.setText("No cancellable to cancel")
            return
        self._cancel_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.cancel(cancellable_id),
            on_success=lambda r: self._on_cancel_done(cancellable_id, r),
            on_error=lambda e: self._on_cancel_error(cancellable_id, e),
            parent=self,
            event="frida_cancel",
            logger=_logger,
            level="info",
            cancellable_id=cancellable_id,
        )

    def _on_cancel_done(self, cancellable_id: str, result: object) -> None:
        """Handle successful cancellation.

        Args:
            cancellable_id: ID of the cancellable that was triggered.
            result: Success flag returned by the bridge.
        """
        if result:
            self._last_cancellable_id = None
            self._cancellable_id_input.setText("")
            self._cancel_btn.setEnabled(False)
            self._status_label.setText(f"Cancelled {cancellable_id}")
        else:
            self._status_label.setText(f"Cancellable {cancellable_id} was not found")
        _logger.info("frida_cancelled_via_gui", cancellable_id=cancellable_id, success=bool(result))

    def _on_cancel_error(self, cancellable_id: str, exc: object) -> None:
        """Handle cancellation failure.

        Args:
            cancellable_id: ID of the cancellable that failed to be triggered.
            exc: The exception that occurred.
        """
        self._cancel_btn.setEnabled(True)
        self._status_label.setText(f"Cancel failed: {exc}")
        _logger.warning("frida_cancel_failed", cancellable_id=cancellable_id, error=str(exc))
