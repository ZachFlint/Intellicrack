# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Virtual-address mapping and performance-settings mixin for the hex editor panel."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.dialogs_helpers import show_info, show_warning
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_logged
from intellicrack.ui.panels.hex_editor.widgets import LargeFileSettingsDialog


if TYPE_CHECKING:
    from intellicrack.bridges.hex_editor import HexEditorBridge


_logger = get_logger(__name__)

_BYTES_PER_KB = 1024
_BYTES_PER_MB = 1024 * 1024


class VaMappingMixin:
    """Mixin providing virtual-address mapping and large-file performance controls."""

    document: Any | None
    _bridge: HexEditorBridge | None
    _hex_widget: Any | None
    _va_mappings_tree: QTreeWidget | None
    _va_file_offset_edit: QLineEdit | None
    _va_address_edit: QLineEdit | None
    _va_length_edit: QLineEdit | None
    _va_goto_edit: QLineEdit | None
    _va_status_label: QLabel | None

    def _create_va_mapping_tab(self) -> QWidget:
        """Build the VA Mapping side-tab widget.

        Creates the mapping list, add/remove/auto-detect controls, and the
        virtual-address navigation row, alongside the large-file
        performance-settings entry point.

        Returns:
            QWidget: Container widget for the VA mapping tab.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(2, 2, 2, 2)
        layout.setSpacing(4)

        self._va_mappings_tree = QTreeWidget()
        self._va_mappings_tree.setHeaderLabels(["File Offset", "Virtual Address", "Length"])
        self._va_mappings_tree.setRootIsDecorated(False)
        self._va_mappings_tree.setAlternatingRowColors(True)
        layout.addWidget(self._va_mappings_tree)

        add_row = QHBoxLayout()
        self._va_file_offset_edit = QLineEdit()
        self._va_file_offset_edit.setPlaceholderText("File offset (hex)")
        add_row.addWidget(self._va_file_offset_edit)
        self._va_address_edit = QLineEdit()
        self._va_address_edit.setPlaceholderText("Virtual address (hex)")
        add_row.addWidget(self._va_address_edit)
        self._va_length_edit = QLineEdit()
        self._va_length_edit.setPlaceholderText("Length (hex)")
        add_row.addWidget(self._va_length_edit)
        layout.addLayout(add_row)

        btn_row = QHBoxLayout()
        add_btn = QPushButton("Add Mapping")
        add_btn.clicked.connect(self._on_add_va_mapping)
        btn_row.addWidget(add_btn)
        remove_btn = QPushButton("Remove Selected")
        remove_btn.clicked.connect(self._on_remove_va_mapping)
        btn_row.addWidget(remove_btn)
        auto_btn = QPushButton("Auto-Detect")
        auto_btn.clicked.connect(self._on_auto_detect_va_mappings)
        btn_row.addWidget(auto_btn)
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self._on_refresh_va_mappings)
        btn_row.addWidget(refresh_btn)
        layout.addLayout(btn_row)

        goto_row = QHBoxLayout()
        goto_row.addWidget(QLabel("Go to VA:"))
        self._va_goto_edit = QLineEdit()
        self._va_goto_edit.setPlaceholderText("Virtual address (hex)")
        goto_row.addWidget(self._va_goto_edit)
        goto_btn = QPushButton("Go")
        goto_btn.clicked.connect(self._on_goto_va)
        goto_row.addWidget(goto_btn)
        layout.addLayout(goto_row)

        offset_row = QHBoxLayout()
        offset_lookup_btn = QPushButton("Cursor Offset -> VA")
        offset_lookup_btn.clicked.connect(self._on_cursor_offset_to_va)
        offset_row.addWidget(offset_lookup_btn)
        layout.addLayout(offset_row)

        perf_btn = QPushButton("Performance Settings...")
        perf_btn.clicked.connect(self._on_open_performance_settings)
        layout.addWidget(perf_btn)

        self._va_status_label = QLabel("")
        layout.addWidget(self._va_status_label)

        return container

    @staticmethod
    def _parse_va_hex_field(field: QLineEdit | None) -> int | None:
        """Parse a hex-formatted VA-mapping field into an integer.

        Args:
            field: Line-edit widget holding the value to parse.

        Returns:
            int | None: Parsed non-negative integer, or ``None`` if the
                field is empty, missing, or malformed.
        """
        if field is None:
            return None
        text = field.text().strip()
        if not text:
            return None
        hex_text = text[2:] if text.lower().startswith("0x") else text
        try:
            return int(hex_text, 16)
        except ValueError:
            return None

    def _on_add_va_mapping(self) -> None:
        """Add a virtual-address mapping via :meth:`HexEditorBridge.set_va_base`."""
        parent = self if isinstance(self, QWidget) else None
        bridge = self._bridge
        if bridge is None:
            show_warning(parent, "VA Mapping", "Hex editor bridge is not attached.")
            return

        file_offset = self._parse_va_hex_field(self._va_file_offset_edit)
        virtual_address = self._parse_va_hex_field(self._va_address_edit)
        length = self._parse_va_hex_field(self._va_length_edit)
        if file_offset is None or virtual_address is None or length is None:
            show_warning(parent, "VA Mapping", "File offset, virtual address, and length must all be valid hex values.")
            return

        run_bridge_coroutine_logged(
            bridge.set_va_base(file_offset, virtual_address, length),
            on_success=self._on_va_mapping_added,
            on_error=self._on_va_mapping_error,
            parent=parent,
            event="hex_editor_set_va_base",
            logger=_logger,
            level="info",
            file_offset=hex(file_offset),
            virtual_address=hex(virtual_address),
            length=length,
        )

    def _on_va_mapping_added(self, result: object) -> None:
        """Refresh the mappings tree after a successful ``set_va_base`` call.

        Args:
            result: Boolean success payload returned by the bridge.
        """
        _logger.info("va_mapping_added_success", result=result)
        self._on_refresh_va_mappings()

    def _on_va_mapping_error(self, exc: object) -> None:
        """Surface a VA-mapping bridge failure to the user.

        Args:
            exc: Exception object emitted by the bridge worker.
        """
        parent = self if isinstance(self, QWidget) else None
        show_warning(parent, "VA Mapping", f"Operation failed:\n{exc}")
        _logger.warning("va_mapping_bridge_failed", error=str(exc))

    def _on_remove_va_mapping(self) -> None:
        """Remove the selected mapping via :meth:`HexEditorBridge.remove_va_mapping`."""
        parent = self if isinstance(self, QWidget) else None
        bridge = self._bridge
        if bridge is None:
            show_warning(parent, "VA Mapping", "Hex editor bridge is not attached.")
            return
        if self._va_mappings_tree is None:
            return
        row = self._va_mappings_tree.indexOfTopLevelItem(self._va_mappings_tree.currentItem())
        if row < 0:
            show_warning(parent, "VA Mapping", "Select a mapping to remove.")
            return

        run_bridge_coroutine_logged(
            bridge.remove_va_mapping(row),
            on_success=self._on_va_mapping_added,
            on_error=self._on_va_mapping_error,
            parent=parent,
            event="hex_editor_remove_va_mapping",
            logger=_logger,
            level="info",
            index=row,
        )

    def _on_auto_detect_va_mappings(self) -> None:
        """Auto-detect VA mappings via :meth:`HexEditorBridge.auto_detect_va_mappings`."""
        parent = self if isinstance(self, QWidget) else None
        bridge = self._bridge
        if bridge is None:
            show_warning(parent, "VA Mapping", "Hex editor bridge is not attached.")
            return

        run_bridge_coroutine_logged(
            bridge.auto_detect_va_mappings(),
            on_success=self._on_va_mappings_detected,
            on_error=self._on_va_mapping_error,
            parent=parent,
            event="hex_editor_auto_detect_va_mappings",
            logger=_logger,
            level="info",
        )

    def _on_va_mappings_detected(self, result: object) -> None:
        """Populate the mappings tree with auto-detected mappings.

        Args:
            result: ``list[dict]`` payload returned by
                :meth:`HexEditorBridge.auto_detect_va_mappings`.
        """
        if not isinstance(result, list):
            return
        detected = cast("list[dict[str, int]]", result)
        if self._va_status_label is not None:
            self._va_status_label.setText(f"Auto-detected {len(detected)} mapping(s)")
        self._on_refresh_va_mappings()

    def _on_refresh_va_mappings(self) -> None:
        """Refresh the mappings tree via :meth:`HexEditorBridge.list_va_mappings`."""
        parent = self if isinstance(self, QWidget) else None
        bridge = self._bridge
        if bridge is None:
            return

        run_bridge_coroutine_logged(
            bridge.list_va_mappings(),
            on_success=self._on_va_mappings_listed,
            on_error=self._on_va_mapping_error,
            parent=parent,
            event="hex_editor_list_va_mappings",
            logger=_logger,
        )

    def _on_va_mappings_listed(self, result: object) -> None:
        """Render the list of VA mappings into the tree widget.

        Args:
            result: ``list[dict]`` payload returned by
                :meth:`HexEditorBridge.list_va_mappings`.
        """
        if self._va_mappings_tree is None or not isinstance(result, list):
            return
        self._va_mappings_tree.clear()
        entries = cast("list[dict[str, int]]", result)
        for entry in entries:
            file_offset = int(entry.get("file_offset", 0))
            virtual_address = int(entry.get("virtual_address", 0))
            length = int(entry.get("length", 0))
            item = QTreeWidgetItem([
                f"0x{file_offset:X}",
                f"0x{virtual_address:X}",
                f"0x{length:X}",
            ])
            self._va_mappings_tree.addTopLevelItem(item)
        _logger.debug("va_mappings_listed", count=len(entries))

    def _on_goto_va(self) -> None:
        """Convert a virtual address to a file offset and navigate there."""
        parent = self if isinstance(self, QWidget) else None
        bridge = self._bridge
        if bridge is None:
            show_warning(parent, "VA Mapping", "Hex editor bridge is not attached.")
            return
        va = self._parse_va_hex_field(self._va_goto_edit)
        if va is None:
            show_warning(parent, "VA Mapping", "Enter a valid hex virtual address.")
            return

        run_bridge_coroutine_logged(
            bridge.va_to_file_offset(va),
            on_success=lambda result: self._on_va_to_file_offset_resolved(va, result),
            on_error=lambda exc: self._on_va_conversion_error(va, exc),
            parent=parent,
            event="hex_editor_va_to_file_offset",
            logger=_logger,
            va=hex(va),
        )

    def _on_va_to_file_offset_resolved(self, va: int, offset_result: object) -> None:
        """Navigate the hex view to the file offset resolved from a VA.

        Args:
            va: Virtual address that was looked up.
            offset_result: File-offset payload returned by
                :meth:`HexEditorBridge.va_to_file_offset`, or ``None`` when
                the address is unmapped.
        """
        if offset_result is None:
            if self._va_status_label is not None:
                self._va_status_label.setText(f"0x{va:X} is not mapped to a file offset")
            return
        if not isinstance(offset_result, int):
            return
        offset = offset_result

        if self._va_status_label is not None:
            self._va_status_label.setText(f"0x{va:X} -> file offset 0x{offset:X}")
        goto_fn = getattr(self._hex_widget, "goto_offset", None) if self._hex_widget is not None else None
        if callable(goto_fn):
            goto_fn(offset)
        _logger.info("va_goto_navigated", va=hex(va), offset=hex(offset))

    def _on_va_conversion_error(self, va: int, exc: object) -> None:
        """Surface a VA-to-file-offset bridge failure to the user.

        Args:
            va: Virtual address that failed to resolve.
            exc: Exception object emitted by the bridge worker.
        """
        parent = self if isinstance(self, QWidget) else None
        _logger.warning("va_to_file_offset_failed", va=hex(va), error=str(exc))
        show_warning(parent, "VA Mapping", f"Conversion failed:\n{exc}")

    def _on_cursor_offset_to_va(self) -> None:
        """Convert the current cursor's file offset to a virtual address."""
        parent = self if isinstance(self, QWidget) else None
        bridge = self._bridge
        if bridge is None:
            show_warning(parent, "VA Mapping", "Hex editor bridge is not attached.")
            return
        cursor_offset = getattr(self._hex_widget, "_cursor_offset", None) if self._hex_widget is not None else None
        if not isinstance(cursor_offset, int):
            show_warning(parent, "VA Mapping", "No cursor position available.")
            return

        run_bridge_coroutine_logged(
            bridge.file_offset_to_va(cursor_offset),
            on_success=lambda result: self._on_file_offset_to_va_resolved(cursor_offset, result),
            on_error=lambda exc: self._on_cursor_offset_conversion_error(cursor_offset, exc),
            parent=parent,
            event="hex_editor_file_offset_to_va",
            logger=_logger,
            offset=hex(cursor_offset),
        )

    def _on_file_offset_to_va_resolved(self, cursor_offset: int, va_result: object) -> None:
        """Report the virtual address resolved from the cursor's file offset.

        Args:
            cursor_offset: File offset that was looked up.
            va_result: Virtual-address payload returned by
                :meth:`HexEditorBridge.file_offset_to_va`, or ``None`` when
                the offset is unmapped.
        """
        if va_result is None:
            if self._va_status_label is not None:
                self._va_status_label.setText(f"file offset 0x{cursor_offset:X} is not mapped to a virtual address")
            return
        if not isinstance(va_result, int):
            return
        va = va_result

        if self._va_status_label is not None:
            self._va_status_label.setText(f"file offset 0x{cursor_offset:X} -> VA 0x{va:X}")
        _logger.info("cursor_offset_to_va_resolved", offset=hex(cursor_offset), va=hex(va))

    def _on_cursor_offset_conversion_error(self, cursor_offset: int, exc: object) -> None:
        """Surface a file-offset-to-VA bridge failure to the user.

        Args:
            cursor_offset: File offset that failed to resolve.
            exc: Exception object emitted by the bridge worker.
        """
        parent = self if isinstance(self, QWidget) else None
        _logger.warning("file_offset_to_va_failed", offset=hex(cursor_offset), error=str(exc))
        show_warning(parent, "VA Mapping", f"Conversion failed:\n{exc}")

    def _on_open_performance_settings(self) -> None:
        """Open the large-file performance dialog and apply chunk/budget changes.

        Reads the current memory usage estimate via
        :meth:`HexEditorBridge.get_memory_usage` on the background bridge
        loop, presents :class:`LargeFileSettingsDialog` once the read
        completes, then applies any changes via
        :meth:`HexEditorBridge.set_chunk_size` / ``set_memory_budget``
        without blocking the Qt main thread.
        """
        parent = self if isinstance(self, QWidget) else None
        bridge = self._bridge
        if bridge is None:
            show_warning(parent, "Performance Settings", "Hex editor bridge is not attached.")
            return

        run_bridge_coroutine_logged(
            bridge.get_memory_usage(),
            on_success=self._on_memory_usage_ready,
            on_error=self._on_get_memory_usage_error,
            parent=parent,
            event="hex_editor_get_memory_usage",
            logger=_logger,
        )

    def _on_get_memory_usage_error(self, exc: object) -> None:
        """Surface a ``get_memory_usage`` bridge failure to the user.

        Args:
            exc: Exception object emitted by the bridge worker.
        """
        parent = self if isinstance(self, QWidget) else None
        show_warning(parent, "Performance Settings", f"Failed to read current memory usage:\n{exc}")

    def _on_memory_usage_ready(self, usage_result: object) -> None:
        """Present the performance-settings dialog once memory usage is known.

        Args:
            usage_result: ``dict`` payload returned by
                :meth:`HexEditorBridge.get_memory_usage`.
        """
        parent = self if isinstance(self, QWidget) else None
        bridge = self._bridge
        if bridge is None:
            return

        usage: dict[str, int] = cast("dict[str, int]", usage_result) if isinstance(usage_result, dict) else {}
        current_chunk_kb = max(1, int(usage.get("chunk_size", 0)) // _BYTES_PER_KB)
        current_budget_mb = max(1, int(usage.get("memory_budget", 0)) // _BYTES_PER_MB)
        current_usage_mb = int(usage.get("usage_bytes", 0)) / _BYTES_PER_MB

        dlg = LargeFileSettingsDialog(current_chunk_kb, current_budget_mb, current_usage_mb, parent)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        chunk_bytes = dlg.chunk_size_kb * _BYTES_PER_KB
        budget_bytes = dlg.memory_budget_mb * _BYTES_PER_MB

        run_bridge_coroutine_logged(
            bridge.set_chunk_size(chunk_bytes),
            on_success=lambda _result: self._on_chunk_size_applied(chunk_bytes, budget_bytes),
            on_error=self._on_apply_performance_settings_error,
            parent=parent,
            event="hex_editor_set_chunk_size",
            logger=_logger,
            level="info",
            chunk_bytes=chunk_bytes,
        )

    def _on_chunk_size_applied(self, chunk_bytes: int, budget_bytes: int) -> None:
        """Apply the memory-budget setting after the chunk size is confirmed.

        Args:
            chunk_bytes: Chunk size, in bytes, already applied to the bridge.
            budget_bytes: Memory budget, in bytes, to apply next.
        """
        parent = self if isinstance(self, QWidget) else None
        bridge = self._bridge
        if bridge is None:
            return

        run_bridge_coroutine_logged(
            bridge.set_memory_budget(budget_bytes),
            on_success=lambda _result: self._on_memory_budget_applied(chunk_bytes, budget_bytes),
            on_error=self._on_apply_performance_settings_error,
            parent=parent,
            event="hex_editor_set_memory_budget",
            logger=_logger,
            level="info",
            budget_bytes=budget_bytes,
        )

    def _on_memory_budget_applied(self, chunk_bytes: int, budget_bytes: int) -> None:
        """Report success once chunk size and memory budget are both applied.

        Args:
            chunk_bytes: Chunk size, in bytes, applied to the bridge.
            budget_bytes: Memory budget, in bytes, applied to the bridge.
        """
        parent = self if isinstance(self, QWidget) else None
        show_info(
            parent,
            "Performance Settings",
            f"Chunk size set to {chunk_bytes // _BYTES_PER_KB} KB, memory budget set to {budget_bytes // _BYTES_PER_MB} MB.",
        )

    def _on_apply_performance_settings_error(self, exc: object) -> None:
        """Surface a ``set_chunk_size`` / ``set_memory_budget`` bridge failure.

        Args:
            exc: Exception object emitted by the bridge worker.
        """
        parent = self if isinstance(self, QWidget) else None
        show_warning(parent, "Performance Settings", f"Failed to apply settings:\n{exc}")
