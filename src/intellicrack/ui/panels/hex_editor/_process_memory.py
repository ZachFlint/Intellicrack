# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Process memory mixin for the hex editor panel."""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast

from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_logged
from intellicrack.ui.panels.hex_editor._base import hexcore, hexcore_available


if TYPE_CHECKING:
    from collections.abc import Coroutine

    from intellicrack.bridges.hex_editor import HexEditorBridge


_logger = get_logger(__name__)


_MAX_PID: Final[int] = 999999
_TABLE_COLUMNS: Final[int] = 4
_COL_BASE: Final[int] = 0
_COL_SIZE: Final[int] = 1
_COL_PROT: Final[int] = 2
_COL_STATE: Final[int] = 3

_PROCESS_QUERY_INFORMATION: Final[int] = 0x0400
_PROCESS_VM_READ: Final[int] = 0x0010
_MEM_COMMIT: Final[int] = 0x1000
_ADDR_RANGE_PARTS: Final[int] = 2
_USER_VA_LIMIT: Final[int] = 1 << 47
_PROT_READ: Final[int] = 1
_PROT_WRITE: Final[int] = 2
_PROT_EXEC: Final[int] = 4


if sys.platform == "win32":

    class MemoryBasicInformation(ctypes.Structure):
        """Windows MEMORY_BASIC_INFORMATION structure for VirtualQueryEx."""

        _fields_ = (
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", ctypes.wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", ctypes.wintypes.DWORD),
            ("Protect", ctypes.wintypes.DWORD),
            ("Type", ctypes.wintypes.DWORD),
        )


class ProcessMemoryDialog(QDialog):
    """Dialog for browsing and opening process memory regions.

    Provides a PID input, region listing, and region selection for loading process memory into the hex editor. After the dialog is accepted,
    ``region_selected`` holds the chosen ``(pid, base, size)`` tuple or ``None`` when no region was picked.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the ProcessMemoryDialog.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self.setWindowTitle("Open Process Memory")
        self.setMinimumWidth(500)
        self.setMinimumHeight(400)

        self.region_selected: tuple[int, int, int] | None = None

        layout = QVBoxLayout(self)

        pid_row = QHBoxLayout()
        pid_row.addWidget(QLabel("PID:"))
        self._pid_spin = QSpinBox()
        self._pid_spin.setRange(0, _MAX_PID)
        pid_row.addWidget(self._pid_spin)
        list_btn = QPushButton("List Regions")
        list_btn.clicked.connect(self._on_list_regions)
        pid_row.addWidget(list_btn)
        pid_row.addStretch()
        layout.addLayout(pid_row)

        self._status_label = QLabel("")
        layout.addWidget(self._status_label)

        self._regions_table = QTableWidget(0, _TABLE_COLUMNS)
        self._regions_table.setHorizontalHeaderLabels([
            "Base Address",
            "Size",
            "Protection",
            "State",
        ])
        self._regions_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._regions_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self._regions_table)

        open_btn = QPushButton("Open Selected Region")
        open_btn.clicked.connect(self._on_open_region)
        layout.addWidget(open_btn)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _on_list_regions(self) -> None:
        """Query memory regions for the specified PID and populate the table."""
        pid = self._pid_spin.value()
        self._regions_table.setRowCount(0)

        _logger.info(
            "process_memory_list_regions_started",
            pid=pid,
            hexcore_available=hexcore_available,
            platform=sys.platform,
        )

        if hexcore_available and hexcore is not None:
            try:
                list_fn = getattr(hexcore.HexDocument, "list_process_memory_regions", None)
                if callable(list_fn):
                    raw_regions = list_fn(pid)
                    regions: list[tuple[int, int, int, int]] = cast(
                        "list[tuple[int, int, int, int]]",
                        raw_regions,
                    )
                    self._populate_regions(regions)
                    self._status_label.setText(f"{len(regions)} region(s) found")
                    _logger.info(
                        "process_memory_list_regions_complete",
                        pid=pid,
                        backend="hexcore",
                        region_count=len(regions),
                    )
                    return
            except (OSError, RuntimeError, ValueError):
                _logger.exception("process_regions_hexcore_failed", pid=pid)

        if sys.platform == "win32":
            self._list_regions_ctypes(pid)
        else:
            self._list_regions_procfs(pid)

    def _list_regions_ctypes(self, pid: int) -> None:
        """List process memory regions using Windows ctypes API.

        Args:
            pid: Process ID to query.
        """
        access_mask = _PROCESS_QUERY_INFORMATION | _PROCESS_VM_READ
        try:
            kernel32 = ctypes.windll.kernel32

            no_inherit: int = 0
            inherit_handle = ctypes.c_bool(no_inherit)
            _logger.info(
                "win32_open_process_call",
                pid=pid,
                access=f"0x{access_mask:08X}",
                inherit_handle=False,
            )
            handle = kernel32.OpenProcess(
                access_mask,
                inherit_handle,
                pid,
            )
            if not handle:
                self._status_label.setText(f"Cannot open process {pid}")
                _logger.warning(
                    "win32_open_process_failed",
                    pid=pid,
                    access=f"0x{access_mask:08X}",
                )
                return

            _logger.debug("win32_open_process_handle_acquired", pid=pid)

            mbi = MemoryBasicInformation()
            address = 0
            regions: list[tuple[int, int, int, int]] = []
            query_calls = 0

            while kernel32.VirtualQueryEx(
                handle,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            ):
                query_calls += 1
                if mbi.State == _MEM_COMMIT:
                    regions.append((
                        mbi.BaseAddress or 0,
                        mbi.RegionSize,
                        mbi.Protect,
                        mbi.State,
                    ))
                address = (mbi.BaseAddress or 0) + mbi.RegionSize
                if address >= _USER_VA_LIMIT:
                    break

            _logger.debug(
                "win32_virtual_query_ex_complete",
                pid=pid,
                query_calls=query_calls,
                committed_regions=len(regions),
            )

            close_status = kernel32.CloseHandle(handle)
            _logger.debug(
                "win32_close_handle_called",
                pid=pid,
                status=int(close_status) if close_status is not None else None,
            )
            self._populate_regions(regions)
            self._status_label.setText(f"{len(regions)} committed region(s) found")
            _logger.info(
                "process_memory_list_regions_complete",
                pid=pid,
                backend="ctypes",
                region_count=len(regions),
            )
        except (OSError, AttributeError, ValueError) as exc:
            self._status_label.setText(f"Error: {exc}")
            _logger.exception("process_regions_ctypes_failed", pid=pid, error=str(exc))

    def _list_regions_procfs(self, pid: int) -> None:
        """List process memory regions from /proc on Linux.

        Args:
            pid: Process ID to query.
        """
        maps_path = Path(f"/proc/{pid}/maps")
        if not maps_path.exists():
            self._status_label.setText(f"Cannot read /proc/{pid}/maps")
            _logger.warning("procfs_maps_unavailable", pid=pid, path=str(maps_path))
            return

        regions: list[tuple[int, int, int, int]] = []
        try:
            _logger.info("procfs_maps_read_begin", pid=pid, path=str(maps_path))
            for line in maps_path.read_text(encoding="utf-8").splitlines():
                parts = line.split()
                if not parts:
                    continue
                addr_range = parts[0].split("-")
                if len(addr_range) != _ADDR_RANGE_PARTS:
                    continue
                start = int(addr_range[0], 16)
                end = int(addr_range[1], 16)
                perms_str = parts[1] if len(parts) > 1 else "----"
                prot = 0
                if "r" in perms_str:
                    prot |= _PROT_READ
                if "w" in perms_str:
                    prot |= _PROT_WRITE
                if "x" in perms_str:
                    prot |= _PROT_EXEC
                regions.append((start, end - start, prot, _MEM_COMMIT))
        except (OSError, ValueError) as exc:
            self._status_label.setText(f"Error: {exc}")
            _logger.exception("process_regions_procfs_failed", pid=pid, error=str(exc))
            return

        self._populate_regions(regions)
        self._status_label.setText(f"{len(regions)} region(s) found")
        _logger.info(
            "process_memory_list_regions_complete",
            pid=pid,
            backend="procfs",
            region_count=len(regions),
        )

    def _populate_regions(self, regions: list[tuple[int, int, int, int]]) -> None:
        """Fill the table widget with memory region data.

        Args:
            regions: List of (base_address, size, protection, state) tuples.
        """
        self._regions_table.setRowCount(len(regions))
        for row, (base, size, prot, state) in enumerate(regions):
            self._regions_table.setItem(row, _COL_BASE, QTableWidgetItem(f"0x{base:016X}"))
            self._regions_table.setItem(row, _COL_SIZE, QTableWidgetItem(f"0x{size:X} ({size})"))
            self._regions_table.setItem(row, _COL_PROT, QTableWidgetItem(f"0x{prot:X}"))
            self._regions_table.setItem(row, _COL_STATE, QTableWidgetItem(f"0x{state:X}"))

    def _on_open_region(self) -> None:
        """Store the selected region and accept the dialog."""
        row = self._regions_table.currentRow()
        if row < 0:
            return

        base_item = self._regions_table.item(row, _COL_BASE)
        size_item = self._regions_table.item(row, _COL_SIZE)
        if base_item is None or size_item is None:
            return

        try:
            base_text = base_item.text().strip()
            base = int(base_text, 16)
            size_text = size_item.text().split("(")[0].strip()
            size = int(size_text, 16)
        except ValueError:
            _logger.exception("process_region_parse_failed", row=row)
            return

        pid = self._pid_spin.value()
        self.region_selected = (pid, base, size)
        self.accept()


class ProcessMemoryMixin:
    """Mixin providing process memory browsing for the hex editor panel."""

    document: Any | None
    _hex_widget: Any | None
    _bridge: HexEditorBridge | None

    def _on_open_process_memory(self) -> None:
        """Open the process memory dialog and route the selected region through the bridge.

        Routing through :meth:`HexEditorBridge.open_process_memory` is
        the only correct path: the bridge closes any existing document,
        publishes a ``DOCUMENT_OPENED`` event on the shared state holder,
        updates ``binary_loaded`` / ``target_path`` / cursor / selection,
        and only then exposes the new document to subscribers (AI tools,
        peer GUIs). The previous implementation hard-replaced
        ``self.document`` and left the bridge pointing at the old map,
        so every consumer asking the bridge what it had open got stale
        state.
        """
        parent = self if isinstance(self, QWidget) else None

        if not hexcore_available or hexcore is None:
            QMessageBox.warning(
                parent,
                "Process Memory",
                "Rust hexcore is required for process memory access.\nBuild with: cd src/intellicrack-hexcore && maturin develop --release",
            )
            return

        bridge = self._bridge
        if bridge is None:
            QMessageBox.warning(
                parent,
                "Process Memory",
                "The hex editor bridge is not attached to this panel.",
            )
            return

        dlg = ProcessMemoryDialog(parent)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        if dlg.region_selected is None:
            return

        pid, addr, size = dlg.region_selected
        coro: Coroutine[object, object, dict[str, Any]] = bridge.open_process_memory(pid, addr, size)
        run_bridge_coroutine_logged(
            coro,
            on_success=self._on_process_memory_success,
            on_error=self._on_process_memory_error,
            parent=parent,
            event="hex_editor_open_process_memory",
            logger=_logger,
            level="info",
            pid=pid,
            address=hex(addr),
            size=size,
        )

    def _on_process_memory_success(self, result: object) -> None:
        """Adopt the bridge's freshly-opened document into the panel widgets.

        The bridge has already updated its own document attribute and
        emitted ``DOCUMENT_OPENED`` on the state holder. This handler
        only mirrors the resulting document into the panel-local
        attributes the GUI reads from, so the hex view repaints with
        the new contents even if the panel's state-holder subscription
        is filtered (loop-guard) on its own ``"bridge"`` source.

        Args:
            result: ``dict`` payload returned by
                :meth:`HexEditorBridge.open_process_memory` containing
                ``pid``, ``address``, ``size`` and ``document_length``.
        """
        bridge = getattr(self, "_bridge", None)
        if bridge is None:
            return
        new_document = getattr(bridge, "document", None)
        if new_document is None:
            _logger.warning("process_memory_success_no_document")
            return
        self.document = new_document
        if self._hex_widget is not None:
            set_doc = getattr(self._hex_widget, "set_document", None)
            if callable(set_doc):
                set_doc(new_document)
        if isinstance(result, dict):
            payload: dict[str, Any] = cast("dict[str, Any]", result)
            _logger.info(
                "process_memory_success",
                pid=payload.get("pid"),
                address=payload.get("address"),
                size=payload.get("size"),
                document_length=payload.get("document_length"),
            )
        else:
            _logger.info("process_memory_success_unknown_payload_shape")

    def _on_process_memory_error(self, exc: object) -> None:
        """Surface a bridge ``open_process_memory`` failure to the user.

        Args:
            exc: Exception object emitted by the bridge worker.
        """
        parent = self if isinstance(self, QWidget) else None
        QMessageBox.warning(
            parent,
            "Process Memory",
            f"Failed to open process memory:\n{exc}",
        )
        _logger.warning(
            "process_memory_open_failed",
            error_type=type(exc).__name__,
            error=str(exc),
        )
