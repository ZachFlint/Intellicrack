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
from typing import Any, ClassVar, Final, cast

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

from intellicrack.ui.panels.hex_editor._base import hexcore, hexcore_available, logger


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

        _fields_: ClassVar[list[tuple[str, type]]] = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", ctypes.wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", ctypes.wintypes.DWORD),
            ("Protect", ctypes.wintypes.DWORD),
            ("Type", ctypes.wintypes.DWORD),
        ]


class ProcessMemoryDialog(QDialog):
    """Dialog for browsing and opening process memory regions.

    Provides a PID input, region listing, and region selection for
    loading process memory into the hex editor. After the dialog is
    accepted, ``region_selected`` holds the chosen ``(pid, base, size)``
    tuple or ``None`` when no region was picked.

    Args:
        parent: Parent widget.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
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
                    return
            except (OSError, RuntimeError, ValueError) as exc:
                logger.debug("process_regions_hexcore_failed", error=str(exc))

        if sys.platform == "win32":
            self._list_regions_ctypes(pid)
        else:
            self._list_regions_procfs(pid)

    def _list_regions_ctypes(self, pid: int) -> None:
        """List process memory regions using Windows ctypes API.

        Args:
            pid: Process ID to query.
        """
        try:
            kernel32 = ctypes.windll.kernel32

            no_inherit: int = 0
            inherit_handle = ctypes.c_bool(no_inherit)
            handle = kernel32.OpenProcess(
                _PROCESS_QUERY_INFORMATION | _PROCESS_VM_READ,
                inherit_handle,
                pid,
            )
            if not handle:
                self._status_label.setText(f"Cannot open process {pid}")
                return

            mbi = MemoryBasicInformation()
            address = 0
            regions: list[tuple[int, int, int, int]] = []

            while kernel32.VirtualQueryEx(
                handle,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            ):
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

            kernel32.CloseHandle(handle)
            self._populate_regions(regions)
            self._status_label.setText(f"{len(regions)} committed region(s) found")
        except (OSError, AttributeError, ValueError) as exc:
            self._status_label.setText(f"Error: {exc}")
            logger.debug("process_regions_ctypes_failed", error=str(exc))

    def _list_regions_procfs(self, pid: int) -> None:
        """List process memory regions from /proc on Linux.

        Args:
            pid: Process ID to query.
        """
        maps_path = Path(f"/proc/{pid}/maps")
        if not maps_path.exists():
            self._status_label.setText(f"Cannot read /proc/{pid}/maps")
            return

        regions: list[tuple[int, int, int, int]] = []
        try:
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
            logger.debug("process_regions_procfs_failed", error=str(exc))
            return

        self._populate_regions(regions)
        self._status_label.setText(f"{len(regions)} region(s) found")

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
            return

        pid = self._pid_spin.value()
        self.region_selected = (pid, base, size)
        self.accept()


class ProcessMemoryMixin:
    """Mixin providing process memory browsing for the hex editor panel."""

    document: Any | None
    _hex_widget: Any | None

    def _on_open_process_memory(self) -> None:
        """Open the process memory dialog and load the selected region."""
        parent = self if isinstance(self, QWidget) else None

        if not hexcore_available or hexcore is None:
            QMessageBox.warning(
                parent,
                "Process Memory",
                "Rust hexcore is required for process memory access.\nBuild with: cd src/intellicrack-hexcore && maturin develop --release",
            )
            return

        dlg = ProcessMemoryDialog(parent)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        if dlg.region_selected is None:
            return

        pid, addr, size = dlg.region_selected

        try:
            from_mem_fn = getattr(hexcore.HexDocument, "from_process_memory", None)
            if not callable(from_mem_fn):
                QMessageBox.warning(parent, "Process Memory", "from_process_memory not available")
                return

            doc = from_mem_fn(pid, addr, size)
            self.document = doc

            if self._hex_widget is not None:
                set_doc = getattr(self._hex_widget, "set_document", None)
                if callable(set_doc):
                    set_doc(doc)

            logger.info("process_memory_opened", pid=pid, address=addr, size=size)
        except (OSError, RuntimeError, ValueError) as exc:
            QMessageBox.warning(
                parent,
                "Process Memory",
                f"Failed to open process memory:\n{exc}",
            )
            logger.warning("process_memory_open_failed", error=str(exc))
