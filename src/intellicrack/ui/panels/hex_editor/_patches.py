# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Patches mixin for the hex editor panel."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any, cast

from PyQt6.QtWidgets import QFileDialog, QMessageBox, QTreeWidget, QTreeWidgetItem, QWidget

from intellicrack.ui.panels.hex_editor._base import (
    IPS32_OFFSET_SIZE,
    IPS_HEADER_SIZE,
    IPS_LENGTH_FIELD_SIZE,
    IPS_OFFSET_SIZE,
    logger,
)


class PatchesMixin:
    """Mixin providing patch tracking and IPS import/export for the hex editor panel."""

    _document: Any | None
    document: Any | None
    _hex_widget: Any | None
    _patches_tree: QTreeWidget | None
    _original_data_cache: dict[int, int]

    def _on_data_changed(self) -> None: ...

    def _update_patches(self) -> None:
        """Update the patches tree by comparing modified offsets to originals."""
        if self._patches_tree is None or self.document is None or self._hex_widget is None:
            return

        modified_offsets: set[int] = getattr(self._hex_widget, "_modified_offsets", set())
        if not modified_offsets:
            return

        for off in sorted(modified_offsets):
            if off not in self._original_data_cache:
                continue

            original_byte = self._original_data_cache[off]
            current_byte: int = -1
            try:
                raw_patch: object = self.document.read(off, 1)
                if (isinstance(raw_patch, bytes) and len(raw_patch) > 0) or (isinstance(raw_patch, bytearray) and len(raw_patch) > 0):
                    current_byte = raw_patch[0]
                elif isinstance(raw_patch, list) and (patch_list := cast("list[int]", raw_patch)):
                    current_byte = patch_list[0]
            except (AttributeError, ValueError):
                logger.debug("patch_read_failed", offset=off)
                continue

            if current_byte < 0:
                continue

            if current_byte != original_byte:
                existing = False
                for i in range(self._patches_tree.topLevelItemCount()):
                    tree_item = self._patches_tree.topLevelItem(i)
                    if tree_item is not None and tree_item.text(0) == f"0x{off:08X}":
                        tree_item.setText(2, f"0x{current_byte:02X}")
                        existing = True
                        break
                if not existing:
                    patch_item = QTreeWidgetItem([
                        f"0x{off:08X}",
                        f"0x{original_byte:02X}",
                        f"0x{current_byte:02X}",
                    ])
                    self._patches_tree.addTopLevelItem(patch_item)

    def _cache_original_byte(self, offset: int) -> None:
        """
        Cache the original byte value before first modification.

        Args:
            offset: Byte offset to cache.
        """
        if offset in self._original_data_cache or self.document is None:
            return
        try:
            raw = self.document.read(offset, 1)
        except (AttributeError, ValueError):
            logger.debug("cache_original_byte_failed", offset=offset)
        else:
            if isinstance(raw, (list, bytes, bytearray)):
                self._original_data_cache[offset] = raw[0] if raw else 0

    def _on_export_patches(self) -> None:
        """Export current patches to an IPS or IPS32 patch file."""
        if self._patches_tree is None or self.document is None:
            return
        patch_count = self._patches_tree.topLevelItemCount()
        if patch_count == 0:
            parent = self if isinstance(self, QWidget) else None
            QMessageBox.information(parent, "Export Patches", "No patches to export.")
            return
        parent = self if isinstance(self, QWidget) else None
        result = QFileDialog.getSaveFileName(
            parent,
            "Export Patches",
            "",
            "IPS Patches (*.ips);;IPS32 Patches (*.ips32);;All Files (*)",
        )
        save_path = result[0] if result else ""
        if not save_path:
            return
        use_ips32 = save_path.lower().endswith(".ips32")
        try:
            records: list[bytes] = []
            for i in range(patch_count):
                tree_item = self._patches_tree.topLevelItem(i)
                if tree_item is None:
                    continue
                offset_text = tree_item.text(0).strip()
                new_text = tree_item.text(2).strip()
                if not offset_text or not new_text:
                    continue
                offset_val = int(offset_text, 16)
                new_byte = int(new_text, 16)
                if use_ips32:
                    records.append(struct.pack(">I", offset_val))
                else:
                    records.append(struct.pack(">I", offset_val)[1:])
                records.extend((struct.pack(">H", 1), bytes([new_byte])))
            patch_data = b"PATCH" + b"".join(records) + b"EOF"
            Path(save_path).write_bytes(patch_data)
        except (struct.error, OSError, ValueError) as exc:
            logger.debug("patches_export_failed", error=str(exc))
            QMessageBox.warning(parent, "Export Patches", f"Export failed:\n{exc}")
        else:
            logger.info("patches_exported", path=save_path, count=patch_count)
            QMessageBox.information(parent, "Export Patches", f"Exported {patch_count} patch(es).")

    def _on_import_patches(self) -> None:
        """Import patches from an IPS or IPS32 file and apply them to the document."""
        if self.document is None:
            return
        parent = self if isinstance(self, QWidget) else None
        result = QFileDialog.getOpenFileName(
            parent,
            "Import Patches",
            "",
            "Patch Files (*.ips *.ips32);;All Files (*)",
        )
        file_path_str = result[0] if result else ""
        if not file_path_str:
            return
        try:
            patch_bytes = Path(file_path_str).read_bytes()
        except OSError as exc:
            logger.debug("patches_import_failed", error=str(exc))
            QMessageBox.warning(parent, "Import Patches", f"Import failed:\n{exc}")
            return

        use_ips32 = file_path_str.lower().endswith(".ips32")
        if not patch_bytes.startswith(b"PATCH"):
            QMessageBox.warning(parent, "Import Patches", "Not a valid IPS file (missing PATCH header).")
            return

        pos = IPS_HEADER_SIZE
        applied = 0
        eof_marker = b"EOF"
        offset_size = IPS32_OFFSET_SIZE if use_ips32 else IPS_OFFSET_SIZE
        try:
            while pos + offset_size + IPS_LENGTH_FIELD_SIZE <= len(patch_bytes) and patch_bytes[pos : pos + IPS_OFFSET_SIZE] != eof_marker:
                if use_ips32:
                    (patch_offset,) = struct.unpack(">I", patch_bytes[pos : pos + IPS32_OFFSET_SIZE])
                    pos += IPS32_OFFSET_SIZE
                else:
                    (patch_offset,) = struct.unpack(">I", b"\x00" + patch_bytes[pos : pos + IPS_OFFSET_SIZE])
                    pos += IPS_OFFSET_SIZE
                (length,) = struct.unpack(">H", patch_bytes[pos : pos + IPS_LENGTH_FIELD_SIZE])
                pos += IPS_LENGTH_FIELD_SIZE
                if length == 0:
                    if pos + IPS_LENGTH_FIELD_SIZE > len(patch_bytes):
                        break
                    (rle_len,) = struct.unpack(">H", patch_bytes[pos : pos + IPS_LENGTH_FIELD_SIZE])
                    pos += IPS_LENGTH_FIELD_SIZE
                    rle_byte = patch_bytes[pos]
                    pos += 1
                    data_to_write = bytes([rle_byte] * rle_len)
                else:
                    if pos + length > len(patch_bytes):
                        break
                    data_to_write = patch_bytes[pos : pos + length]
                    pos += length
                self.document.write_bytes(patch_offset, bytes(data_to_write))
                applied += 1
        except (struct.error, AttributeError, ValueError, IndexError) as exc:
            logger.debug("patches_import_failed", error=str(exc))
            QMessageBox.warning(parent, "Import Patches", f"Import failed:\n{exc}")
        else:
            if self._hex_widget is not None:
                update_fn = getattr(self._hex_widget, "_update_viewport", None)
                if callable(update_fn):
                    update_fn()
            self._on_data_changed()
            logger.info("patches_imported", path=file_path_str, count=applied)
            QMessageBox.information(parent, "Import Patches", f"Applied {applied} patch record(s).")
