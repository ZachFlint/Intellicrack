# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Patches mixin for the hex editor panel."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from PyQt6.QtWidgets import QFileDialog, QMessageBox, QTreeWidget, QTreeWidgetItem, QWidget

from intellicrack.ui.panels.hex_editor._base import logger


class PatchesMixin:
    """Mixin providing patch tracking and IPS import/export for the hex editor panel."""

    _document: Any | None
    document: Any | None
    _hex_widget: Any | None
    _patches_tree: QTreeWidget | None
    _original_data_cache: dict[int, int]

    def _on_data_changed(self) -> None:
        """Handle document data-change signals by refreshing derived views."""

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
        """Cache the original byte value before first modification.

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
        """Export current patches via hexcore, dispatching on file extension.

        Prompts for a save path and routes to the matching document RPC:
        ``.ips`` -> ``export_patches_ips``; ``.ips32`` -> ``export_patches_ips32``;
        ``.bps`` -> ``export_patches_bps(source_data)``;
        ``.ups`` -> ``export_patches_ups(source_data)``. The source bytes for
        BPS/UPS are read from the document via ``document.read(0, doc_len)``.
        The raw hexcore bytes are written verbatim to the selected file.
        """
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
            "IPS Patches (*.ips);;IPS32 Patches (*.ips32);;BPS Patches (*.bps);;UPS Patches (*.ups);;All Files (*)",
        )
        save_path = result[0] if result else ""
        if not save_path:
            return
        suffix = Path(save_path).suffix.lower()
        try:
            patch_data = self._dispatch_export_patches(suffix)
        except (AttributeError, OSError, RuntimeError, ValueError) as exc:
            logger.debug("patches_export_failed", error=str(exc), suffix=suffix)
            QMessageBox.warning(parent, "Export Patches", f"Export failed:\n{exc}")
            return
        if patch_data is None:
            QMessageBox.warning(
                parent,
                "Export Patches",
                f"Unsupported patch format for extension {suffix!r}.",
            )
            return
        try:
            Path(save_path).write_bytes(patch_data)
        except OSError as exc:
            logger.debug("patches_export_write_failed", error=str(exc), path=save_path)
            QMessageBox.warning(parent, "Export Patches", f"Export failed:\n{exc}")
            return
        logger.info(
            "patches_exported",
            path=save_path,
            count=patch_count,
            suffix=suffix,
            size=len(patch_data),
        )
        QMessageBox.information(parent, "Export Patches", f"Exported {patch_count} patch(es).")

    def _dispatch_export_patches(self, suffix: str) -> bytes | None:
        """Dispatch patch export to the appropriate hexcore document method.

        Args:
            suffix: Lowercase file extension including the leading dot (for
                example ``".ips"``). Unknown suffixes return ``None``.

        Returns:
            bytes | None: Raw hexcore patch bytes for the requested format,
                or ``None`` if ``suffix`` is not a supported patch extension
                or the document does not expose the required method.
        """
        document: Any = self.document
        if document is None:
            return None
        if suffix == ".ips32":
            export_ips32: Any = getattr(document, "export_patches_ips32", None)
            if callable(export_ips32):
                return self._coerce_patch_bytes(export_ips32())
            return None
        if suffix == ".ips":
            export_ips: Any = getattr(document, "export_patches_ips", None)
            if callable(export_ips):
                return self._coerce_patch_bytes(export_ips())
            return None
        if suffix == ".bps":
            export_bps: Any = getattr(document, "export_patches_bps", None)
            if callable(export_bps):
                source_data = self._read_document_bytes()
                return self._coerce_patch_bytes(export_bps(source_data))
            return None
        if suffix == ".ups":
            export_ups: Any = getattr(document, "export_patches_ups", None)
            if callable(export_ups):
                source_data = self._read_document_bytes()
                return self._coerce_patch_bytes(export_ups(source_data))
            return None
        return None

    @staticmethod
    def _coerce_patch_bytes(raw: object) -> bytes:
        """Coerce a hexcore patch export return value into immutable ``bytes``.

        Args:
            raw: Value returned by a hexcore ``export_patches_*`` method.
                Typically ``bytes`` or ``bytearray``; ``list[int]`` is also
                accepted for compatibility with Python-only fallbacks.

        Returns:
            bytes: Raw patch bytes. Returns empty bytes when ``raw`` is not a
                recognized byte-sequence type.
        """
        if isinstance(raw, bytes):
            return raw
        if isinstance(raw, bytearray):
            return bytes(raw)
        if isinstance(raw, list):
            return bytes(cast("list[int]", raw))
        return b""

    def _read_document_bytes(self) -> bytes:
        """Read the entire document buffer via hexcore.

        Returns:
            bytes: Current document contents from offset ``0`` for
                ``document.length()`` bytes. Returns empty bytes when the
                document is closed or exposes no length/read methods.
        """
        document: Any = self.document
        if document is None:
            return b""
        length_fn: Any = getattr(document, "length", None)
        read_fn: Any = getattr(document, "read", None)
        if not callable(length_fn) or not callable(read_fn):
            return b""
        length_val: Any = length_fn()
        if not isinstance(length_val, int):
            return b""
        if length_val <= 0:
            return b""
        raw: Any = read_fn(0, length_val)
        if isinstance(raw, bytes):
            return raw
        if isinstance(raw, bytearray):
            return bytes(raw)
        if isinstance(raw, list):
            return bytes(cast("list[int]", raw))
        return b""

    def _on_import_patches(self) -> None:
        """Import patches via hexcore, dispatching on file extension.

        Reads the selected patch file and routes to the matching document RPC:
        ``.ips`` / ``.ips32`` -> ``import_patches_ips(bytes)``;
        ``.bps`` -> ``import_patches_bps(data, source_data)``;
        ``.ups`` -> ``import_patches_ups(data, source_data)``. The source bytes
        for BPS/UPS are read from the document via ``document.read(0, doc_len)``
        so the patch is applied against the current document contents.
        """
        if self.document is None:
            return
        parent = self if isinstance(self, QWidget) else None
        result = QFileDialog.getOpenFileName(
            parent,
            "Import Patches",
            "",
            "Patch Files (*.ips *.ips32 *.bps *.ups);;All Files (*)",
        )
        file_path_str = result[0] if result else ""
        if not file_path_str:
            return
        try:
            patch_bytes = Path(file_path_str).read_bytes()
        except OSError as exc:
            logger.debug("patches_import_read_failed", error=str(exc), path=file_path_str)
            QMessageBox.warning(parent, "Import Patches", f"Import failed:\n{exc}")
            return

        suffix = Path(file_path_str).suffix.lower()
        try:
            applied = self._dispatch_import_patches(suffix, patch_bytes)
        except (AttributeError, OSError, RuntimeError, ValueError) as exc:
            logger.debug("patches_import_failed", error=str(exc), suffix=suffix)
            QMessageBox.warning(parent, "Import Patches", f"Import failed:\n{exc}")
            return
        if applied is None:
            QMessageBox.warning(
                parent,
                "Import Patches",
                f"Unsupported patch format for extension {suffix!r}.",
            )
            return

        if self._hex_widget is not None:
            update_fn = getattr(self._hex_widget, "_update_viewport", None)
            if callable(update_fn):
                update_fn()
        self._on_data_changed()
        logger.info("patches_imported", path=file_path_str, count=applied, suffix=suffix)
        QMessageBox.information(parent, "Import Patches", f"Applied {applied} patch record(s).")

    def _dispatch_import_patches(self, suffix: str, patch_bytes: bytes) -> int | None:
        """Dispatch patch import to the appropriate hexcore document method.

        Args:
            suffix: Lowercase file extension including the leading dot (for
                example ``".bps"``).
            patch_bytes: Raw patch payload read from disk.

        Returns:
            int | None: Count of patch records applied, as returned by the
                hexcore document method. Returns ``None`` when ``suffix`` is
                not a supported patch extension or the document does not
                expose the required method.
        """
        document: Any = self.document
        if document is None:
            return None
        if suffix in {".ips", ".ips32"}:
            import_ips: Any = getattr(document, "import_patches_ips", None)
            if callable(import_ips):
                return self._coerce_patch_count(import_ips(patch_bytes))
            return None
        if suffix == ".bps":
            import_bps: Any = getattr(document, "import_patches_bps", None)
            if callable(import_bps):
                source_data = self._read_document_bytes()
                return self._coerce_patch_count(import_bps(patch_bytes, source_data))
            return None
        if suffix == ".ups":
            import_ups: Any = getattr(document, "import_patches_ups", None)
            if callable(import_ups):
                source_data = self._read_document_bytes()
                return self._coerce_patch_count(import_ups(patch_bytes, source_data))
            return None
        return None

    @staticmethod
    def _coerce_patch_count(raw: object) -> int:
        """Coerce a hexcore patch import return value into a non-negative count.

        Args:
            raw: Value returned by a hexcore ``import_patches_*`` method.
                Expected to be an integer record count.

        Returns:
            int: The applied-record count when ``raw`` is an integer;
                ``0`` otherwise so callers never report a negative count.
        """
        if isinstance(raw, int):
            return raw
        return 0
