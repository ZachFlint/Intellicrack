# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Patches mixin for the hex editor panel."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast

from PyQt6.QtWidgets import QFileDialog, QTreeWidget, QTreeWidgetItem, QWidget

from intellicrack.core.logging import get_logger
from intellicrack.ui.dialogs_helpers import show_info, show_warning
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_logged


if TYPE_CHECKING:
    from intellicrack.bridges.hex_editor import HexEditorBridge


_logger = get_logger(__name__)


_BPS_UPS_FORMATS: Final[frozenset[str]] = frozenset({".bps", ".ups"})
_SUFFIX_TO_FORMAT: Final[dict[str, str]] = {
    ".ips": "ips",
    ".ips32": "ips32",
    ".bps": "bps",
    ".ups": "ups",
}


class PatchesMixin:
    """Mixin providing patch tracking and IPS/BPS/UPS import/export for the hex editor panel."""

    _document: Any | None
    document: Any | None
    _hex_widget: Any | None
    _patches_tree: QTreeWidget | None
    _original_data_cache: dict[int, int]
    _bridge: HexEditorBridge | None
    file_path: Path | None
    _pending_export_patches_path: str | None
    _pending_export_patches_count: int
    _pending_export_patches_format: str | None
    _pending_import_patches_path: str | None
    _pending_import_patches_suffix: str | None

    def _on_data_changed(self) -> None:
        """Handle document data-change signals by refreshing derived views."""
        self._update_patches()

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
                _logger.exception("patch_read_failed", offset=off)
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
            _logger.exception("cache_original_byte_failed", offset=offset)
        else:
            if isinstance(raw, (list, bytes, bytearray)):
                self._original_data_cache[offset] = raw[0] if raw else 0

    def _on_export_patches(self) -> None:
        """Export patches via :meth:`HexEditorBridge.export_patches`.

        Routes through the bridge so the GUI, AI tools, and the CLI all produce identical patch wire-format bytes — including the bridge's
        Python-only fallback for hexcore builds without a native exporter. Panel-side ``document.export_patches_*`` calls bypassed that
        fallback and returned different bytes when the native build was missing. Dispatches through :func:`run_bridge_coroutine_logged` so
        BPS/UPS full-file diff/rebuild work does not block the Qt main thread; the returned payload is decoded and written to disk by
        :meth:`_on_export_patches_success`, which runs on the main thread once the bridge call completes.
        """
        if self._patches_tree is None or self.document is None:
            return
        patch_count = self._patches_tree.topLevelItemCount()
        parent = self if isinstance(self, QWidget) else None
        if patch_count == 0:
            show_info(parent, "Export Patches", "No patches to export.")
            return
        bridge = self._bridge
        if bridge is None:
            show_warning(parent, "Export Patches", "Hex editor bridge is not attached.")
            return

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
        patch_format = _SUFFIX_TO_FORMAT.get(suffix)
        if patch_format is None:
            show_warning(
                parent,
                "Export Patches",
                f"Unsupported patch format for extension {suffix!r}.",
            )
            return

        original_path: str | None = None
        if suffix in _BPS_UPS_FORMATS:
            if self.file_path is None or not Path(self.file_path).exists():
                show_warning(
                    parent,
                    "Export Patches",
                    f"{patch_format.upper()} export requires the original unmodified file on disk."
                    " Save the document to a file before exporting BPS/UPS patches.",
                )
                return
            original_path = str(self.file_path)

        self._pending_export_patches_path = save_path
        self._pending_export_patches_count = patch_count
        self._pending_export_patches_format = patch_format
        run_bridge_coroutine_logged(
            bridge.export_patches(patch_format, original_path),
            on_success=self._on_export_patches_success,
            on_error=self._on_export_patches_error,
            parent=parent,
            event="hex_editor_export_patches",
            logger=_logger,
            level="info",
            patch_format=patch_format,
            path=save_path,
            count=patch_count,
        )

    def _on_export_patches_success(self, result: object) -> None:
        """Decode and write the bridge-produced patch payload to disk.

        Args:
            result: Base64-encoded patch bytes returned by :meth:`HexEditorBridge.export_patches`.
        """
        parent = self if isinstance(self, QWidget) else None
        save_path = self._pending_export_patches_path
        patch_count = self._pending_export_patches_count
        patch_format = self._pending_export_patches_format
        self._pending_export_patches_path = None
        self._pending_export_patches_format = None
        if save_path is None or patch_format is None:
            return

        if not isinstance(result, str):
            _logger.error("patches_export_unexpected_type", actual=type(result).__name__)
            show_warning(parent, "Export Patches", "Bridge returned an unexpected payload type.")
            return

        try:
            patch_data = base64.b64decode(result.encode("ascii"))
        except (ValueError, TypeError) as exc:
            _logger.exception("patches_export_b64_decode_failed", patch_format=patch_format)
            show_warning(parent, "Export Patches", f"Bridge returned invalid base64:\n{exc}")
            return

        _logger.info(
            "patches_export_write_begin",
            path=save_path,
            data_size=len(patch_data),
            data_sha256=hashlib.sha256(patch_data).hexdigest()[:12],
            patch_format=patch_format,
        )
        try:
            Path(save_path).write_bytes(patch_data)
        except OSError as exc:
            _logger.exception("patches_export_write_failed", path=save_path)
            show_warning(parent, "Export Patches", f"Export failed:\n{exc}")
            return

        _logger.info(
            "patches_exported",
            path=save_path,
            count=patch_count,
            patch_format=patch_format,
            size=len(patch_data),
        )
        show_info(parent, "Export Patches", f"Exported {patch_count} patch(es).")

    def _on_export_patches_error(self, exc: object) -> None:
        """Report a patch export failure raised by the bridge.

        Args:
            exc: Exception object emitted by the bridge worker.
        """
        parent = self if isinstance(self, QWidget) else None
        self._pending_export_patches_path = None
        self._pending_export_patches_format = None
        show_warning(parent, "Export Patches", f"Export failed:\n{exc}")

    def _on_import_patches(self) -> None:
        """Import patches via :meth:`HexEditorBridge.import_patches`.

        The bridge inspects the patch magic bytes and dispatches to the correct format handler so IPS/IPS32/BPS/UPS all work through one
        API. For BPS/UPS the bridge requires the original unmodified source file so it can rebuild the target deterministically; the panel
        passes ``self.file_path`` when available. Dispatches through :func:`run_bridge_coroutine_logged` so BPS/UPS full-file diff/rebuild
        work does not block the Qt main thread; the returned patch count is applied and the derived views refreshed by
        :meth:`_on_import_patches_success`, which runs on the main thread once the bridge call completes.
        """
        if self.document is None:
            return
        parent = self if isinstance(self, QWidget) else None
        bridge = self._bridge
        if bridge is None:
            show_warning(parent, "Import Patches", "Hex editor bridge is not attached.")
            return

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
            _logger.exception("patches_import_read_failed", path=file_path_str)
            show_warning(parent, "Import Patches", f"Import failed:\n{exc}")
            return

        suffix = Path(file_path_str).suffix.lower()
        original_path: str | None = None
        if suffix in _BPS_UPS_FORMATS:
            if self.file_path is None or not Path(self.file_path).exists():
                show_warning(
                    parent,
                    "Import Patches",
                    f"{suffix[1:].upper()} patches require the original unmodified file on disk."
                    " Open the source file before importing this patch.",
                )
                return
            original_path = str(self.file_path)

        patch_b64 = base64.b64encode(patch_bytes).decode("ascii")
        self._pending_import_patches_path = file_path_str
        self._pending_import_patches_suffix = suffix
        run_bridge_coroutine_logged(
            bridge.import_patches(patch_b64, original_path),
            on_success=self._on_import_patches_success,
            on_error=self._on_import_patches_error,
            parent=parent,
            event="hex_editor_import_patches",
            logger=_logger,
            level="info",
            path=file_path_str,
            suffix=suffix,
        )

    def _on_import_patches_success(self, result: object) -> None:
        """Apply the bridge-reported patch count and refresh derived hex-editor views.

        Args:
            result: Number of patch records applied, returned by :meth:`HexEditorBridge.import_patches`.
        """
        parent = self if isinstance(self, QWidget) else None
        file_path_str = self._pending_import_patches_path
        suffix = self._pending_import_patches_suffix
        self._pending_import_patches_path = None
        self._pending_import_patches_suffix = None
        if file_path_str is None:
            return

        if not isinstance(result, int):
            _logger.error("patches_import_unexpected_type", actual=type(result).__name__)
            show_warning(parent, "Import Patches", "Bridge returned an unexpected payload type.")
            return

        if self._hex_widget is not None:
            update_fn = getattr(self._hex_widget, "_update_viewport", None)
            if callable(update_fn):
                update_fn()
        self._on_data_changed()
        _logger.info("patches_imported", path=file_path_str, count=result, suffix=suffix)
        show_info(parent, "Import Patches", f"Applied {result} patch record(s).")

    def _on_import_patches_error(self, exc: object) -> None:
        """Report a patch import failure raised by the bridge.

        Args:
            exc: Exception object emitted by the bridge worker.
        """
        parent = self if isinstance(self, QWidget) else None
        file_path_str = self._pending_import_patches_path
        self._pending_import_patches_path = None
        self._pending_import_patches_suffix = None
        show_warning(parent, "Import Patches", f"Import failed to {file_path_str}:\n{exc}")
