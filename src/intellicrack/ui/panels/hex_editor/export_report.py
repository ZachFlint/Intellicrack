# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Annotated report export mixin for the hex editor panel."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QLineEdit,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.dialogs_helpers import show_info, show_warning
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_logged


if TYPE_CHECKING:
    from intellicrack.bridges.hex_editor import HexEditorBridge


_logger = get_logger(__name__)


_DEFAULT_BYTES_PER_ROW: Final[int] = 16
_MIN_BYTES_PER_ROW: Final[int] = 1
_MAX_BYTES_PER_ROW: Final[int] = 64


class AnnotatedExportRangeDialog(QDialog):
    """Dialog collecting the byte range and layout for an annotated export.

    Presents start / end offset fields (hex accepted via ``0x`` prefix) alongside a bytes-per-row spin box shared by both the HTML and PDF
    annotated export paths.
    """

    def __init__(self, doc_length: int, parent: QWidget | None = None) -> None:
        """Initialize the AnnotatedExportRangeDialog.

        Args:
            doc_length: Length of the currently open document, used to
                pre-fill the end-offset field with the full document range.
            parent: Parent widget.
        """
        super().__init__(parent)
        self.setWindowTitle("Export Annotated Report")
        self.setMinimumWidth(360)

        layout = QVBoxLayout(self)
        form = QFormLayout()

        self._start_edit = QLineEdit("0x0")
        form.addRow("Start offset:", self._start_edit)

        self._end_edit = QLineEdit(f"0x{doc_length:X}")
        form.addRow("End offset (0 = end of file):", self._end_edit)

        self._bytes_per_row_spin = QSpinBox()
        self._bytes_per_row_spin.setRange(_MIN_BYTES_PER_ROW, _MAX_BYTES_PER_ROW)
        self._bytes_per_row_spin.setValue(_DEFAULT_BYTES_PER_ROW)
        form.addRow("Bytes per row:", self._bytes_per_row_spin)

        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    @staticmethod
    def _parse_offset(text: str) -> int:
        """Parse an offset field accepting decimal or ``0x``-prefixed hex input.

        Args:
            text: Raw field text.

        Returns:
            int: Parsed non-negative offset, or ``0`` if the field is blank
                or malformed.
        """
        stripped = text.strip()
        if not stripped:
            return 0
        try:
            return int(stripped, 16) if stripped.lower().startswith("0x") else int(stripped)
        except ValueError:
            return 0

    @property
    def start_offset(self) -> int:
        """Parsed start offset in bytes.

        Returns:
            int: Start offset in bytes.
        """
        return max(0, self._parse_offset(self._start_edit.text()))

    @property
    def end_offset(self) -> int:
        """Parsed end offset in bytes.

        Returns:
            int: End offset in bytes (``0`` means "entire document").
        """
        return max(0, self._parse_offset(self._end_edit.text()))

    @property
    def bytes_per_row(self) -> int:
        """Selected bytes-per-row layout value.

        Returns:
            int: Number of bytes rendered per row.
        """
        return self._bytes_per_row_spin.value()


class ExportReportMixin:
    """Mixin providing annotated HTML/PDF report export for the hex editor panel."""

    document: Any | None
    _bridge: HexEditorBridge | None
    _pending_html_export_path: str | None
    _pending_pdf_export_path: str | None

    def _on_export_annotated_html(self) -> None:
        """Export the current document as annotated HTML via the bridge.

        Prompts for the byte range and layout, then dispatches :meth:`HexEditorBridge.export_annotated_html` through
        :func:`run_bridge_coroutine_logged` so rendering the annotated range does not block the Qt main thread. The returned HTML string is
        written to the chosen file by :meth:`_on_export_annotated_html_success`, which runs on the main thread once the bridge call
        completes.
        """
        parent = self if isinstance(self, QWidget) else None
        if self.document is None:
            show_warning(parent, "Export Annotated HTML", "No document is open.")
            return
        bridge = self._bridge
        if bridge is None:
            show_warning(parent, "Export Annotated HTML", "Hex editor bridge is not attached.")
            return

        doc_length: int = self.document.length()
        range_dlg = AnnotatedExportRangeDialog(doc_length, parent)
        if range_dlg.exec() != QDialog.DialogCode.Accepted:
            return

        save_result = QFileDialog.getSaveFileName(parent, "Export Annotated HTML", "", "HTML Files (*.html);;All Files (*)")
        save_path = save_result[0] if save_result else ""
        if not save_path:
            return

        start = range_dlg.start_offset
        end = range_dlg.end_offset
        bytes_per_row = range_dlg.bytes_per_row

        self._pending_html_export_path = save_path
        run_bridge_coroutine_logged(
            bridge.export_annotated_html(start, end, bytes_per_row),
            on_success=self._on_export_annotated_html_success,
            on_error=self._on_export_annotated_html_error,
            parent=parent,
            event="hex_editor_export_annotated_html",
            logger=_logger,
            level="info",
            path=save_path,
            start=start,
            end=end,
            bytes_per_row=bytes_per_row,
        )

    def _on_export_annotated_html_success(self, result: object) -> None:
        """Write the bridge-rendered annotated HTML payload to disk.

        Args:
            result: HTML markup string returned by :meth:`HexEditorBridge.export_annotated_html`.
        """
        parent = self if isinstance(self, QWidget) else None
        save_path = self._pending_html_export_path
        self._pending_html_export_path = None
        if save_path is None:
            return

        if not isinstance(result, str):
            _logger.error("export_annotated_html_unexpected_type", actual=type(result).__name__)
            show_warning(parent, "Export Annotated HTML", "Bridge returned an unexpected payload type.")
            return

        try:
            Path(save_path).write_text(result, encoding="utf-8")
        except OSError as exc:
            _logger.exception("export_annotated_html_write_failed", path=save_path)
            show_warning(parent, "Export Annotated HTML", f"Failed to write file:\n{exc}")
            return

        _logger.info("export_annotated_html_complete", path=save_path, size=len(result))
        show_info(parent, "Export Annotated HTML", f"Exported annotated HTML report to:\n{save_path}")

    def _on_export_annotated_html_error(self, exc: object) -> None:
        """Report an annotated HTML export failure raised by the bridge.

        Args:
            exc: Exception object emitted by the bridge worker.
        """
        parent = self if isinstance(self, QWidget) else None
        save_path = self._pending_html_export_path
        self._pending_html_export_path = None
        show_warning(parent, "Export Annotated HTML", f"Export failed to {save_path}:\n{exc}")

    def _on_export_annotated_pdf(self) -> None:
        """Export the current document as an annotated PDF via the bridge.

        Prompts for the byte range and layout, then dispatches :meth:`HexEditorBridge.export_annotated_pdf` through
        :func:`run_bridge_coroutine_logged` so rendering and writing the PDF (which the bridge performs directly at the chosen path) does
        not block the Qt main thread.
        """
        parent = self if isinstance(self, QWidget) else None
        if self.document is None:
            show_warning(parent, "Export Annotated PDF", "No document is open.")
            return
        bridge = self._bridge
        if bridge is None:
            show_warning(parent, "Export Annotated PDF", "Hex editor bridge is not attached.")
            return

        doc_length: int = self.document.length()
        range_dlg = AnnotatedExportRangeDialog(doc_length, parent)
        if range_dlg.exec() != QDialog.DialogCode.Accepted:
            return

        save_result = QFileDialog.getSaveFileName(parent, "Export Annotated PDF", "", "PDF Files (*.pdf);;All Files (*)")
        save_path = save_result[0] if save_result else ""
        if not save_path:
            return

        start = range_dlg.start_offset
        end = range_dlg.end_offset
        bytes_per_row = range_dlg.bytes_per_row

        self._pending_pdf_export_path = save_path
        run_bridge_coroutine_logged(
            bridge.export_annotated_pdf(save_path, start, end, bytes_per_row),
            on_success=self._on_export_annotated_pdf_success,
            on_error=self._on_export_annotated_pdf_error,
            parent=parent,
            event="hex_editor_export_annotated_pdf",
            logger=_logger,
            level="info",
            path=save_path,
            start=start,
            end=end,
            bytes_per_row=bytes_per_row,
        )

    def _on_export_annotated_pdf_success(self, result: object) -> None:
        """Confirm the annotated PDF export the bridge wrote to disk.

        Args:
            result: Path the bridge wrote the rendered PDF to, returned by :meth:`HexEditorBridge.export_annotated_pdf`.
        """
        parent = self if isinstance(self, QWidget) else None
        self._pending_pdf_export_path = None

        if not isinstance(result, str):
            _logger.error("export_annotated_pdf_unexpected_type", actual=type(result).__name__)
            show_warning(parent, "Export Annotated PDF", "Bridge returned an unexpected payload type.")
            return

        _logger.info("export_annotated_pdf_complete", path=result)
        show_info(parent, "Export Annotated PDF", f"Exported annotated PDF report to:\n{result}")

    def _on_export_annotated_pdf_error(self, exc: object) -> None:
        """Report an annotated PDF export failure raised by the bridge.

        Args:
            exc: Exception object emitted by the bridge worker.
        """
        parent = self if isinstance(self, QWidget) else None
        save_path = self._pending_pdf_export_path
        self._pending_pdf_export_path = None
        show_warning(parent, "Export Annotated PDF", f"Export failed to {save_path}:\n{exc}")
