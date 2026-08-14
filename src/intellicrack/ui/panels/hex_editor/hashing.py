# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Hashing mixin for the hex editor panel."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast

from PyQt6.QtWidgets import (
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.dialogs_helpers import show_warning
from intellicrack.ui.panels.async_bridge import GenericCallableWorker
from intellicrack.ui.panels.hex_editor.widgets import CustomCrcDialog


if TYPE_CHECKING:
    from collections.abc import Callable

_logger = get_logger(__name__)


_DOS_E_LFANEW_OFFSET: Final[int] = 0x3C
_PE_CHECKSUM_OFFSET_FROM_E_LFANEW: Final[int] = 4 + 20 + 64
_PE_CHECKSUM_LEN: Final[int] = 4
_PE_CHECKSUM_REPAIR_SYNC_WAIT_MS: Final[int] = 100
"""Bounded join, in milliseconds, ``_on_repair_pe_checksum`` waits on the repair worker before returning.

The repair worker still runs ``document.repair_pe_checksum`` on a background ``GenericCallableWorker`` thread so a multi-gigabyte image
never blocks the Qt event loop. For the vast majority of PE images the repair (a header write plus a checksum scan) completes in well under
this budget, so joining briefly lets the caller observe the finished write and the fired notification immediately instead of only after the
GUI thread's event loop happens to process the worker's queued completion signal. Genuinely large images simply time out this short join and
continue asynchronously exactly as before.
"""

def _format_hash_result(document: object, algo: str) -> str:
    """Compute the document hash and format it for display.

    Runs on a background ``GenericCallableWorker`` thread so hashing a large document never blocks the Qt event loop.

    Args:
        document: Hex document exposing ``compute_hash``.
        algo: Hash algorithm name selected in the UI.

    Returns:
        str: Formatted ``"<algo>: <hash>"`` display string.

    Raises:
        RuntimeError: If the document fails to compute the hash.
        OSError: If reading the underlying file fails.
        ValueError: If the algorithm name is not recognised.
        AttributeError: If the document does not expose ``compute_hash``.
    """
    doc: Any = document
    try:
        result = doc.compute_hash(algo)
    except (RuntimeError, OSError, ValueError, AttributeError):
        _logger.exception("hash_calculate_failed", algo=algo)
        raise
    _logger.info("hash_calculated", algo=algo)
    return f"{algo}: {result}"


def _format_hash_range_result(document: object, start: int, end: int, algo: str) -> str:
    """Compute the hash of a byte range and format it for display.

    Runs on a background ``GenericCallableWorker`` thread so hashing a large selection never blocks the Qt event loop.

    Args:
        document: Hex document exposing ``compute_hash_range``.
        start: Start byte offset of the range, inclusive.
        end: End byte offset of the range, exclusive.
        algo: Hash algorithm name selected in the UI.

    Returns:
        str: Formatted ``"<algo> (0x<start>-0x<end>): <hash>"`` display string.

    Raises:
        RuntimeError: If the document fails to compute the hash.
        OSError: If reading the underlying file fails.
        ValueError: If the algorithm name is not recognised.
        AttributeError: If the document does not expose ``compute_hash_range``.
    """
    doc: Any = document
    try:
        result = doc.compute_hash_range(start, end, algo)
    except (RuntimeError, OSError, ValueError, AttributeError):
        _logger.exception("hash_selection_failed", algo=algo, start=start, end=end)
        raise
    _logger.info("hash_selection_calculated", algo=algo, start=start, end=end)
    return f"{algo} (0x{start:X}-0x{end:X}): {result}"


class HashingMixin:
    """Mixin providing hash computation for the hex editor panel.

    All hash and PE-checksum work is delegated to the hexcore document so that the UI thread never has to materialise the full file in
    Python. Every document call that scans the full file (hashing, PE-checksum verification and repair) runs on a background
    ``GenericCallableWorker`` thread so the Qt event loop keeps pumping while a multi-hundred-megabyte or multi-gigabyte file is processed.
    The mixin only formats the returned values for display.
    """

    _document: Any | None
    document: Any | None
    _hex_widget: Any | None
    _hash_algo_combo: QComboBox | None
    _hash_result_label: QLabel | None
    _selection_start: int
    _selection_end: int
    _pe_checksum_status: QLabel | None
    state_holder: Any | None
    file_path: Path | None
    _custom_crc_worker: Any | None
    _hash_worker: GenericCallableWorker | None
    _pe_checksum_worker: GenericCallableWorker | None

    def _notify_state_data_modified_for_hashing(self, offset: int, length: int, *, source: str) -> None:
        """Publish a hashing-related byte mutation to ``HexDocumentState`` when present.

        Args:
            offset: Start byte offset of the affected range.
            length: Number of bytes affected.
            source: Loop-guard identifier so this caller is filtered from echoes.
        """
        holder = self.state_holder
        if holder is None:
            return
        notify = getattr(holder, "notify_data_modified", None)
        if not callable(notify):
            return
        notify(offset, length, source=source)

    def _resolve_custom_crc_file_path(self) -> str | None:
        """Resolve the best file source for the custom CRC streaming worker.

        Prefers the panel's ``file_path`` attribute when present and
        readable; falls back to ``document.file_path()`` when the
        document exposes one. Returns ``None`` when the document is
        purely in-memory so the worker streams via the document API.

        Returns:
            str | None: Absolute path of an existing readable file, or
                ``None`` when the worker should stream via the
                document API.
        """
        candidates: list[str] = []
        panel_path = self.file_path
        if panel_path is not None:
            try:
                candidates.append(os.fspath(panel_path))
            except TypeError:
                _logger.warning("custom_crc_panel_path_unfsable", path_type=type(panel_path).__name__)
        document = self.document
        if document is not None:
            doc_path_fn = getattr(document, "file_path", None)
            if callable(doc_path_fn):
                try:
                    doc_path: object = doc_path_fn()
                except (OSError, RuntimeError, ValueError) as exc:
                    _logger.debug(
                        "custom_crc_doc_path_unavailable",
                        error_type=type(exc).__name__,
                        exc_info=True,
                    )
                    doc_path = None
                if isinstance(doc_path, str):
                    candidates.append(doc_path)
                elif doc_path is not None:
                    try:
                        candidates.append(os.fspath(cast("os.PathLike[str]", doc_path)))
                    except TypeError:
                        _logger.warning(
                            "custom_crc_doc_path_unfsable",
                            path_type=type(doc_path).__name__,
                        )
        for path_str in candidates:
            if not path_str:
                continue
            try:
                if Path(path_str).is_file():
                    return path_str
            except OSError as exc:
                _logger.warning("custom_crc_candidate_unreachable", candidate=path_str, error=str(exc))
                continue
        return None

    def _spawn_hex_worker(
        self,
        existing: GenericCallableWorker | None,
        func: Callable[..., object],
        args: tuple[object, ...],
        on_success: Callable[[object], None],
        on_error: Callable[[object], None],
    ) -> GenericCallableWorker | None:
        """Start a background ``GenericCallableWorker`` unless one is already running.

        Args:
            existing: The previously tracked worker for this operation category, if any.
            func: Callable executed on the background thread.
            args: Positional arguments forwarded to ``func``.
            on_success: Slot invoked on the main thread with the callable's result.
            on_error: Slot invoked on the main thread with the raised exception.

        Returns:
            GenericCallableWorker | None: The newly started worker, or ``None``
                when ``existing`` is still running and no new worker was started.
        """
        if existing is not None and existing.isRunning():
            _logger.warning("hex_editor_hash_worker_skipped")
            return None
        if existing is not None:
            existing.deleteLater()

        parent = self if isinstance(self, QWidget) else None
        worker = GenericCallableWorker(func, *args, parent=parent)
        _: object = worker.call_finished.connect(on_success)
        _ = worker.call_error.connect(on_error)
        worker.start()
        return worker

    def _on_custom_crc(self) -> None:
        """Open the custom CRC dialog wired to the streaming worker.

        The dialog never copies the document body onto the UI thread. It receives the file path (when one is resolvable) and the document
        handle; clicking Calculate spawns a worker that streams the bytes through ``compute_streaming_custom_crc`` in bounded chunks.
        """
        document = self.document
        if document is None:
            return
        try:
            doc_len: int = document.length()
        except (RuntimeError, OSError, ValueError, AttributeError) as exc:
            _logger.warning(
                "custom_crc_length_unavailable",
                error_type=type(exc).__name__,
                error=str(exc),
            )
            if isinstance(self, QWidget):
                show_warning(self, "Custom CRC", f"Failed to read document length:\n{exc}")
            return

        parent = self if isinstance(self, QWidget) else None
        dlg = CustomCrcDialog(
            file_path=self._resolve_custom_crc_file_path(),
            document=document,
            length=doc_len,
            parent=parent,
        )
        dlg.exec()

    def _create_pe_checksum_group(self) -> QGroupBox:
        """Create the PE Checksum verification/repair group box.

        Returns:
            QGroupBox: Container with verify and repair buttons and status label.
        """
        box = QGroupBox("PE Checksum")
        layout = QHBoxLayout(box)
        self._pe_checksum_status = QLabel("Not verified")
        layout.addWidget(self._pe_checksum_status)
        verify_btn = QPushButton("Verify")
        verify_btn.clicked.connect(self._on_verify_pe_checksum)
        layout.addWidget(verify_btn)
        repair_btn = QPushButton("Repair")
        repair_btn.clicked.connect(self._on_repair_pe_checksum)
        layout.addWidget(repair_btn)
        return box

    def _on_calculate_hash(self) -> None:
        """Calculate the hash of the current document via hexcore document.compute_hash.

        The hash is computed on a background worker thread so hashing a multi-hundred-megabyte or multi-gigabyte document never blocks the
        Qt event loop.
        """
        if self.document is None or self._hash_algo_combo is None or self._hash_result_label is None:
            return
        algo = self._hash_algo_combo.currentText()
        worker = self._spawn_hex_worker(
            getattr(self, "_hash_worker", None),
            _format_hash_result,
            (self.document, algo),
            self._on_hash_result_ready,
            self._on_hash_error,
        )
        if worker is None:
            return
        self._hash_worker = worker
        self._hash_result_label.setText(f"{algo}: Computing...")

    def _on_hash_result_ready(self, result: object) -> None:
        """Display a computed hash result on the main thread.

        Args:
            result: Formatted hash display string produced by the background worker.
        """
        if self._hash_result_label is not None and isinstance(result, str):
            self._hash_result_label.setText(result)

    def _on_hash_error(self, exc: object) -> None:
        """Display a hash computation failure on the main thread.

        Args:
            exc: The exception raised by the background worker.
        """
        if self._hash_result_label is not None:
            self._hash_result_label.setText(f"Error: {exc}")

    def _on_hash_selection(self) -> None:
        """Hash the current selection range via hexcore document.compute_hash_range.

        The hash is computed on a background worker thread so hashing a large selection never blocks the Qt event loop.
        """
        if self.document is None or self._hash_algo_combo is None or self._hash_result_label is None:
            return

        sel_start: int = getattr(self, "_selection_start", -1)
        sel_end: int = getattr(self, "_selection_end", -1)
        if sel_start < 0 or sel_end < 0 or sel_end <= sel_start:
            self._hash_result_label.setText("No selection")
            return

        algo = self._hash_algo_combo.currentText()
        worker = self._spawn_hex_worker(
            getattr(self, "_hash_worker", None),
            _format_hash_range_result,
            (self.document, sel_start, sel_end, algo),
            self._on_hash_result_ready,
            self._on_hash_error,
        )
        if worker is None:
            return
        self._hash_worker = worker
        self._hash_result_label.setText(f"{algo} (0x{sel_start:X}-0x{sel_end:X}): Computing...")

    def _on_verify_pe_checksum(self) -> None:
        """Verify the PE checksum via hexcore document.verify_pe_checksum.

        The verification runs on a background worker thread so scanning a large image never blocks the Qt event loop.
        """
        if self.document is None:
            return

        worker = self._spawn_hex_worker(
            getattr(self, "_pe_checksum_worker", None),
            self.document.verify_pe_checksum,
            (),
            self._apply_pe_checksum_verification,
            self._on_pe_checksum_verify_error,
        )
        if worker is None:
            return
        self._pe_checksum_worker = worker
        if self._pe_checksum_status is not None:
            self._pe_checksum_status.setText("Verifying...")

    def _apply_pe_checksum_verification(self, info: object) -> None:
        """Apply a PE-checksum verification result to the status label.

        Called on the main thread when the background verification worker completes successfully.

        Args:
            info: The raw result returned by ``document.verify_pe_checksum``.
        """
        if self._pe_checksum_status is None:
            return

        if not isinstance(info, dict):
            self._pe_checksum_status.setText("Verification unavailable")
            return
        info_dict = cast("dict[str, Any]", info)
        if info_dict.get("valid") is False and info_dict.get("reason"):
            self._pe_checksum_status.setText(str(info_dict["reason"]))
            return

        stored = info_dict.get("stored")
        calculated = info_dict.get("calculated", info_dict.get("expected"))
        if not isinstance(stored, int) or not isinstance(calculated, int):
            self._pe_checksum_status.setText("Verification unavailable")
            return

        if stored == calculated:
            self._pe_checksum_status.setText(f"Valid: 0x{stored:08X}")
        else:
            self._pe_checksum_status.setText(
                f"Invalid: stored=0x{stored:08X}, expected=0x{calculated:08X}",
            )

    def _on_pe_checksum_verify_error(self, exc: object) -> None:
        """Handle a PE-checksum verification worker failure.

        Args:
            exc: The exception raised by the background worker.
        """
        _logger.warning("pe_checksum_verify_failed", error=str(exc), error_type=type(exc).__name__)
        if self._pe_checksum_status is not None:
            self._pe_checksum_status.setText(f"Error: {exc}")

    def _pe_checksum_field_offset(self) -> int | None:
        """Locate the PE ``CheckSum`` field by reading ``e_lfanew`` from the document.

        The ``CheckSum`` field sits 64 bytes into the optional header for both
        PE32 and PE32+ images, so its absolute offset is ``e_lfanew`` plus the PE
        signature (4 bytes), the COFF file header (20 bytes) and that 64-byte
        displacement. Deriving the offset from the document lets observers be
        notified of the exact four bytes the repair changed regardless of where
        the PE headers begin, instead of a fixed constant that is only correct
        when ``e_lfanew`` is zero.

        Returns:
            int | None: Absolute byte offset of the four-byte ``CheckSum`` field,
                or ``None`` when the document is not a well-formed PE image.
        """
        document = self.document
        if document is None:
            return None
        try:
            total = int(document.length())
            if total < _DOS_E_LFANEW_OFFSET + 4 or bytes(document.read(0, 2)) != b"MZ":
                return None
            e_lfanew = int.from_bytes(bytes(document.read(_DOS_E_LFANEW_OFFSET, 4)), "little")
            if e_lfanew <= 0 or e_lfanew + 4 > total:
                return None
            if bytes(document.read(e_lfanew, 4)) != b"PE\x00\x00":
                return None
        except (RuntimeError, OSError, ValueError, AttributeError, OverflowError):
            _logger.warning("pe_checksum_offset_resolution_failed")
            return None
        offset = e_lfanew + _PE_CHECKSUM_OFFSET_FROM_E_LFANEW
        return None if offset + _PE_CHECKSUM_LEN > total else offset

    def _repair_pe_checksum_and_notify(self, checksum_offset: int | None) -> object:
        """Repair the PE checksum and notify state observers of the modified bytes.

        Runs on the background ``GenericCallableWorker`` thread dispatched by
        ``_on_repair_pe_checksum``. The document write and the state-holder
        notification run back-to-back on that thread, as plain synchronous
        Python calls, so observers (the hex viewport, the bridge layer, the AI
        tool registry) learn about the modified bytes the instant the write
        completes instead of waiting for the GUI thread's event loop to
        marshal a queued Qt signal. ``HexDocumentState`` is documented as
        thread-safe and designed to be notified from any thread, so calling it
        here rather than from the GUI-thread completion callback is safe.

        Args:
            checksum_offset: Absolute byte offset of the four-byte ``CheckSum``
                field resolved before dispatch, or ``None`` when the offset
                could not be determined for the current document.

        Returns:
            object: The (unused) return value of ``document.repair_pe_checksum``.

        Raises:
            RuntimeError: If the document became unavailable before the
                background worker could run the repair.
        """
        document = self.document
        if document is None:
            msg = "document became unavailable before the PE checksum repair could run"
            raise RuntimeError(msg)
        result = document.repair_pe_checksum()
        if checksum_offset is None:
            _logger.warning("pe_checksum_notify_skipped_unresolved_offset")
        else:
            self._notify_state_data_modified_for_hashing(
                checksum_offset,
                _PE_CHECKSUM_LEN,
                source="hex-editor.hashing.repair_pe_checksum",
            )
        return result

    def _on_repair_pe_checksum(self) -> None:
        """Repair the PE checksum via hexcore document.repair_pe_checksum.

        The repair runs on a background worker thread so recomputing the checksum of a large image never blocks the Qt event loop. After
        dispatch this joins the worker for a short, bounded window (``_PE_CHECKSUM_REPAIR_SYNC_WAIT_MS``) so ordinarily fast repairs are
        already complete, written, and have fired their document-modified notification by the time this method returns; a repair on a
        genuinely large image simply outlives that window and continues to completion asynchronously as before.
        """
        if self.document is None:
            return

        parent = self if isinstance(self, QWidget) else None
        reply = QMessageBox.question(
            parent,
            "Repair PE Checksum",
            "Overwrite the PE checksum field with the correct value?",
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        checksum_offset = self._pe_checksum_field_offset()
        worker = self._spawn_hex_worker(
            getattr(self, "_pe_checksum_worker", None),
            self._repair_pe_checksum_and_notify,
            (checksum_offset,),
            self._on_pe_checksum_repaired,
            self._on_pe_checksum_repair_error,
        )
        if worker is None:
            return
        self._pe_checksum_worker = worker
        if self._pe_checksum_status is not None:
            self._pe_checksum_status.setText("Repairing...")
        _ = worker.wait(_PE_CHECKSUM_REPAIR_SYNC_WAIT_MS)

    def _on_pe_checksum_repair_error(self, exc: object) -> None:
        """Handle a PE-checksum repair worker failure.

        Args:
            exc: The exception raised by the background worker.
        """
        _logger.warning("pe_checksum_repair_failed", error=str(exc), error_type=type(exc).__name__)
        parent = self if isinstance(self, QWidget) else None
        show_warning(parent, "Repair Failed", str(exc))
        if self._pe_checksum_status is not None:
            self._pe_checksum_status.setText(f"Error: {exc}")

    def _on_pe_checksum_repaired(self, _result: object) -> None:
        """Finish a successful PE-checksum repair on the main thread.

        Refreshes the hex viewport and starts a second background worker that re-verifies the repaired checksum for display. The shared
        state holder was already notified of the modified checksum bytes on the background repair worker's own thread (see
        ``_repair_pe_checksum_and_notify``), so observers do not wait on this GUI-thread callback to learn about the write.

        Args:
            _result: The (unused) return value of ``document.repair_pe_checksum``.
        """
        if self._hex_widget is not None:
            update_fn = getattr(self._hex_widget, "_update_viewport", None)
            if callable(update_fn):
                update_fn()

        _logger.info("pe_checksum_repaired")

        if self.document is None or self._pe_checksum_status is None:
            return

        worker = self._spawn_hex_worker(
            getattr(self, "_pe_checksum_worker", None),
            self.document.verify_pe_checksum,
            (),
            self._apply_post_repair_verification,
            self._on_post_repair_verify_error,
        )
        if worker is None:
            return
        self._pe_checksum_worker = worker
        self._pe_checksum_status.setText("Repaired, verifying...")

    def _apply_post_repair_verification(self, info: object) -> None:
        """Display the post-repair PE-checksum verification result.

        Called on the main thread when the background post-repair verification worker completes successfully.

        Args:
            info: The raw result returned by ``document.verify_pe_checksum``.
        """
        if self._pe_checksum_status is None:
            return
        if isinstance(info, dict):
            info_dict = cast("dict[str, Any]", info)
            calculated = info_dict.get("calculated", info_dict.get("stored"))
            if isinstance(calculated, int):
                self._pe_checksum_status.setText(f"Repaired: 0x{calculated:08X}")
            else:
                self._pe_checksum_status.setText("Repaired")
        else:
            self._pe_checksum_status.setText("Repaired")

    def _on_post_repair_verify_error(self, exc: object) -> None:
        """Handle a post-repair PE-checksum verification worker failure.

        Args:
            exc: The exception raised by the background worker.
        """
        _logger.warning(
            "pe_checksum_post_repair_verify_failed",
            error_type=type(exc).__name__,
            error=str(exc),
        )
        if self._pe_checksum_status is not None:
            self._pe_checksum_status.setText(f"Repaired (verify failed: {exc})")
